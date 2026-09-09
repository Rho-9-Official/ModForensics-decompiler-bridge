#!/usr/bin/env python3
"""
rho9_decompile_server.py
Rho-9 Systems -- ModForensics Local Decompile Bridge

WHAT THIS IS
------------
A small localhost-only HTTP server that lets the ModForensics web UI send a
.jar or .class file for STATIC decompilation and get back a zip of .java
source, instead of the analyst manually round-tripping through decompiler.com.

SECURITY MODEL (read this before you trust it)
------------------------------------------------
- This server never executes the sample. It shells out to a decompiler
  (CFR, and optionally Vineflower) which statically parses the classfile
  binary format and reconstructs Java-like source. It does not load the
  target class into a JVM, does not call its main(), and does not invoke
  any of its methods.
- It binds ONLY to 127.0.0.1 (loopback). It will never listen on 0.0.0.0
  and will refuse to start if that's overridden to something non-loopback
  without an explicit --allow-non-loopback flag (see below).
- Every decompile runs as a subprocess with a hard timeout, so a sample
  crafted to make the decompiler hang can't wedge the server indefinitely.
- Honest caveat: the decompiler itself (CFR/Vineflower, both JVM programs)
  is a parser being fed untrusted binary input. Like any parser, it has
  some theoretical bug surface. This design eliminates "malware runs" as
  a risk; it does not eliminate "parser has a bug" as a risk. If that
  matters for your threat model, run this inside a VM/container you're
  willing to throw away.
- Uploaded bytes and decompiled output live ONLY as SQLite blobs, written
  with parameterized queries. A job's raw file also touches disk briefly
  (JVM tools require a real file path) in a per-job temp directory that is
  deleted immediately after the subprocess exits, success or failure.
- On every shutdown path (Ctrl+C, SIGTERM, an explicit /rho9/shutdown
  call, or just falling off the end of main()), the server DELETEs all
  job rows, VACUUMs the database file to actually reclaim the freed
  pages, closes the connection, and unlinks the db file and its temp
  directory. This is not "best effort at exit" -- it's wrapped in
  try/finally and registered with atexit and both SIGINT/SIGTERM so it
  runs whichever way the process ends.

CROSS-PLATFORM
---------------
Pure Python standard library. No pip installs required to run the server
itself. Works the same on Windows, Linux, and Termux (Android). Only
external dependency is a JVM (to run CFR/Vineflower) and the decompiler
jar itself, both of which this script tries to fetch/install for you --
see setup_environment() below. If auto-setup fails (no internet, locked
down device, whatever), you can always drop your own working jar named
"cfr.jar" or "vineflower.jar" into the tools directory and it'll be used
as-is, no re-download attempted.

RUNNING IT
----------
    python3 rho9_decompile_server.py

Then open ModForensics in your browser -- it will find this automatically.
Stop with Ctrl+C. That's it.

Flags:
    --port-start N       first port to try (default 8991, tries 5 in a row)
    --tools-dir PATH      where to store/download the decompiler jar
    --no-auto-install     don't attempt JVM/engine auto-install, just detect
    --reinstall            wipe the tools dir and re-fetch everything
    --no-page              API only -- don't create/serve the ModForensics
                           static folder. Use this when the UI is hosted
                           elsewhere (e.g. GitHub Pages).
    --timeout SECONDS      per-job decompile timeout (default 90)
    --max-upload-mb N      reject uploads bigger than this (default 150)
    --max-session-mb N     reject saved-session reports bigger than this (default 250)
"""

import argparse
import atexit
import base64
import hashlib
import http.server
import io
import json
import os
import platform
import re
import shutil
import signal
import socket
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

# --------------------------------------------------------------------------
# Constants shared (by contract) with the HTML side. If you change this
# string here, change it in index.html's RHO9_BRIDGE_PURPOSE too, or the
# capability handshake will simply never match and the UI will treat the
# bridge as "not found" -- which is the safe failure mode.
# --------------------------------------------------------------------------
BRIDGE_PURPOSE = "rho9-modforensics-decompile-bridge-v1"
SERVER_VERSION = "1.2.0"
DEFAULT_PORTS = [8991, 8992, 8993, 8994, 8995]

# The threat-intel store is DELIBERATELY persistent and lives at a fixed path,
# completely separate from the per-run jobs DB (which is a throwaway temp file
# wiped on every shutdown). Nothing in the cleanup/wipe/purge paths ever touches
# this file -- see IntelStore below and cleanup() at the bottom. That is the
# whole point: attacker fingerprints (webhook/C2/staging IOCs, malware hashes,
# observed attack methods, and how often each has recurred) must survive across
# sessions so repeat infrastructure can be recognised over time.
INTEL_DB_DEFAULT = os.path.join(os.path.expanduser("~"), ".rho9", "threat_intel.sqlite3")

# Each engine entry: name, jar filename we store it as, candidate download
# URLs (tried in order, first that produces a working jar wins), and the
# CLI argument shape used to invoke it. URLs are pinned to specific
# versions on purpose -- pinned versions can 404 someday if a project
# reshuffles its release assets. If that happens, edit the URL list below,
# or just hand-place a working jar at <tools_dir>/<jar_name> and the
# downloader will skip fetching entirely.
ENGINES = [
    {
        "name": "vineflower",
        "jar_name": "vineflower.jar",
        "min_java_major": 11,
        "urls": [
            "https://github.com/Vineflower/vineflower/releases/download/1.11.1/vineflower-1.11.1.jar",
            "https://repo1.maven.org/maven2/org/vineflower/vineflower/1.11.1/vineflower-1.11.1.jar",
        ],
        # (source, destination) -- Vineflower writes decompiled output as
        # a jar/zip of .java files into the destination folder.
        "build_cmd": lambda jar, src, outdir: ["java", "-jar", jar, src, outdir],
    },
    {
        "name": "cfr",
        "jar_name": "cfr.jar",
        "min_java_major": 8,
        "urls": [
            "https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar",
            "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar",
        ],
        "build_cmd": lambda jar, src, outdir: [
            "java", "-jar", jar, src, "--outputdir", outdir, "--silent", "true",
        ],
    },
]

_state_lock = threading.Lock()
_state = {
    "java_path": None,
    "java_major": None,
    "engine": None,          # dict from ENGINES, once one is confirmed working
    "engine_version": None,
    "setup_message": None,   # human-readable status/error for the UI to show
    "ready": False,
}


# ==========================================================================
# Environment setup: find/install a JVM, find/download a decompiler jar
# ==========================================================================

def log(msg):
    print("[rho9-bridge] " + msg, flush=True)


def is_termux():
    return "com.termux" in os.environ.get("PREFIX", "") or os.path.exists("/data/data/com.termux")


def find_java():
    path = shutil.which("java")
    if not path:
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            candidate = os.path.join(java_home, "bin", "java.exe" if os.name == "nt" else "java")
            if os.path.isfile(candidate):
                path = candidate
    if not path:
        return None, None
    try:
        out = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=10)
        text = (out.stderr or "") + (out.stdout or "")
        major = None
        for token in text.replace('"', " ").split():
            if token.count(".") >= 1 or token.isdigit():
                head = token.split(".")[0]
                if head.isdigit():
                    n = int(head)
                    # old-style "1.8.0_xxx" -> major is really 8
                    if n == 1:
                        parts = token.split(".")
                        if len(parts) > 1 and parts[1].isdigit():
                            major = int(parts[1])
                            break
                    else:
                        major = n
                        break
        return path, major
    except Exception:
        return path, None


def attempt_install_jvm():
    """Best-effort JVM install. On Linux this WILL block waiting for your
    sudo password if passwordless sudo isn't configured -- it runs sudo
    interactively (no -n), inheriting this terminal's stdin/stdout/stderr,
    so you'll see the normal apt/dnf/pacman prompt right here and can type
    your password. If you're running this non-interactively (e.g. no
    controlling terminal), sudo itself will fail fast rather than hang
    forever, and we fall through to telling you the manual command."""
    system = platform.system()
    if is_termux():
        log("Termux detected. Attempting: pkg install -y openjdk-17")
        try:
            subprocess.run(["pkg", "install", "-y", "openjdk-17"], timeout=300)
        except Exception as e:
            log("Auto-install via pkg failed: %s" % e)
        return

    if system == "Linux":
        if shutil.which("apt-get"):
            log("Installing default-jre-headless via apt-get -- you may be "
                "prompted for your sudo password below.")
            try:
                r = subprocess.run(
                    ["sudo", "apt-get", "install", "-y", "default-jre-headless"],
                    timeout=300,
                )
                if r.returncode != 0:
                    log("apt-get install failed (exit code %d). Run manually:\n"
                        "    sudo apt-get install -y default-jre-headless" % r.returncode)
            except Exception as e:
                log("apt-get attempt failed: %s" % e)
        elif shutil.which("dnf"):
            log("Installing java-17-openjdk via dnf -- you may be prompted "
                "for your sudo password below.")
            try:
                r = subprocess.run(
                    ["sudo", "dnf", "install", "-y", "java-17-openjdk"], timeout=300,
                )
                if r.returncode != 0:
                    log("dnf install failed (exit code %d). Run manually:\n"
                        "    sudo dnf install -y java-17-openjdk" % r.returncode)
            except Exception as e:
                log("dnf attempt failed: %s" % e)
        elif shutil.which("pacman"):
            log("Installing jre-openjdk via pacman -- you may be prompted "
                "for your sudo password below.")
            try:
                r = subprocess.run(
                    ["sudo", "pacman", "-S", "--noconfirm", "jre-openjdk"], timeout=300,
                )
                if r.returncode != 0:
                    log("pacman install failed (exit code %d). Run manually:\n"
                        "    sudo pacman -S --noconfirm jre-openjdk" % r.returncode)
            except Exception as e:
                log("pacman attempt failed: %s" % e)
        else:
            log("No known package manager found. Please install a JDK/JRE 17+ manually.")
        return

    if system == "Windows":
        if shutil.which("winget"):
            log("Attempting: winget install EclipseAdoptium.Temurin.17.JRE")
            try:
                subprocess.run(
                    ["winget", "install", "--id", "EclipseAdoptium.Temurin.17.JRE", "-e",
                     "--silent", "--accept-package-agreements", "--accept-source-agreements"],
                    timeout=600,
                )
            except Exception as e:
                log("winget attempt failed: %s" % e)
        else:
            log("winget not found. Install a JDK manually from https://adoptium.net/ "
                "then re-run this script.")
        return

    if system == "Darwin":
        if shutil.which("brew"):
            log("Attempting: brew install openjdk@17")
            try:
                subprocess.run(["brew", "install", "openjdk@17"], timeout=600)
            except Exception as e:
                log("brew attempt failed: %s" % e)
        else:
            log("Homebrew not found. Install a JDK manually from https://adoptium.net/")
        return

    log("Unrecognized platform %r -- please install a JDK 17+ manually." % system)


def _download(url, dest_path, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "rho9-decompile-bridge"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    if len(data) < 20000:
        raise ValueError("downloaded file suspiciously small (%d bytes)" % len(data))
    if data[:2] != b"PK":
        raise ValueError("downloaded file is not a valid jar/zip")
    with open(dest_path, "wb") as f:
        f.write(data)


def ensure_engine_jar(engine, tools_dir):
    jar_path = os.path.join(tools_dir, engine["jar_name"])
    if os.path.isfile(jar_path) and os.path.getsize(jar_path) > 20000:
        return jar_path
    last_err = None
    for url in engine["urls"]:
        try:
            log("Downloading %s from %s ..." % (engine["name"], url))
            _download(url, jar_path)
            log("Saved %s" % jar_path)
            return jar_path
        except Exception as e:
            last_err = e
            log("  failed: %s" % e)
    raise RuntimeError(
        "Could not download %s (last error: %s). You can manually place a working "
        "jar at %s to skip downloading." % (engine["name"], last_err, jar_path)
    )


def verify_engine(java_path, jar_path):
    try:
        r = subprocess.run([java_path, "-jar", jar_path, "--help"],
                            capture_output=True, text=True, timeout=20)
        combined = (r.stdout or "") + (r.stderr or "")
        return len(combined) > 0
    except Exception:
        try:
            r = subprocess.run([java_path, "-jar", jar_path],
                                capture_output=True, text=True, timeout=20)
            return True
        except Exception:
            return False


def setup_environment(tools_dir, auto_install, reinstall):
    os.makedirs(tools_dir, exist_ok=True)

    if reinstall:
        log("--reinstall passed: clearing tools directory.")
        for name in os.listdir(tools_dir):
            try:
                os.remove(os.path.join(tools_dir, name))
            except Exception:
                pass

    java_path, java_major = find_java()
    if not java_path and auto_install:
        attempt_install_jvm()
        java_path, java_major = find_java()

    with _state_lock:
        _state["java_path"] = java_path
        _state["java_major"] = java_major

    if not java_path:
        msg = ("No Java runtime found and auto-install didn't complete. Install a "
               "JDK/JRE (17+ recommended, 8+ minimum) and restart this server. "
               "Termux: pkg install openjdk-17 | Debian/Ubuntu: sudo apt-get install "
               "default-jre-headless | Windows: https://adoptium.net/")
        with _state_lock:
            _state["setup_message"] = msg
            _state["ready"] = False
        log(msg)
        return

    log("Java found: %s (major version %s)" % (java_path, java_major))

    chosen = None
    chosen_jar = None
    last_err = None
    for engine in ENGINES:
        if java_major and java_major < engine["min_java_major"]:
            log("Skipping %s: needs Java %d+, found %s" %
                (engine["name"], engine["min_java_major"], java_major))
            continue
        try:
            jar_path = ensure_engine_jar(engine, tools_dir)
        except Exception as e:
            last_err = e
            log(str(e))
            continue
        if verify_engine(java_path, jar_path):
            chosen, chosen_jar = engine, jar_path
            break
        else:
            last_err = RuntimeError("%s did not respond to --help/launch check" % engine["name"])

    if not chosen:
        msg = ("Could not set up a decompiler engine (CFR/Vineflower). Last error: %s. "
               "You can manually place a working cfr.jar or vineflower.jar in: %s" %
               (last_err, tools_dir))
        with _state_lock:
            _state["setup_message"] = msg
            _state["ready"] = False
        log(msg)
        return

    with _state_lock:
        _state["engine"] = {"name": chosen["name"], "jar_path": chosen_jar,
                             "build_cmd": chosen["build_cmd"]}
        _state["engine_version"] = chosen["name"]
        _state["setup_message"] = None
        _state["ready"] = True

    log("Decompile engine ready: %s (%s)" % (chosen["name"], chosen_jar))


# ==========================================================================
# SQLite blob storage -- parameterized everywhere, wiped on any shutdown path
# ==========================================================================

class Store:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="rho9_bridge_")
        self.db_path = os.path.join(self.dir, "jobs.sqlite3")
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute(
                "CREATE TABLE jobs ("
                " id TEXT PRIMARY KEY,"
                " filename TEXT NOT NULL,"
                " created_at REAL NOT NULL,"
                " input_blob BLOB NOT NULL,"
                " output_zip BLOB,"
                " status TEXT NOT NULL,"
                " error TEXT"
                ")"
            )
            # Single-row table: the analyst's in-progress report (S state from
            # the UI), so a page refresh can restore exactly where they left
            # off instead of losing everything. Wiped by the same shutdown
            # guarantee as job blobs -- see wipe() below.
            self.conn.execute(
                "CREATE TABLE session ("
                " id TEXT PRIMARY KEY,"
                " updated_at REAL NOT NULL,"
                " data BLOB NOT NULL"
                ")"
            )
            self.conn.commit()

    def create_job(self, job_id, filename, data):
        with self.lock:
            self.conn.execute(
                "INSERT INTO jobs (id, filename, created_at, input_blob, status) "
                "VALUES (?, ?, ?, ?, ?)",
                (job_id, filename, time.time(), sqlite3.Binary(data), "processing"),
            )
            self.conn.commit()

    def mark_done(self, job_id, output_zip_bytes):
        with self.lock:
            self.conn.execute(
                "UPDATE jobs SET output_zip = ?, status = ? WHERE id = ?",
                (sqlite3.Binary(output_zip_bytes), "done", job_id),
            )
            self.conn.commit()

    def mark_error(self, job_id, error_text):
        with self.lock:
            self.conn.execute(
                "UPDATE jobs SET status = ?, error = ? WHERE id = ?",
                ("error", error_text, job_id),
            )
            self.conn.commit()

    def get_result(self, job_id):
        with self.lock:
            cur = self.conn.execute(
                "SELECT output_zip, status, error FROM jobs WHERE id = ?", (job_id,)
            )
            return cur.fetchone()

    def get_input(self, job_id):
        """Original uploaded bytes for a job, so a fuzzy rescan does not make
        the UI re-upload a file the bridge is already holding."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT input_blob, filename FROM jobs WHERE id = ?", (job_id,))
            return cur.fetchone()

    def list_jobs(self):
        with self.lock:
            cur = self.conn.execute(
                "SELECT id, filename, created_at, status FROM jobs ORDER BY created_at DESC"
            )
            return cur.fetchall()

    def save_session(self, data_bytes):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO session (id, updated_at, data) VALUES ('current', ?, ?)",
                (time.time(), sqlite3.Binary(data_bytes)),
            )
            self.conn.commit()

    def get_session(self):
        with self.lock:
            cur = self.conn.execute(
                "SELECT data, updated_at FROM session WHERE id = 'current'"
            )
            return cur.fetchone()

    def clear_session(self):
        with self.lock:
            self.conn.execute("DELETE FROM session WHERE id = 'current'")
            self.conn.commit()

    def purge(self):
        """Delete all rows (jobs + session) and reclaim the space, but keep
        the connection open. This is for a mid-session manual wipe via
        POST /rho9/wipe -- the server keeps running afterward, so closing
        the connection here would break every request that follows.
        Contrast with wipe() below, which is only for actual shutdown."""
        with self.lock:
            self.conn.execute("DELETE FROM jobs")
            self.conn.execute("DELETE FROM session")
            self.conn.commit()
            self.conn.execute("VACUUM")
            self.conn.commit()

    def wipe(self):
        """Erase everything: delete all rows, VACUUM to reclaim freed pages,
        close the connection, and remove the db file + temp dir from disk.
        Idempotent -- safe to call more than once (both the normal shutdown
        path and atexit call this; whichever runs first does the real work,
        the second is a harmless no-op)."""
        with self.lock:
            if getattr(self, "_wiped", False):
                return
            self._wiped = True
            try:
                self.conn.execute("DELETE FROM jobs")
                self.conn.execute("DELETE FROM session")
                self.conn.commit()
                self.conn.execute("VACUUM")
                self.conn.commit()
                self.conn.close()
            except Exception as e:
                log("Warning: error during DB wipe: %s" % e)
            finally:
                try:
                    shutil.rmtree(self.dir, ignore_errors=True)
                except Exception:
                    pass


# ==========================================================================
# Persistent threat-intel store -- parameterized everywhere, NEVER wiped.
#
# This is the deliberate counterpart to Store above. Store is a temp blob DB
# that is DELETEd + VACUUMed + unlinked on every shutdown path. IntelStore is
# the opposite: a durable knowledge base at a fixed on-disk path that survives
# restarts and is intentionally exempt from cleanup(), /rho9/wipe and
# STORE.purge(). It records, per unique indicator value:
#   - the indicator itself (webhook / C2 / staging link / wallet / url / etc.)
#   - times_seen: how many DISTINCT samples that exact value has appeared in
#     (the attacker-identification counter -- re-analysing the same file never
#     inflates it, because sightings are deduplicated per (indicator, sample))
#   - first_seen / last_seen timestamps
# and, per malware sample (keyed by SHA-256 of the uploaded bytes):
#   - filename, triage score + band, signature families, derived attack methods
#     (e.g. "Discord webhook exfiltration", "Telegram C2", "Remote code loading")
#   - file/class counts and how many times it has been analysed
# plus a sample<->indicator link table (so an indicator can be pivoted to every
# sample it appeared in, and vice versa) and an append-only analyses log used
# for trend charts.
# ==========================================================================

class IntelStore:
    def __init__(self, db_path):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS samples ("
                " sha256 TEXT PRIMARY KEY,"
                " filename TEXT,"
                " first_seen REAL NOT NULL,"
                " last_seen REAL NOT NULL,"
                " score INTEGER,"
                " band TEXT,"
                " families TEXT,"          # JSON array of signature families
                " attack_methods TEXT,"    # JSON array of human-readable methods
                " file_count INTEGER,"
                " class_count INTEGER,"
                " times_analyzed INTEGER NOT NULL DEFAULT 1"
                ")"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS iocs ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " type TEXT NOT NULL,"
                " value TEXT NOT NULL,"
                " first_seen REAL NOT NULL,"
                " last_seen REAL NOT NULL,"
                " times_seen INTEGER NOT NULL DEFAULT 0,"
                " UNIQUE(type, value)"
                ")"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS sample_iocs ("
                " sample_sha256 TEXT NOT NULL,"
                " ioc_id INTEGER NOT NULL,"
                " source TEXT,"
                " decoded INTEGER DEFAULT 0,"
                " ts REAL NOT NULL,"
                " UNIQUE(sample_sha256, ioc_id)"
                ")"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS analyses ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " ts REAL NOT NULL,"
                " sample_sha256 TEXT,"
                " score INTEGER,"
                " band TEXT,"
                " ioc_count INTEGER"
                ")"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS webhook_meta ("
                " value TEXT PRIMARY KEY,"        # the full webhook URL
                " webhook_id TEXT,"
                " name TEXT,"
                " guild_id TEXT,"                 # persistent operator fingerprint
                " channel_id TEXT,"
                " avatar TEXT,"
                " application_id TEXT,"
                " first_seen REAL NOT NULL,"
                " last_seen REAL NOT NULL"
                ")"
            )
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_si_ioc ON sample_iocs(ioc_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_si_sample ON sample_iocs(sample_sha256)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_wm_guild ON webhook_meta(guild_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_wm_channel ON webhook_meta(channel_id)")
            self.conn.commit()

    # ---- write path -------------------------------------------------------
    def record(self, payload):
        """Record one finished analysis: upsert the sample, upsert every IOC,
        link them, and bump the per-IOC 'times_seen' counter only when a genuinely
        new (indicator, sample) pairing is observed. Everything is parameterized."""
        sample = payload.get("sample") or {}
        iocs = payload.get("iocs") or []
        sha = (sample.get("sha256") or "").strip()
        if not sha:
            raise ValueError("sample.sha256 is required")

        now = time.time()
        score = sample.get("score")
        band = sample.get("band")
        families = json.dumps(sample.get("families") or [])
        methods = json.dumps(sample.get("attack_methods") or [])
        filename = sample.get("filename") or "unknown"
        file_count = int(sample.get("file_count") or 0)
        class_count = int(sample.get("class_count") or 0)

        new_iocs = 0
        new_links = 0
        with self.lock:
            cur = self.conn.execute("SELECT sha256 FROM samples WHERE sha256=?", (sha,))
            sample_new = cur.fetchone() is None
            if sample_new:
                self.conn.execute(
                    "INSERT INTO samples (sha256, filename, first_seen, last_seen, score, band,"
                    " families, attack_methods, file_count, class_count, times_analyzed)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                    (sha, filename, now, now, score, band, families, methods,
                     file_count, class_count),
                )
            else:
                self.conn.execute(
                    "UPDATE samples SET last_seen=?, score=?, band=?, families=?,"
                    " attack_methods=?, file_count=?, class_count=?,"
                    " times_analyzed=times_analyzed+1 WHERE sha256=?",
                    (now, score, band, families, methods, file_count, class_count, sha),
                )

            for ioc in iocs:
                t = (ioc.get("type") or "").strip()
                v = (ioc.get("value") or "").strip()
                if not t or not v:
                    continue
                src = ioc.get("source") or ""
                dec = 1 if ioc.get("decoded") else 0

                row = self.conn.execute(
                    "SELECT id FROM iocs WHERE type=? AND value=?", (t, v)
                ).fetchone()
                if row:
                    ioc_id = row[0]
                    self.conn.execute(
                        "UPDATE iocs SET last_seen=? WHERE id=?", (now, ioc_id)
                    )
                else:
                    c = self.conn.execute(
                        "INSERT INTO iocs (type, value, first_seen, last_seen, times_seen)"
                        " VALUES (?, ?, ?, ?, 0)", (t, v, now, now)
                    )
                    ioc_id = c.lastrowid
                    new_iocs += 1

                link = self.conn.execute(
                    "INSERT OR IGNORE INTO sample_iocs (sample_sha256, ioc_id, source, decoded, ts)"
                    " VALUES (?, ?, ?, ?, ?)", (sha, ioc_id, src, dec, now)
                )
                if link.rowcount == 1:
                    # First time THIS indicator has been tied to THIS sample:
                    # that is a distinct sighting, so the counter climbs.
                    self.conn.execute(
                        "UPDATE iocs SET times_seen=times_seen+1, last_seen=? WHERE id=?",
                        (now, ioc_id)
                    )
                    new_links += 1

            self.conn.execute(
                "INSERT INTO analyses (ts, sample_sha256, score, band, ioc_count)"
                " VALUES (?, ?, ?, ?, ?)", (now, sha, score, band, len(iocs))
            )

            # Optional Discord webhook attribution: the client resolves each
            # webhook's server/channel/name via the bridge and passes it here so
            # the same operator can be recognised across different webhooks.
            for wm in (payload.get("webhook_meta") or []):
                val = (wm.get("value") or "").strip()
                if not val:
                    continue
                seen_wm = self.conn.execute(
                    "SELECT value FROM webhook_meta WHERE value=?", (val,)).fetchone()
                if seen_wm:
                    self.conn.execute(
                        "UPDATE webhook_meta SET webhook_id=?, name=?, guild_id=?,"
                        " channel_id=?, avatar=?, application_id=?, last_seen=? WHERE value=?",
                        (wm.get("webhook_id"), wm.get("name"), wm.get("guild_id"),
                         wm.get("channel_id"), wm.get("avatar"), wm.get("application_id"),
                         now, val))
                else:
                    self.conn.execute(
                        "INSERT INTO webhook_meta (value, webhook_id, name, guild_id,"
                        " channel_id, avatar, application_id, first_seen, last_seen)"
                        " VALUES (?,?,?,?,?,?,?,?,?)",
                        (val, wm.get("webhook_id"), wm.get("name"), wm.get("guild_id"),
                         wm.get("channel_id"), wm.get("avatar"), wm.get("application_id"),
                         now, now))

            self.conn.commit()

        return {"ok": True, "sha256": sha, "sample_new": sample_new,
                "new_iocs": new_iocs, "new_links": new_links,
                "iocs_submitted": len(iocs)}

    # ---- read path --------------------------------------------------------
    def list_iocs(self, limit=2000, type_filter=None, q=None):
        with self.lock:
            sql = ("SELECT type, value, times_seen, first_seen, last_seen FROM iocs")
            conds = []
            params = []
            if type_filter:
                conds.append("type=?")
                params.append(type_filter)
            if q:
                conds.append("value LIKE ?")
                params.append("%" + q + "%")
            if conds:
                sql += " WHERE " + " AND ".join(conds)
            sql += " ORDER BY times_seen DESC, last_seen DESC LIMIT ?"
            params.append(int(limit))
            rows = self.conn.execute(sql, params).fetchall()
            total = self.conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        return {
            "total": total,
            "iocs": [
                {"type": r[0], "value": r[1], "times_seen": r[2],
                 "first_seen": r[3], "last_seen": r[4]} for r in rows
            ],
        }

    def ioc_detail(self, type_, value):
        with self.lock:
            row = self.conn.execute(
                "SELECT id, type, value, first_seen, last_seen, times_seen"
                " FROM iocs WHERE type=? AND value=?", (type_, value)
            ).fetchone()
            if not row:
                return None
            ioc_id = row[0]
            samples = self.conn.execute(
                "SELECT s.sha256, s.filename, s.score, s.band, s.attack_methods,"
                " s.families, si.source, si.decoded, si.ts"
                " FROM sample_iocs si JOIN samples s ON s.sha256 = si.sample_sha256"
                " WHERE si.ioc_id=? ORDER BY si.ts DESC", (ioc_id,)
            ).fetchall()
            cooc = self.conn.execute(
                "SELECT i.type, i.value, i.times_seen, COUNT(*) AS shared"
                " FROM sample_iocs a"
                " JOIN sample_iocs b ON a.sample_sha256 = b.sample_sha256 AND b.ioc_id <> a.ioc_id"
                " JOIN iocs i ON i.id = b.ioc_id"
                " WHERE a.ioc_id=? GROUP BY i.id"
                " ORDER BY shared DESC, i.times_seen DESC LIMIT 50", (ioc_id,)
            ).fetchall()
            # Discord attribution enrichment
            webhook_meta = None
            related_webhooks = []
            if row[1] == "webhook":
                wm = self.conn.execute(
                    "SELECT webhook_id, name, guild_id, channel_id, avatar,"
                    " application_id, first_seen, last_seen FROM webhook_meta WHERE value=?",
                    (row[2],)).fetchone()
                if wm:
                    webhook_meta = {"webhook_id": wm[0], "name": wm[1], "guild_id": wm[2],
                                    "channel_id": wm[3], "avatar": wm[4], "application_id": wm[5],
                                    "first_seen": wm[6], "last_seen": wm[7]}
                    if wm[2]:
                        sib = self.conn.execute(
                            "SELECT value, name FROM webhook_meta WHERE guild_id=? AND value<>?",
                            (wm[2], row[2])).fetchall()
                        related_webhooks = [{"value": s[0], "name": s[1]} for s in sib]
            elif row[1] in ("discord_guild", "discord_channel"):
                col = "guild_id" if row[1] == "discord_guild" else "channel_id"
                wl = self.conn.execute(
                    "SELECT value, name, guild_id, channel_id FROM webhook_meta WHERE %s=?" % col,
                    (row[2],)).fetchall()
                related_webhooks = [{"value": w[0], "name": w[1], "guild_id": w[2],
                                     "channel_id": w[3]} for w in wl]
        return {
            "ioc": {"type": row[1], "value": row[2], "first_seen": row[3],
                    "last_seen": row[4], "times_seen": row[5]},
            "webhook_meta": webhook_meta,
            "related_webhooks": related_webhooks,
            "samples": [
                {"sha256": s[0], "filename": s[1], "score": s[2], "band": s[3],
                 "attack_methods": _load_json_list(s[4]), "families": _load_json_list(s[5]),
                 "source": s[6], "decoded": bool(s[7]), "ts": s[8]} for s in samples
            ],
            "cooccurring": [
                {"type": c[0], "value": c[1], "times_seen": c[2], "shared_samples": c[3]}
                for c in cooc
            ],
        }

    def list_samples(self, limit=1000):
        with self.lock:
            rows = self.conn.execute(
                "SELECT sha256, filename, score, band, attack_methods, families,"
                " first_seen, last_seen, times_analyzed FROM samples"
                " ORDER BY last_seen DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return {"samples": [
            {"sha256": r[0], "filename": r[1], "score": r[2], "band": r[3],
             "attack_methods": _load_json_list(r[4]), "families": _load_json_list(r[5]),
             "first_seen": r[6], "last_seen": r[7], "times_analyzed": r[8]} for r in rows
        ]}

    def trends(self):
        with self.lock:
            totals = {
                "samples": self.conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0],
                "iocs": self.conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
                "analyses": self.conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0],
            }
            by_day = self.conn.execute(
                "SELECT strftime('%Y-%m-%d', ts, 'unixepoch') AS day, COUNT(*)"
                " FROM analyses GROUP BY day ORDER BY day"
            ).fetchall()
            by_type = self.conn.execute(
                "SELECT type, COUNT(*) FROM iocs GROUP BY type ORDER BY COUNT(*) DESC"
            ).fetchall()
            bands = self.conn.execute(
                "SELECT band, COUNT(*) FROM samples GROUP BY band"
            ).fetchall()
            top = self.conn.execute(
                "SELECT type, value, times_seen FROM iocs"
                " ORDER BY times_seen DESC, last_seen DESC LIMIT 15"
            ).fetchall()
            method_rows = self.conn.execute(
                "SELECT attack_methods FROM samples"
            ).fetchall()
        method_counts = {}
        for (mj,) in method_rows:
            for m in _load_json_list(mj):
                method_counts[m] = method_counts.get(m, 0) + 1
        methods = sorted(
            ({"method": k, "count": v} for k, v in method_counts.items()),
            key=lambda x: x["count"], reverse=True
        )
        return {
            "totals": totals,
            "analyses_by_day": [{"day": d[0], "count": d[1]} for d in by_day],
            "iocs_by_type": [{"type": t[0], "count": t[1]} for t in by_type],
            "bands": [{"band": b[0], "count": b[1]} for b in bands],
            "top_iocs": [{"type": t[0], "value": t[1], "times_seen": t[2]} for t in top],
            "methods": methods,
        }

    def close(self):
        """Commit and close the connection WITHOUT deleting anything. This is a
        persistent store, so shutdown means 'flush and let go', never 'erase'."""
        with self.lock:
            try:
                self.conn.commit()
                self.conn.close()
            except Exception as e:
                log("Warning: error closing intel DB: %s" % e)


# ==========================================================================
# Jar signature engine (added in bridge v1.3.0)
# ==========================================================================
# Rho-9 jar signature engine: a PhotoDNA-style robust hash for Java archives.
#
# THE PROBLEM WITH HASHING A JAR
# ------------------------------
# A jar is a zip. Zip is deflate. Deflate destroys byte locality, so any
# byte-level fuzzy hash (ssdeep, TLSH) computed over the raw file is measuring
# compression artefacts, not code. Measured on real samples, raw-jar TLSH
# rated a piece of malware as MORE similar to an unrelated clean mod than to a
# repacked copy of itself. Hashing the raw file is worse than not hashing.
#
# WHAT SURVIVES REPACKING
# -----------------------
# Repackaging, renaming and reordering all rewrite the constant pool and the
# archive layout. What they cannot rewrite, without breaking the program, is
# what the code DOES:
#
#   1. the opcode stream, with operands stripped. Renaming a class changes the
#      pool indices embedded in operands, but the sequence of instructions
#      (aload, invokevirtual, ifne, ...) is what the JVM actually executes and
#      an obfuscator cannot alter it without changing behaviour.
#   2. the external API surface: which JDK classes and methods get called.
#      Malware still has to reach Runtime.exec, URLClassLoader.defineClass or
#      Cipher.getInstance no matter what it renames its own classes to.
#   3. coarse structure: method count, per-method code lengths, branch density.
#
# Those three are the features. Everything else is packaging.
#
# WHAT A SIGNATURE IS
# -------------------
# A fixed-size JSON document holding per-class opcode digests, a MinHash sketch
# of the API surface, a TLSH of the aggregate opcode stream, and structural
# counters.
#
# Be honest about what this does and does not protect. It is NOT a privacy
# boundary. Every fuzzy or perceptual hash leaks some of its input, and this
# one is no exception: the MinHash sketch leaks API set membership, TLSH leaks
# structural layout, and truncated opcode digests let anyone holding a
# candidate sample confirm whether it is the one described. PhotoDNA itself
# has been inverted to recognisable images, so nothing here should be sold as
# irreversible.
#
# What a signature actually buys you is narrower and still worth having: it is
# small enough to paste into a report, and it is inert. Sharing it moves
# detection capability between analysts without moving a live executable
# payload, which is the practical risk when people mail malware samples
# around. Treat a signature as sensitive-ish metadata about a sample, not as
# an anonymised artefact.
#
# MATCHING
# --------
# Nearest neighbour against a signature database, three independent signals
# combined. Class-digest overlap is the strongest and most specific; API
# surface catches heavily rewritten variants; TLSH catches the middle ground.
# Deliberately not a single number, so a report can say WHICH signal fired.

# py-tlsh ships wheels but is NOT made a hard requirement: it contributes the
# weakest of the three similarity signals (measured at 0.68 similarity between
# two entirely unrelated Java programs, because all Java bytecode has a similar
# opcode distribution). Class-digest overlap and API surface carry the result.
# If it is missing the engine drops that signal and says so, rather than
# refusing to start.
try:
    import tlsh as _tlsh
except ImportError:
    _tlsh = None
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--user",
                        "--break-system-packages", "py-tlsh"],
                       check=True, timeout=180,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import tlsh as _tlsh
    except Exception:
        _tlsh = None


SIGNATURE_VERSION = 2

# ---------------------------------------------------------------------------
# Constant pool
# ---------------------------------------------------------------------------

# tag -> fixed body width. Utf8 (1) is variable. Long (5) and Double (6) each
# eat TWO pool slots, a detail that silently desynchronises the whole parse
# if missed.
_CP_WIDTHS = {
    3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4,
    15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2,
}
_CLASS_MAGIC = b"\xca\xfe\xba\xbe"


class ClassParseError(Exception):
    pass


def parse_class(data):
    """Parse enough of a classfile to reach the code.

    Returns (pool, refs, cursor) where pool maps index -> str for Utf8
    entries, refs maps index -> (tag, idx1, idx2) for the reference-style
    entries needed to resolve method calls, and cursor is the offset of
    access_flags, i.e. the first byte after the constant pool.
    """
    if len(data) < 10 or data[:4] != _CLASS_MAGIC:
        raise ClassParseError("not a classfile")
    count = int.from_bytes(data[8:10], "big")
    pool = {}
    refs = {}
    pos = 10
    i = 1
    while i < count:
        if pos >= len(data):
            raise ClassParseError("truncated constant pool")
        tag = data[pos]
        pos += 1
        if tag == 1:
            length = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            raw = data[pos:pos + length]
            pos += length
            try:
                pool[i] = raw.decode("utf-8")
            except UnicodeDecodeError:
                pool[i] = raw.decode("latin-1", "ignore")
        else:
            width = _CP_WIDTHS.get(tag)
            if width is None:
                raise ClassParseError("unknown constant pool tag %d" % tag)
            if tag in (7, 9, 10, 11, 12, 8):
                refs[i] = (tag,
                           int.from_bytes(data[pos:pos + 2], "big"),
                           int.from_bytes(data[pos + 2:pos + 4], "big")
                           if width >= 4 else 0)
            pos += width
            if tag in (5, 6):
                i += 1
        i += 1
    return pool, refs, pos


# ---------------------------------------------------------------------------
# Opcode table
# ---------------------------------------------------------------------------

def _build_opcode_widths():
    """Operand byte count per opcode. Variable-length ones are marked None
    and handled explicitly in the walker."""
    w = {}
    for op in range(0x00, 0x10):
        w[op] = 0
    w[0x10] = 1                      # bipush
    w[0x11] = 2                      # sipush
    w[0x12] = 1                      # ldc
    w[0x13] = 2                      # ldc_w
    w[0x14] = 2                      # ldc2_w
    for op in range(0x15, 0x1a):     # iload..aload
        w[op] = 1
    for op in range(0x1a, 0x36):     # *load_<n>, *aload
        w[op] = 0
    for op in range(0x36, 0x3b):     # istore..astore
        w[op] = 1
    for op in range(0x3b, 0x84):     # stores, stack ops, arithmetic
        w[op] = 0
    w[0x84] = 2                      # iinc
    for op in range(0x85, 0x99):     # conversions, comparisons
        w[op] = 0
    for op in range(0x99, 0xa9):     # if*, goto, jsr
        w[op] = 2
    w[0xa9] = 1                      # ret
    w[0xaa] = None                   # tableswitch
    w[0xab] = None                   # lookupswitch
    for op in range(0xac, 0xb2):     # returns
        w[op] = 0
    for op in range(0xb2, 0xb9):     # field access, invokevirtual/special/static
        w[op] = 2
    w[0xb9] = 4                      # invokeinterface
    w[0xba] = 4                      # invokedynamic
    w[0xbb] = 2                      # new
    w[0xbc] = 1                      # newarray
    w[0xbd] = 2                      # anewarray
    w[0xbe] = 0                      # arraylength
    w[0xbf] = 0                      # athrow
    w[0xc0] = 2                      # checkcast
    w[0xc1] = 2                      # instanceof
    w[0xc2] = 0                      # monitorenter
    w[0xc3] = 0                      # monitorexit
    w[0xc4] = None                   # wide
    w[0xc5] = 3                      # multianewarray
    w[0xc6] = 2                      # ifnull
    w[0xc7] = 2                      # ifnonnull
    w[0xc8] = 4                      # goto_w
    w[0xc9] = 4                      # jsr_w
    return w


_OPCODE_WIDTHS = _build_opcode_widths()
_INVOKE_OPS = (0xb6, 0xb7, 0xb8, 0xb9, 0xba)
_BRANCH_OPS = set(range(0x99, 0xa9)) | {0xc6, 0xc7, 0xc8, 0xc9}


def walk_code(code):
    """Yield (offset, opcode, operand_bytes) for one method body.

    Operands are yielded but deliberately discarded by the feature extractor:
    they contain constant pool indices, which is exactly the part an
    obfuscator rewrites.
    """
    pos = 0
    n = len(code)
    while pos < n:
        op = code[pos]
        start = pos
        pos += 1
        width = _OPCODE_WIDTHS.get(op)
        if width is None:
            if op == 0xc4:                       # wide
                if pos >= n:
                    return
                sub = code[pos]
                pos += 1
                pos += 4 if sub == 0x84 else 2   # wide iinc vs wide load/store
            elif op == 0xaa:                     # tableswitch
                pad = (4 - (pos % 4)) % 4
                pos += pad
                if pos + 12 > n:
                    return
                low = int.from_bytes(code[pos + 4:pos + 8], "big", signed=True)
                high = int.from_bytes(code[pos + 8:pos + 12], "big", signed=True)
                pos += 12 + max(0, (high - low + 1)) * 4
            elif op == 0xab:                     # lookupswitch
                pad = (4 - (pos % 4)) % 4
                pos += pad
                if pos + 8 > n:
                    return
                npairs = int.from_bytes(code[pos + 4:pos + 8], "big", signed=True)
                pos += 8 + max(0, npairs) * 8
            else:
                return
            yield (start, op, b"")
            continue
        operand = code[pos:pos + width]
        pos += width
        yield (start, op, operand)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _read_attributes(data, pos, pool, want):
    """Walk an attribute table, returning the body of attributes named in
    `want` plus the position after the table."""
    if pos + 2 > len(data):
        raise ClassParseError("truncated attribute table")
    count = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    found = []
    for _ in range(count):
        if pos + 6 > len(data):
            raise ClassParseError("truncated attribute")
        name_idx = int.from_bytes(data[pos:pos + 2], "big")
        length = int.from_bytes(data[pos + 2:pos + 6], "big")
        pos += 6
        body = data[pos:pos + length]
        pos += length
        if pool.get(name_idx) in want:
            found.append((pool.get(name_idx), body))
    return found, pos


def _resolve_ref(pool, refs, index):
    """Turn a Methodref/Fieldref index into 'java/lang/Runtime.exec'."""
    entry = refs.get(index)
    if not entry:
        return None
    _tag, class_idx, nat_idx = entry
    cls = refs.get(class_idx)
    class_name = pool.get(cls[1]) if cls else None
    nat = refs.get(nat_idx)
    member = pool.get(nat[1]) if nat else None
    if not class_name:
        return None
    return "%s.%s" % (class_name, member) if member else class_name


def extract_class_features(data):
    """Feature vector for a single classfile.

    Returns None for anything unparseable. Obfuscators do ship deliberately
    malformed classfiles that no parser will read; those are counted as
    unparsed rather than being allowed to poison the signature.
    """
    pool, refs, pos = parse_class(data)

    pos += 6                                        # access_flags, this, super
    if pos + 2 > len(data):
        raise ClassParseError("truncated header")
    iface_count = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2 + iface_count * 2

    for _section in ("fields", "methods"):
        pass                                        # handled explicitly below

    # fields
    if pos + 2 > len(data):
        raise ClassParseError("truncated fields")
    field_count = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    for _ in range(field_count):
        pos += 6                                    # access, name, descriptor
        _attrs, pos = _read_attributes(data, pos, pool, ())

    # methods
    if pos + 2 > len(data):
        raise ClassParseError("truncated methods")
    method_count = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2

    opcode_stream = bytearray()
    method_shapes = []
    api = set()
    branches = 0
    invokes = 0

    for _ in range(method_count):
        pos += 6
        attrs, pos = _read_attributes(data, pos, pool, ("Code",))
        for _name, body in attrs:
            if len(body) < 8:
                continue
            code_len = int.from_bytes(body[4:8], "big")
            code = body[8:8 + code_len]
            ops = bytearray()
            for _off, op, operand in walk_code(code):
                ops.append(op)
                if op in _BRANCH_OPS:
                    branches += 1
                if op in _INVOKE_OPS:
                    invokes += 1
                    if len(operand) >= 2:
                        idx = int.from_bytes(operand[:2], "big")
                        name = _resolve_ref(pool, refs, idx)
                        # Only external API matters. The sample's own class
                        # names are exactly what gets renamed, so keeping them
                        # would make the signature fragile.
                        if name and _is_external(name):
                            api.add(name)
            if ops:
                opcode_stream.extend(ops)
                method_shapes.append(len(ops))

    return {
        "opcodes": bytes(opcode_stream),
        "api": api,
        "methods": method_count,
        "method_shapes": sorted(method_shapes),
        "branches": branches,
        "invokes": invokes,
    }


_EXTERNAL_PREFIXES = (
    "java/", "javax/", "jdk/", "sun/", "com/sun/",
    "net/minecraft/", "net/fabricmc/", "net/minecraftforge/",
    "org/spongepowered/", "com/mojang/", "org/apache/", "org/slf4j/",
    "com/google/", "io/netty/", "org/objectweb/", "kotlin/",
)


def _is_external(name):
    return name.startswith(_EXTERNAL_PREFIXES)


# ---------------------------------------------------------------------------
# MinHash over the API surface
# ---------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Compact sketch encoding
#
# A signature must not approach the size of the sample it describes. The
# point of storing a fingerprint instead of the file is partly safety and
# partly storage, and a 6.8 KB signature for a 6.6 KB mod fails both.
#
# Three things were wasting space:
#   1. MinHash was serialised as a JSON array of 64-bit decimals, about
#      1.3 KB per sketch, and a signature carries two or three of them. That
#      cost is paid even by a sample with five classes.
#   2. Per-class digests were stored as a JSON array of quoted hex strings:
#      15 bytes of JSON for 6 bytes of information, and the list grows with
#      the sample.
#   3. Base64 adds a third on top of the bytes it encodes.
#
# The fix is b-bit minwise hashing (Li and Konig): keep only the low 16 bits
# of each of 128 permutations, which is 256 bytes, and correct the similarity
# estimate for the collisions those truncated bits introduce. That is a
# FIXED size no matter how large the sample is.
#
# Z85 encodes 4 bytes as 5 characters (25% overhead versus base64's 33%) and
# its alphabet contains no quote or backslash, so it survives JSON without
# escaping. 128 permutations become 320 characters instead of ~1300.
# --------------------------------------------------------------------------

Z85_CHARS = ("0123456789abcdefghijklmnopqrstuvwxyz"
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")
_Z85_INDEX = {c: i for i, c in enumerate(Z85_CHARS)}


def z85_encode(data):
    if len(data) % 4:
        data = data + b"\x00" * (4 - len(data) % 4)
    out = []
    for i in range(0, len(data), 4):
        value = int.from_bytes(data[i:i + 4], "big")
        chunk = []
        for _ in range(5):
            chunk.append(Z85_CHARS[value % 85])
            value //= 85
        out.append("".join(reversed(chunk)))
    return "".join(out)


def z85_decode(text):
    out = bytearray()
    for i in range(0, len(text) - len(text) % 5, 5):
        value = 0
        for c in text[i:i + 5]:
            idx = _Z85_INDEX.get(c)
            if idx is None:
                return bytes(out)
            value = value * 85 + idx
        out.extend(value.to_bytes(4, "big"))
    return bytes(out)


SKETCH_PERMUTATIONS = 128
SKETCH_BITS = 16
_SKETCH_MASK = (1 << SKETCH_BITS) - 1
_SKETCH_COLLISION = 1.0 / (1 << SKETCH_BITS)

MINHASH_PERMUTATIONS = 64
_MASK64 = (1 << 64) - 1


def minhash(items, k=MINHASH_PERMUTATIONS):
    """Fixed-size sketch of a set, so Jaccard similarity can be estimated
    from the signature alone without shipping the underlying strings. Also
    means the signature stays constant size no matter how big the jar is."""
    if not items:
        return []
    sketch = []
    base = [int.from_bytes(hashlib.sha256(s.encode("utf-8")).digest()[:8], "big")
            for s in items]
    for i in range(k):
        salt = (i * 0x9E3779B97F4A7C15) & _MASK64
        sketch.append(min(((h ^ salt) * 0xFF51AFD7ED558CCD) & _MASK64 for h in base))
    return sketch


def minhash_similarity(a, b):
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(1 for x, y in zip(a, b) if x == y) / float(len(a))


def build_sketch(items, k=SKETCH_PERMUTATIONS):
    """Fixed-size b-bit MinHash of a set, Z85 encoded.

    Returns "" for an empty set. The result is 320 characters for any input,
    whether the set holds five elements or forty thousand.
    """
    items = list(items)
    if not items:
        return ""
    base = [int.from_bytes(hashlib.sha256(str(s).encode("utf-8")).digest()[:8], "big")
            for s in items]
    packed = bytearray()
    for i in range(k):
        salt = (i * 0x9E3779B97F4A7C15) & _MASK64
        m = min(((h ^ salt) * 0xFF51AFD7ED558CCD) & _MASK64 for h in base)
        packed.extend((m & _SKETCH_MASK).to_bytes(SKETCH_BITS // 8, "big"))
    return z85_encode(bytes(packed))


def sketch_jaccard(a, b):
    """Estimate Jaccard from two b-bit sketches.

    Truncating each minimum to 16 bits means two DIFFERENT minima agree by
    chance about once every 65,536 comparisons, so the raw agreement rate is
    biased upward by that amount and is corrected here. Without the
    correction every unrelated pair would show a small constant similarity.
    """
    if not a or not b or len(a) != len(b):
        return 0.0
    da, db = z85_decode(a), z85_decode(b)
    if len(da) != len(db) or not da:
        return 0.0
    step = SKETCH_BITS // 8
    n = len(da) // step
    if not n:
        return 0.0
    agree = sum(1 for i in range(n)
                if da[i * step:(i + 1) * step] == db[i * step:(i + 1) * step])
    raw = agree / float(n)
    corrected = (raw - _SKETCH_COLLISION) / (1.0 - _SKETCH_COLLISION)
    return max(0.0, min(1.0, corrected))


def sketch_overlap(a, b, count_a, count_b):
    """Jaccard plus set sizes gives intersection, and intersection over the
    smaller set gives containment. That is what lets the full per-class digest
    list be dropped: containment was the only thing it was still needed for,
    and a dropper hiding inside a larger mod is found by containment."""
    j = sketch_jaccard(a, b)
    if j <= 0 or not count_a or not count_b:
        return 0.0, 0.0
    inter = j * (count_a + count_b) / (1.0 + j)
    inter = min(inter, float(min(count_a, count_b)))
    return j, inter / float(min(count_a, count_b))


# ---------------------------------------------------------------------------
# TLSH wrapper
# ---------------------------------------------------------------------------

def tlsh_hash(data):
    if _tlsh is None or len(data) < 256:
        return None
    try:
        h = _tlsh.hash(data)
        return h if h and h != "TNULL" else None
    except Exception:
        return None


def tlsh_distance(a, b):
    if _tlsh is None or not a or not b:
        return None
    try:
        return _tlsh.diff(a, b)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Sample signature
# ---------------------------------------------------------------------------

# A 50 MB modpack jar is a normal thing to be handed, and it can hold tens of
# thousands of classes across dozens of embedded jars. These ceilings are what
# the fingerprinter will actually walk; the number of digests KEPT in the
# signature is capped separately (see max_class_digests) so the artifact stays
# small enough to paste, with the MinHash sketch covering whatever is dropped.
MAX_CLASSES = 40000
MAX_CLASS_BYTES = 16 * 1024 * 1024
MAX_NEST_DEPTH = 4
MAX_NESTED_JARS = 250
MAX_NESTED_JAR_BYTES = 128 * 1024 * 1024
MAX_STORED_CLASS_DIGESTS = 8000

# --------------------------------------------------------------------------
# Encrypted archives
#
# Sample-sharing services ship malware inside a password-protected zip so it
# survives mail scanners; "infected" is the near-universal convention, and
# MalwareBazaar uses it. The app already knows how to open these, and the
# fingerprinter did not, so an encrypted-but-perfectly-readable archive came
# back as "deliberately malformed archive" and was auto-classified malware on
# the strength of that. Wrong verdict, wrong reason, and it would have taught
# the corpus a lie.
#
# Encryption is now detected from the header flag, decryption is attempted
# with a caller-supplied password first and then the standard conventions,
# and an archive that stays locked is reported as ENCRYPTED rather than
# malformed. Encrypted is not a verdict: plenty of legitimate samples arrive
# that way.
# --------------------------------------------------------------------------
ZIP_PASSWORD_CANDIDATES = ("infected", "malware", "virus", "password", "bazaar")

try:
    import pyzipper as _pyzipper
except ImportError:
    _pyzipper = None
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--user",
                        "--break-system-packages", "pyzipper"],
                       check=True, timeout=180,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import pyzipper as _pyzipper
    except Exception:
        _pyzipper = None


def _entry_encrypted(info):
    return bool(info.flag_bits & 0x1)


def open_archive(blob, password=None):
    """Open an archive, decrypting it if that is what it needs.

    Returns (zipfile-like, password_used, encrypted). WinZip AES (method 99)
    needs pyzipper; stdlib zipfile handles only legacy ZipCrypto, so a
    plain-zipfile read of an AES entry raises and looks exactly like
    corruption.
    """
    raw = io.BytesIO(blob)
    try:
        zf = zipfile.ZipFile(raw)
        infos = zf.infolist()
    except Exception:
        zf = None
        infos = []
    encrypted = any(_entry_encrypted(i) for i in infos) if infos else False
    if zf is not None and not encrypted:
        return zf, None, False

    aes = any(getattr(i, "compress_type", 0) == 99 for i in infos)
    candidates = ([password] if password else []) + list(ZIP_PASSWORD_CANDIDATES)
    openers = []
    if _pyzipper is not None:
        openers.append(lambda: _pyzipper.AESZipFile(io.BytesIO(blob)))
    if not aes:
        openers.append(lambda: zipfile.ZipFile(io.BytesIO(blob)))
    for make in openers:
        for pw in candidates:
            if not pw:
                continue
            try:
                cand = make()
                cand.setpassword(pw.encode("utf-8"))
                target = next((i for i in cand.infolist() if not i.is_dir()), None)
                if target is None:
                    continue
                with cand.open(target) as fh:
                    fh.read(1)
                return cand, pw, True
            except Exception:
                continue
    return zf, None, True

# --------------------------------------------------------------------------
# Decompression bomb guards
#
# Everything above is a per-item limit, and per-item limits alone do not stop
# a bomb. Three specific holes they leave:
#
#   1. info.file_size is a number the ARCHIVE claims, taken from its own
#      header. zipfile does not verify it before or during decompression, so
#      an entry declaring 4 KB can expand to gigabytes and the size check
#      passes right before the read blows up the process. Reads here are
#      therefore bounded by the reader, not by the claim, and an entry whose
#      real output exceeds its declared size is dropped as malformed.
#   2. Per-entry caps multiply. 40,000 entries at 16 MB each is 640 GB, all
#      individually "within limits". A single cumulative budget is shared
#      across the entire walk, nested archives included.
#   3. Nesting was bounded by depth but not by breadth, so an archive holding
#      thousands of archives, each holding thousands more, stays inside the
#      depth limit and still explodes combinatorially. Entries visited and
#      archives opened are both counted globally.
#
# A tripped guard is not a crash and not a silent truncation: the walk stops,
# what was gathered so far is still fingerprinted, and the reason is recorded
# on the signature so the analyst knows the picture is partial.
# --------------------------------------------------------------------------
SSDEEP_MAX_BYTES = 256 * 1024
MAX_TOTAL_DECOMPRESSED = 768 * 1024 * 1024
MAX_ENTRIES_VISITED = 200000
MAX_ARCHIVES_OPENED = 400
# Ratios above this on a sizeable entry are the signature of a bomb: deflate
# on real code sits well under 10:1, while a run of identical bytes reaches
# 1000:1 and higher.
MAX_COMPRESSION_RATIO = 250
RATIO_CHECK_MIN_BYTES = 1024 * 1024


def classify_bomb(blob, budget=None):
    """Work out WHAT kind of bomb this is, from the central directory only.

    Header inspection decompresses nothing, so this stays safe on exactly the
    archives that are unsafe to read. The guard messages from the walk are
    folded in too, since a declared-size lie is only detectable once a read
    has been attempted.
    """
    types, detail = [], {}
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            infos = zf.infolist()[:MAX_ENTRIES_VISITED]
    except Exception as e:
        return ["malformedArchive"], {"error": str(e)[:200]}
    if any(_entry_encrypted(i) for i in infos):
        detail["encrypted"] = True


    files = [i for i in infos if not i.is_dir()]
    declared = sum(i.file_size for i in files)
    compressed = sum(i.compress_size for i in files) or 1
    archives = [i for i in files
                if i.filename.lower().endswith((".jar", ".zip"))]
    classes = [i for i in files if i.filename.lower().endswith(".class")]
    biggest = max((i.file_size for i in files), default=0)
    worst_ratio = max((i.file_size / float(i.compress_size or 1)
                       for i in files), default=0.0)

    detail.update({
        "entries": len(files),
        "declared_bytes": declared,
        "compressed_bytes": compressed,
        "overall_ratio": round(declared / float(compressed), 1),
        "worst_entry_ratio": round(worst_ratio, 1),
        "largest_entry_bytes": biggest,
        "nested_archives": len(archives),
    })

    if worst_ratio > MAX_COMPRESSION_RATIO or (declared / float(compressed)) > MAX_COMPRESSION_RATIO:
        types.append("zipBomb")
        detail["kind"] = "compression ratio"
    if len(archives) > MAX_NESTED_JARS:
        types.append("zipBomb")
        detail["kind"] = "nested archive fan-out"
    if len(files) > MAX_ENTRIES_VISITED // 2:
        types.append("zipBomb")
        detail["kind"] = "entry flood"
    if declared > MAX_TOTAL_DECOMPRESSED:
        types.append("zipBomb")
        detail.setdefault("kind", "total expanded size")
    # A single enormous classfile is a PARSER bomb, not a zip bomb: it costs
    # nothing to decompress and everything to analyse. This is the shape the
    # MalwareBazaar stealer uses, and it is what stalls a decompiler.
    if any(i.file_size > 1024 * 1024 for i in classes):
        types.append("parserBomb")
        detail["largest_class_bytes"] = max(i.file_size for i in classes)
    for msg in (budget.tripped if budget else []):
        if "expanded past its declared size" in msg:
            types.append("zipBomb")
            detail["kind"] = "declared size mismatch"
        elif "compression ratio" in msg:
            types.append("zipBomb")
            detail.setdefault("kind", "compression ratio")
        elif "nested archive limit" in msg:
            types.append("zipBomb")
            detail.setdefault("kind", "nested archive fan-out")
        elif "entry limit" in msg or "budget" in msg:
            types.append("zipBomb")
            detail.setdefault("kind", "resource exhaustion")
    if budget and budget.tripped:
        detail["guards"] = budget.tripped
    if budget and budget.locked:
        # Locked, not broken. This is the shape every sample-sharing service
        # ships, and calling it malformed produced a bomb verdict on a file
        # the rest of the app opens without complaint.
        detail["encrypted"] = True
        detail["locked"] = budget.locked
        return ["encryptedArchive"], detail
    if budget and budget.encrypted:
        detail["encrypted"] = True
        detail["password_used"] = sorted(budget.passwords)[:1]
    if budget and budget.read_failures and budget.read_failures >= max(1, budget.reads_attempted):
        # Nothing in the archive could be decompressed at all.
        types.append("malformedArchive")
        detail["read_failures"] = budget.read_failures
    seen, ordered = set(), []
    for t in types:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered, detail


class ZipBudget:
    """Shared limits for one fingerprinting walk."""

    def __init__(self):
        self.bytes_left = MAX_TOTAL_DECOMPRESSED
        self.entries_left = MAX_ENTRIES_VISITED
        self.archives_left = MAX_ARCHIVES_OPENED
        self.tripped = []
        self.read_failures = 0
        self.reads_attempted = 0
        self.encrypted = 0
        self.locked = 0
        self.passwords = set()

    def trip(self, reason):
        if reason not in self.tripped:
            self.tripped.append(reason)
            log("fuzzy: decompression guard tripped -- %s" % reason)
        return None

    def visit_entry(self):
        if self.entries_left <= 0:
            return self.trip("entry limit (%d) reached" % MAX_ENTRIES_VISITED) is None and False
        self.entries_left -= 1
        return True

    def open_archive(self):
        if self.archives_left <= 0:
            self.trip("nested archive limit (%d) reached" % MAX_ARCHIVES_OPENED)
            return False
        self.archives_left -= 1
        return True

    def exhausted(self):
        return self.bytes_left <= 0 or self.entries_left <= 0


def safe_zip_read(zf, info, budget, cap):
    """Decompress one entry without trusting anything the archive says.

    Reads in chunks against the remaining global budget and stops one byte
    past the allowed size, so a lying header cannot turn into an unbounded
    allocation. Returns None when the entry is refused.
    """
    declared = info.file_size
    if declared > cap:
        budget.read_failures += 1
        return None
    comp = info.compress_size or 1
    if declared >= RATIO_CHECK_MIN_BYTES and (declared / float(comp)) > MAX_COMPRESSION_RATIO:
        budget.trip("entry %s has a %.0f:1 compression ratio"
                    % (info.filename[:60], declared / float(comp)))
        budget.read_failures += 1
        return None
    # Bound the read by what the entry CLAIMS (plus a little slack), not by
    # the per-entry ceiling. An entry declaring 4 KB then streaming 200 MB is
    # stopped at roughly 4 KB instead of after reading the full cap.
    budget.reads_attempted += 1
    limit = min(cap, budget.bytes_left, max(int(declared * 1.05) + 4096, 65536))
    if limit <= 0:
        budget.trip("total decompressed budget (%d MB) exhausted"
                    % (MAX_TOTAL_DECOMPRESSED // (1024 * 1024)))
        return None
    out = bytearray()
    try:
        with zf.open(info) as fh:
            while True:
                chunk = fh.read(min(1024 * 1024, limit - len(out) + 1))
                if not chunk:
                    break
                out.extend(chunk)
                if len(out) > limit:
                    budget.trip("entry %s expanded past its declared size"
                                % info.filename[:60])
                    budget.read_failures += 1
                    return None
    except Exception:
        # A stream that will not decompress is either corrupt or crafted, and
        # either way the entry is a dead end. Counted so that an archive where
        # EVERY entry fails can be recognised as hostile rather than empty.
        budget.read_failures += 1
        return None
    budget.bytes_left -= len(out)
    return bytes(out)


def _collect_classes(blob, entries, nested, depth=0, label="", budget=None,
                     password=None):
    """Gather every classfile in an archive, descending into embedded jars.

    Nesting is the normal shape of this ecosystem, not an edge case:
      - Fabric "jar-in-jar" ships dependencies under META-INF/jars/
      - CurseForge packs put the actual mod at overrides/mods/*.jar
      - droppers bundle their payload as a resource jar and load it at runtime
    Fingerprinting only the outer layer means a payload one level down is
    invisible, which on a real CurseForge pack produced no signature at all.

    Each embedded jar is ALSO recorded separately in `nested`, so a bundled
    payload can be matched on its own merits rather than being diluted by the
    2000 classes of legitimate library wrapped around it.
    """
    if budget is None:
        budget = ZipBudget()
    zf, used_pw, was_encrypted = open_archive(blob, password)
    if zf is None:
        raise zipfile.BadZipFile("unreadable archive")
    if was_encrypted:
        budget.encrypted += 1
        if used_pw:
            budget.passwords.add(used_pw)
        else:
            budget.locked += 1
    with zf:
        for info in zf.infolist():
            if budget.exhausted():
                break
            if info.is_dir():
                continue
            if not budget.visit_entry():
                break
            name = info.filename
            lower = name.lower()
            if lower.endswith(".class"):
                if len(entries) >= MAX_CLASSES:
                    continue
                data = safe_zip_read(zf, info, budget, MAX_CLASS_BYTES)
                if data is None:
                    continue
                entries.append(data)
            elif lower.endswith((".jar", ".zip")) and depth < MAX_NEST_DEPTH:
                if len(nested) >= MAX_NESTED_JARS or not budget.open_archive():
                    continue
                inner = safe_zip_read(zf, info, budget, MAX_NESTED_JAR_BYTES)
                if inner is None:
                    continue
                inner_path = (label + "!/" + name) if label else name
                inner_entries = []
                try:
                    _collect_classes(inner, inner_entries, nested,
                                     depth + 1, inner_path, budget, password)
                except Exception:
                    continue
                if inner_entries:
                    # Recorded as its OWN layer and deliberately NOT merged
                    # into the parent. Merging made an outer archive appear to
                    # contain every library class it bundles, so a mod that
                    # ships commons-logging scored a perfect containment match
                    # against any other sample's commons-logging layer. Layers
                    # stay separate; compare_nested walks them pairwise.
                    nested.append({"path": inner_path,
                                   "sha256": _sig_sha256(inner),
                                   "bytes": len(inner),
                                   "classes": inner_entries})


def _sig_sha256(data):
    return hashlib.sha256(data).hexdigest()


_RE_JAVA_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_RE_JAVA_LINE_COMMENT = re.compile(r"//[^\n]*")
_RE_JAVA_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
_RE_JAVA_CHAR = re.compile(r"'(?:\\.|[^'\\])*'")
_RE_JAVA_WS = re.compile(r"\s+")
_RE_JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.M)
_RE_JAVA_QUALIFIED = re.compile(r"\b((?:[a-z]\w*\.){2,}[A-Z]\w*)")


def normalise_java(text):
    """Structure-only view of a .java file.

    Comments and string literals are stripped because a decompiler rewrites
    both and neither survives recompilation; whitespace is collapsed because
    formatting is the decompiler's choice, not the author's. What is left is
    the statement structure and the identifiers, which is what actually
    matches between two dumps of the same code.
    """
    text = _RE_JAVA_BLOCK_COMMENT.sub(" ", text)
    text = _RE_JAVA_LINE_COMMENT.sub(" ", text)
    text = _RE_JAVA_STRING.sub('""', text)
    text = _RE_JAVA_CHAR.sub("''", text)
    return _RE_JAVA_WS.sub(" ", text).strip()


def _collect_sources(blob, sources, depth=0, label="", budget=None,
                     password=None):
    """Gather .java files from a decompiled-source archive.

    ModForensics accepts decompiled source zips as a first-class input (that
    is what decompiler.com hands back, and what an analyst working without a
    bridge uploads). Those archives contain no bytecode at all, so a
    bytecode-only fingerprinter refuses them outright, which is exactly the
    error an analyst hits mid-workflow.
    """
    if budget is None:
        budget = ZipBudget()
    zf, _pw, _enc = open_archive(blob, password)
    if zf is None:
        raise zipfile.BadZipFile("unreadable archive")
    with zf:
        for info in zf.infolist():
            if budget.exhausted():
                break
            if info.is_dir():
                continue
            if not budget.visit_entry():
                break
            lower = info.filename.lower()
            if lower.endswith(".java"):
                if len(sources) >= MAX_CLASSES:
                    continue
                data = safe_zip_read(zf, info, budget, MAX_CLASS_BYTES)
                if data is None:
                    continue
                sources.append((info.filename, data.decode("utf-8", "replace")))
            elif lower.endswith((".jar", ".zip")) and depth < MAX_NEST_DEPTH:
                # This branch previously had no breadth limit whatsoever: only
                # depth was checked, so an archive of archives of archives
                # stayed "within depth" and expanded combinatorially.
                if not budget.open_archive():
                    continue
                inner = safe_zip_read(zf, info, budget, MAX_NESTED_JAR_BYTES)
                if inner is None:
                    continue
                try:
                    _collect_sources(inner, sources, depth + 1,
                                     info.filename, budget, password)
                except Exception:
                    continue


def source_features(name, text):
    """Per-file digest plus the external API surface referenced in source."""
    norm = normalise_java(text)
    api = set()
    for m in _RE_JAVA_IMPORT.finditer(text):
        if m.group(1).startswith(_SOURCE_EXTERNAL_PREFIXES):
            api.add(m.group(1))
    for m in _RE_JAVA_QUALIFIED.finditer(text):
        if m.group(1).startswith(_SOURCE_EXTERNAL_PREFIXES):
            api.add(m.group(1))
    return {"digest": hashlib.sha256(norm.encode("utf-8")).hexdigest()[:12],
            "api": api, "norm": norm}


_SOURCE_EXTERNAL_PREFIXES = tuple(
    p.replace("/", ".") for p in _EXTERNAL_PREFIXES)


def build_signature(jar_bytes, filename="sample.jar", label=None, family=None,
                    max_class_digests=MAX_STORED_CLASS_DIGESTS, source_zip=None,
                    password=None):
    """Build the shareable signature document for one jar.

    When `source_zip` is supplied (the bridge already holds the decompiled
    output for every job it ran), the fingerprint carries BOTH halves: opcode
    digests from the bytecode and structural digests from the reconstructed
    source. The two are not interchangeable, and without the source half a
    decompiled-source archive uploaded by somebody else could only ever be
    "possibly related" to the very jar it came from. With it, source matches
    source directly and that cap disappears.
    """
    class_digests = []
    api_all = set()
    opcode_blobs = []
    parsed = unparsed = nocode = 0
    total_methods = total_branches = total_invokes = 0

    entries = []
    nested = []
    budget = ZipBudget()
    try:
        _collect_classes(jar_bytes, entries, nested, depth=0, budget=budget,
                         password=password)
        if not entries and not nested:
            sources = []
            _collect_sources(jar_bytes, sources, budget=budget, password=password)
            if sources:
                sig = _build_source_signature(sources, jar_bytes, filename,
                                              label, family)
                if budget.tripped:
                    sig["truncated"] = budget.tripped
                    sig["self_hash"] = signature_self_hash(sig)
                return sig
            # Nothing came out. Rather than refusing the sample, fall back to
            # hashing the container and say why.
            bomb_types, bomb_detail = classify_bomb(jar_bytes, budget)
            if bomb_types or budget.tripped or budget.read_failures:
                return _build_container_signature(jar_bytes, filename, label,
                                                  family, bomb_types, bomb_detail)
    except zipfile.BadZipFile:
        if jar_bytes[:4] == _CLASS_MAGIC:
            entries = [jar_bytes]          # a bare .class is a valid input
        else:
            raise ValueError("not a jar, classfile, or source archive")

    for data in entries:
        try:
            feat = extract_class_features(data)
        except Exception:
            # A genuine parse failure: truncated, or a deliberately malformed
            # pool of the kind obfuscators ship to break tooling.
            unparsed += 1
            continue
        if not feat:
            unparsed += 1
            continue
        if not feat["opcodes"]:
            # Parsed cleanly, just has no bytecode: interfaces, marker types,
            # constants-only holders. Counting these as failures overstated
            # breakage badly (10% of a normal library) and hid real errors.
            nocode += 1
            api_all |= feat["api"]
            continue
        parsed += 1
        api_all |= feat["api"]
        opcode_blobs.append(feat["opcodes"])
        total_methods += feat["methods"]
        total_branches += feat["branches"]
        total_invokes += feat["invokes"]
        # 12 hex chars is plenty to make collisions negligible across a
        # corpus of this size, and keeps the signature small enough to paste
        # into a report or a forum post.
        class_digests.append(
            hashlib.sha256(feat["opcodes"]).hexdigest()[:12])

    if not parsed and not nested:
        bomb_types, bomb_detail = classify_bomb(jar_bytes, budget)
        if bomb_types or budget.tripped or unparsed or budget.read_failures:
            return _build_container_signature(jar_bytes, filename, label,
                                              family, bomb_types, bomb_detail)
        raise ValueError(
            "nothing fingerprintable in this archive: no compiled classes "
            "(%d without code, %d unparseable) and no .java sources either. "
            "Resource packs and config-only archives have no code to "
            "fingerprint." % (nocode, unparsed))

    # Sort by digest, not by class name: names are what obfuscators change,
    # so ordering by them would make the aggregate hash unstable.
    class_digests = sorted(set(class_digests))
    aggregate = b"".join(sorted(opcode_blobs))

    sig = {
        "sig_version": SIGNATURE_VERSION,
        "kind": "rho9-jar-signature",
        "mode": "bytecode",
        "filename": filename,
        "label": label or "",
        "family": family or "",
        "sha256": hashlib.sha256(jar_bytes).hexdigest(),
        "classes_parsed": parsed,
        "classes_no_code": nocode,
        "classes_unparsed": unparsed,
        # v2: a fixed-size sketch plus the set size, instead of the full
        # digest list. Jaccard comes from the sketch and the intersection
        # (and therefore containment) is recovered from the two set sizes,
        # so nothing that was actually used has been lost. The signature no
        # longer grows with the sample.
        "cls": build_sketch(class_digests),
        "n_cls": len(class_digests),
        "api": build_sketch(sorted(api_all)),
        "api_count": len(api_all),
        "opcode_tlsh": tlsh_hash(aggregate),
        # Each embedded jar gets its own digest set and its own opcode TLSH, so
        # a bundled payload is matchable on its own even when the outer archive
        # is mostly innocent library code.
        "nested": [{
            "path": n["path"],
            "sha256": n["sha256"],
            "bytes": n["bytes"],
            "class_count": len(n["classes"]),
            "cls": build_sketch(_nested_digests(n["classes"])),
            "n_cls": len(_nested_digests(n["classes"])),
        } for n in nested[:MAX_NESTED_JARS]],
        "nested_count": len(nested),
        "nested_classes": sum(len(n["classes"]) for n in nested),
        "structure": {
            "methods": total_methods,
            "branches": total_branches,
            "invokes": total_invokes,
            "branch_density": round(total_branches / max(1, len(aggregate)), 5),
        },
    }
    # The archive's own bytes, always. Seventy characters, and it is the only
    # axis left if a later build cannot parse this sample, or when the same
    # weaponised archive reappears under a different name. It is NOT used for
    # ordinary jar-to-jar comparison, where deflate makes byte similarity
    # meaningless; see compare().
    sig["container"] = {"bytes": len(jar_bytes), "tlsh": tlsh_hash(jar_bytes)}

    if budget.tripped:
        # Recorded on the signature itself so a partial fingerprint is never
        # mistaken for a complete one, by this bridge or by whoever it is
        # shared with.
        sig["truncated"] = budget.tripped
        bomb_types, bomb_detail = classify_bomb(jar_bytes, budget)
        if bomb_types:
            sig["bomb"] = {"types": bomb_types, "detail": bomb_detail}
            tags = ["stealer"] + [t for t in bomb_types if t in FUZZY_TAG_IDS]
            sig["auto_classification"] = {
                "classification": 3, "tags": tags,
                "code": fuzzy_encode_flags(3, tags),
                "reason": "partial parse, guards tripped: "
                          + ", ".join(bomb_types),
            }
    else:
        # A parser bomb costs nothing to unzip, so it never trips a guard: it
        # is only visible in the shape of what came out.
        bomb_types, bomb_detail = classify_bomb(jar_bytes, budget)
        if "parserBomb" in bomb_types:
            sig["bomb"] = {"types": ["parserBomb"], "detail": bomb_detail}
            # It parsed, so there is no need to override the classification.
            # The tag is offered instead, and the analyst decides.
            sig["suggested_tags"] = ["parserBomb"]

    if source_zip:
        try:
            sources = []
            _collect_sources(source_zip, sources, budget=ZipBudget())
            if sources:
                sig["source"] = _source_component(sources)
                sig["mode"] = "bytecode+source"
        except Exception as e:
            log("signature: could not fold in decompiled source: %s" % e)

    sig["self_hash"] = signature_self_hash(sig)
    return sig


def _source_component(sources):
    """The source half of a fingerprint: per-file structural digests, the API
    surface, and a TLSH over the whole normalised body."""
    digests, api_all, norm_total = [], set(), []
    for name, text in sources:
        feat = source_features(name, text)
        digests.append(feat["digest"])
        api_all |= feat["api"]
        norm_total.append(feat["norm"])
    digests = sorted(set(digests))
    aggregate = ("\n".join(sorted(norm_total))).encode("utf-8")
    return {
        "files": len(sources),
        "cls": build_sketch(digests),
        "n_cls": len(digests),
        "api": build_sketch(sorted(api_all)),
        "api_count": len(api_all),
        "tlsh": tlsh_hash(aggregate),
    }


def _build_container_signature(raw_bytes, filename, label, family,
                               bomb_types, bomb_detail):
    """Last-resort fingerprint: hash the archive as an opaque blob.

    Used when nothing inside can be parsed safely. Normally hashing a jar's
    raw bytes is close to useless, because deflate destroys the locality any
    fuzzy hash depends on, and it was measured rating a piece of malware as
    more similar to an unrelated clean mod than to a repack of itself. That
    objection does not apply here: when the archive is a bomb, the CONTAINER
    is the artefact. Two victims handed the same weaponised zip receive the
    same bytes, and matching those bytes is exactly what is wanted.

    An archive built to break the tools that open it is not an accident, so
    it is classified as malware on sight. Per the analyst's instruction the
    default assumption is a stealer, which is what this family overwhelmingly
    turns out to be; the flags are pre-set but remain editable, like any
    other classification in the UI.
    """
    locked = "encryptedArchive" in (bomb_types or ())
    if locked:
        # No verdict is possible without the password, and guessing one would
        # poison the corpus. Flag it for review and say what is needed.
        tags = ["encryptedArchive", "needsReview"]
        classification = 0
    else:
        tags = ["stealer"] + [t for t in bomb_types if t in FUZZY_TAG_IDS]
        classification = 3
    if not bomb_types:
        tags.append("malformedArchive")
    sig = {
        "sig_version": SIGNATURE_VERSION,
        "kind": "rho9-jar-signature",
        "mode": "container",
        "filename": filename,
        "label": label or "",
        "family": family or "",
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "classes_parsed": 0,
        "classes_no_code": 0,
        "classes_unparsed": 0,
        "cls": "",
        "n_cls": 0,
        "api": "",
        "api_count": 0,
        "opcode_tlsh": None,
        "nested": [],
        "nested_count": 0,
        "nested_classes": 0,
        "structure": {"methods": 0, "branches": 0, "invokes": 0,
                      "branch_density": 0},
        # The container hash itself: raw bytes, both algorithms.
        "container": {
            "bytes": len(raw_bytes),
            "tlsh": tlsh_hash(raw_bytes),
            # ppdeep is pure Python and costs seconds per megabyte, so it is
            # only run on the leading window; TLSH is native and covers the
            # whole blob. Measured: hashing a 1 MB container took 6.5s before
            # this cap.
            "ssdeep": (_ppdeep.hash(raw_bytes[:SSDEEP_MAX_BYTES])
                       if _ppdeep is not None else None),
            "ssdeep_window": min(len(raw_bytes), SSDEEP_MAX_BYTES),
        },
        "bomb": {"types": bomb_types or ["malformedArchive"],
                 "detail": bomb_detail},
        "auto_classification": {
            "classification": classification,
            "tags": tags,
            "code": fuzzy_encode_flags(classification, tags),
            "reason": ("archive is password protected and no known password "
                       "opened it, so its contents were never seen"
                       if locked else
                       "archive could not be safely parsed: "
                       + ", ".join(bomb_types or ["malformed"])),
        },
    }
    sig["self_hash"] = signature_self_hash(sig)
    return sig


def _build_source_signature(sources, raw_bytes, filename, label, family):
    """Fingerprint a decompiled-source archive.

    Marked mode="source" and NOT interchangeable with a bytecode fingerprint:
    a normalised-source digest and an opcode digest are different things and
    comparing them directly would produce confident nonsense. Cross-mode
    comparison falls back to the API surface, which is the one feature that
    means the same thing on both sides.
    """
    comp = _source_component(sources)
    sig = {
        "sig_version": SIGNATURE_VERSION,
        "kind": "rho9-jar-signature",
        "mode": "source",
        "filename": filename,
        "label": label or "",
        "family": family or "",
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "classes_parsed": len(sources),
        "classes_no_code": 0,
        "classes_unparsed": 0,
        "cls": comp["cls"],
        "n_cls": comp["n_cls"],
        "api": comp["api"],
        "api_count": comp["api_count"],
        "opcode_tlsh": comp["tlsh"],
        # Same shape a compiled jar carries, so source-to-source comparison is
        # one code path rather than a special case.
        "source": comp,
        "nested": [],
        "nested_count": 0,
        "nested_classes": 0,
        "structure": {"methods": 0, "branches": 0, "invokes": 0,
                      "branch_density": 0},
    }
    sig["self_hash"] = signature_self_hash(sig)
    return sig


def _nested_digests(class_list):
    return sorted({hashlib.sha256(_nested_opcodes(c)).hexdigest()[:12]
                   for c in class_list if _nested_opcodes(c)})


def _nested_opcodes(class_bytes):
    try:
        feat = extract_class_features(class_bytes)
        return feat["opcodes"] if feat else b""
    except Exception:
        return b""


def signature_self_hash(sig):
    """Integrity check for a signature that has been pasted between people.
    Not a security boundary, an anti-corruption one."""
    body = {k: v for k, v in sig.items() if k != "self_hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]


def verify_signature(sig):
    if not isinstance(sig, dict) or sig.get("kind") != "rho9-jar-signature":
        return False, "not a Rho-9 jar signature"
    ver = sig.get("sig_version")
    if not isinstance(ver, int) or ver < 1:
        return False, "signature carries no usable version"
    if ver > SIGNATURE_VERSION:
        return False, ("signature version %s is newer than this build, which "
                       "speaks version %d" % (ver, SIGNATURE_VERSION))
    # Older signatures are still readable: v1 carried full digest lists and
    # plain MinHash arrays, and the comparison path uses those directly when
    # both sides have them, or rebuilds a sketch from them when only one
    # side does. Rejecting them would have orphaned every hash file already
    # shared.
    if sig.get("self_hash") != signature_self_hash(sig):
        return False, "self hash mismatch, signature was altered in transit"
    return True, "ok"


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def _truncated(sig):
    return len(sig.get("class_digests") or []) < (sig.get("class_digest_total") or 0)


def _has_bytecode(sig):
    return sig.get("mode", "bytecode") != "source"


def compare(a, b):
    """Compare two signatures using whichever halves both sides carry.

    A fingerprint may hold a bytecode half, a source half, or both. Both are
    tried and the stronger result wins, so a decompiled-source archive matches
    the jar it came from at full strength provided that jar was fingerprinted
    with its source folded in. Only when the two sides share no half at all
    does it fall back to the API surface, which is the one feature meaning the
    same thing either way, and that result stays capped at "possibly related".
    """
    results = []
    # Container bytes are only meaningful when at least one side could not be
    # parsed. Comparing two ordinary jars byte-wise measures deflate, not
    # code, and was measured calling malware more similar to a clean mod than
    # to its own repack.
    ca, cb = a.get("container"), b.get("container")
    if ca and cb and (a.get("mode") == "container" or b.get("mode") == "container"):
        results.append(_compare_container(ca, cb))
    if a.get("mode") != "container" and b.get("mode") != "container" \
            and _has_bytecode(a) and _has_bytecode(b):
        results.append(_compare_bytecode(a, b))
    sa, sb = a.get("source"), b.get("source")
    if sa and sb:
        src = _compare_source(sa, sb)
        if src:
            results.append(src)
    if not results:
        api_sim = minhash_similarity(a.get("api_minhash"), b.get("api_minhash"))
        return {
            "score": round(0.5 * api_sim, 4),
            "verdict": "possibly related" if api_sim >= 0.60 else "unrelated",
            "class_overlap": 0.0, "containment": 0.0,
            "api_similarity": round(api_sim, 4),
            "opcode_tlsh_distance": None, "shared_classes": 0,
            "matched_on": "api surface only",
            "cross_mode": "%s vs %s" % (a.get("mode", "bytecode"),
                                        b.get("mode", "bytecode")),
        }
    return max(results, key=lambda r: r["score"])


def _compare_container(ca, cb):
    """Raw-bytes similarity, used only when both sides are unparseable
    containers. Two victims handed the same weaponised archive get the same
    bytes, so byte similarity is the right question here even though it is
    the wrong question for an ordinary jar."""
    sim = 0.0
    if _ppdeep is not None and ca.get("ssdeep") and cb.get("ssdeep"):
        try:
            sim = _ppdeep.compare(ca["ssdeep"], cb["ssdeep"]) / 100.0
        except Exception:
            sim = 0.0
    if sim <= 0:
        dist = tlsh_distance(ca.get("tlsh"), cb.get("tlsh"))
        sim = max(0.0, 1.0 - (dist / 300.0)) if dist is not None else 0.0
    if sim >= 0.95:
        verdict = "same build or trivial repack"
    elif sim >= 0.60:
        verdict = "same family, modified"
    elif sim >= 0.35:
        verdict = "possibly related"
    else:
        verdict = "unrelated"
    return {"score": round(sim, 4), "verdict": verdict,
            "class_overlap": 0.0, "containment": 0.0,
            "api_similarity": 0.0, "opcode_tlsh_distance": None,
            "shared_classes": 0, "matched_on": "container bytes"}


def _layer_overlap(a, b, exact_key, sketch_key="cls", count_key="n_cls"):
    """Jaccard, containment and intersection size for one pair of layers.

    Exact digest sets are used when BOTH sides carry them, so signatures
    written by v1 stay fully comparable with each other. Otherwise the b-bit
    sketches are used and the intersection is recovered from the two set
    sizes, which is what allows the per-class digest list to be dropped:
    containment was the only thing still needing it, and containment is what
    finds a dropper hiding inside a larger mod.
    """
    ea, eb = a.get(exact_key), b.get(exact_key)
    if ea and eb:
        sa, sb = set(ea), set(eb)
        union = len(sa | sb)
        overlap = (len(sa & sb) / float(union)) if union else 0.0
        containment = (len(sa & sb) / float(min(len(sa), len(sb)))) if (sa and sb) else 0.0
        return overlap, containment, len(sa & sb)
    ska = a.get(sketch_key) or (build_sketch(ea) if ea else "")
    skb = b.get(sketch_key) or (build_sketch(eb) if eb else "")
    ca = a.get(count_key) or (len(ea) if ea else 0)
    cb = b.get(count_key) or (len(eb) if eb else 0)
    if not ska or not skb or not ca or not cb:
        return 0.0, 0.0, 0
    j, cont = sketch_overlap(ska, skb, ca, cb)
    shared = int(round(j * (ca + cb) / (1.0 + j))) if j > 0 else 0
    return j, cont, shared


def _api_similarity(a, b):
    """v2 carries a Z85 sketch; v1 carried a plain MinHash array."""
    ska, skb = a.get("api"), b.get("api")
    if ska and skb:
        return sketch_jaccard(ska, skb)
    return minhash_similarity(a.get("api_minhash"), b.get("api_minhash"))


def _compare_source(sa, sb):
    """Source half against source half. Both sides come from this bridge's
    own decompiler, so no cross-decompiler normalisation is needed."""
    overlap, containment, shared = _layer_overlap(sa, sb, "digests")
    if not shared and overlap <= 0:
        return None
    api_sim = _api_similarity(sa, sb)
    dist = tlsh_distance(sa.get("tlsh"), sb.get("tlsh"))
    tlsh_sim = max(0.0, 1.0 - (dist / 300.0)) if dist is not None else 0.0
    return _verdict(overlap, containment, api_sim, tlsh_sim, dist,
                    shared, "source")


def _compare_bytecode(a, b):
    class_overlap, containment, shared = _layer_overlap(a, b, "class_digests")
    api_sim = _api_similarity(a, b)
    dist = tlsh_distance(a.get("opcode_tlsh"), b.get("opcode_tlsh"))
    tlsh_sim = max(0.0, 1.0 - (dist / 300.0)) if dist is not None else 0.0
    return _verdict(class_overlap, containment, api_sim, tlsh_sim, dist,
                    shared, "bytecode")


def _verdict(class_overlap, containment, api_sim, tlsh_sim, dist, shared, half):
    score = (0.60 * max(class_overlap, containment * 0.9)
             + 0.25 * api_sim
             + 0.15 * tlsh_sim)
    if class_overlap >= 0.85:
        verdict = "same build or trivial repack"
    elif containment >= 0.80:
        verdict = "one contains the other"
    elif class_overlap >= 0.40 or (api_sim >= 0.80 and tlsh_sim >= 0.60):
        verdict = "same family, modified"
    elif score >= 0.35:
        verdict = "possibly related"
    else:
        verdict = "unrelated"
    return {
        "score": round(score, 4),
        "verdict": verdict,
        "class_overlap": round(class_overlap, 4),
        "containment": round(containment, 4),
        "api_similarity": round(api_sim, 4),
        "opcode_tlsh_distance": dist,
        "shared_classes": shared,
        "matched_on": half,
    }



# ==========================================================================
# Fuzzy matching: sets, flags, rapid classification, shareable artifacts
# ==========================================================================
#
# This replaces the rule-based approach entirely. Tested against a real corpus
# of Minecraft mod malware, public YARA feeds produced scoring hits on 1 of 9
# malicious samples (11% recall) while the code fingerprint linked families
# across package renaming AND full recompilation, where zero class files were
# byte-identical. Rules stay useful for the wider malware world; for this
# ecosystem specifically, nobody has written them.
#
# THREE SETS, not two:
#   goodware  known safe. A match here is evidence FOR the sample.
#   badware   not malicious, but not safe practice either: cleartext HTTP
#             update channels, unsigned self-updaters, sloppy permissions.
#             This set exists because "not malware" and "fine to run" are
#             different questions and collapsing them loses the answer to
#             the second one.
#   malware   actively malicious.
#
# RAPID CLASSIFICATION:
#   Matching runs against the raw jar before the decompiler is invoked, so a
#   known family is named in well under a second while the slow path is still
#   starting a JVM. The guess is explicitly a guess: it reports confidence and
#   what it matched on, and it never replaces the full analysis.

FUZZY_DIR_DEFAULT = os.path.join(os.path.expanduser("~"), ".rho9", "fuzzy")
FUZZY_DB_DEFAULT = os.path.join(os.path.expanduser("~"), ".rho9", "fuzzy.sqlite3")
FUZZY_SETS = ("goodware", "badware", "malware")
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
# Samples are staged as raw bytes and referenced by id, so a JSON request
# never has to carry the file. Base64 inflates by a third and then has to be
# parsed as one enormous JSON string; a 25 MB jar became a 34 MB body and was
# rejected outright.
STAGE_TTL_SECONDS = 900
MAX_STAGED = 4
_STAGED = {}
_STAGE_LOCK = threading.Lock()


def stage_sample(data, filename):
    """Hold an uploaded sample briefly so a follow-up JSON call can reference
    it by id. Bounded and time-limited: this is a transfer buffer, not
    storage, and it never outlives the process."""
    now = time.time()
    with _STAGE_LOCK:
        for k in [k for k, v in _STAGED.items() if now - v["at"] > STAGE_TTL_SECONDS]:
            _STAGED.pop(k, None)
        while len(_STAGED) >= MAX_STAGED:
            oldest = min(_STAGED, key=lambda k: _STAGED[k]["at"])
            _STAGED.pop(oldest, None)
        sid = uuid.uuid4().hex
        _STAGED[sid] = {"data": data, "filename": filename, "at": now}
    return sid


def take_staged(stage_id):
    with _STAGE_LOCK:
        entry = _STAGED.get(stage_id)
    if not entry:
        return None, None
    if time.time() - entry["at"] > STAGE_TTL_SECONDS:
        with _STAGE_LOCK:
            _STAGED.pop(stage_id, None)
        return None, None
    return entry["data"], entry["filename"]
MAX_PACK_BYTES = 64 * 1024 * 1024
MAX_PACK_ENTRIES = 20000

# --------------------------------------------------------------------------
# Flag codebook
#
# Compact by design: a stored or shared classification is a small integer
# array, not prose. First element is the classification, the rest are tag
# numbers. The wire form is a string so the grouping survives JSON without
# being summed: "3:5+9+23" reads as malware, remote loader + dropper logic +
# stealer.
#
# Tags 1-21 mirror the SIGS families the static analyser already produces, in
# its own order, so every existing flag has a number and nothing the UI can
# raise is unrepresentable here. Tags 22+ are analyst-level classifications
# that describe behaviour rather than a specific campaign.
# --------------------------------------------------------------------------

FUZZY_CLASSES = {
    0: "unknown",
    1: "goodware",
    2: "badware",
    3: "malware",
}

FUZZY_TAGS = {
    # --- 1-21: existing SIGS families from the static analyser ---
    1: "fractureiser",
    2: "bleedingPipe",
    3: "xrat",
    4: "eralauncher",
    5: "downloadLogic",
    6: "networkComms",
    7: "filesystem",
    8: "classpathInjection",
    9: "remoteLoader",
    10: "stargazersBaikal",
    11: "weedhack",
    12: "tokenTheft",
    13: "cryptoWallet",
    14: "browserCreds",
    15: "vpnCreds",
    16: "sbftLogger",
    17: "msftAccountTheft",
    18: "launcherCredFiles",
    19: "browserAppBoundBypass",
    20: "skidfuscator",
    21: "obfuscatorHeuristic",
    # --- 22+: behaviour classifications ---
    22: "stealer",
    23: "dropper",
    24: "rat",
    25: "keylogger",
    26: "miner",
    27: "ransomware",
    28: "backdoor",
    29: "clipper",
    30: "c2",
    31: "persistence",
    32: "packed",
    33: "nestedPayload",
    34: "insecureTransport",
    35: "unsignedUpdater",
    36: "telemetry",
    37: "adware",
    38: "griefing",
    39: "cheatClient",
    40: "clean",
    41: "falsePositive",
    42: "needsReview",
    43: "zipBomb",
    44: "parserBomb",
    45: "malformedArchive",
    46: "encryptedArchive",
}

FUZZY_TAG_IDS = {v: k for k, v in FUZZY_TAGS.items()}


def fuzzy_encode_flags(classification, tags):
    """(3, ['remoteLoader','stealer']) -> '3:9+22'."""
    try:
        cls_id = int(classification)
    except (TypeError, ValueError):
        cls_id = FUZZY_TAG_IDS.get(classification, 0)
        cls_id = {"unknown": 0, "goodware": 1, "badware": 2,
                  "malware": 3}.get(str(classification).lower(), 0)
    ids = []
    for t in tags or ():
        if isinstance(t, int):
            if t in FUZZY_TAGS:
                ids.append(t)
        elif t in FUZZY_TAG_IDS:
            ids.append(FUZZY_TAG_IDS[t])
    ids = sorted(set(ids))
    return "%d:%s" % (cls_id, "+".join(str(i) for i in ids)) if ids else "%d:" % cls_id


def fuzzy_decode_flags(code):
    """'3:9+22' -> {classification, classification_id, tags, tag_ids}."""
    cls_id, _sep, tail = str(code or "0:").partition(":")
    try:
        cls_id = int(cls_id)
    except ValueError:
        cls_id = 0
    ids = []
    for part in tail.split("+"):
        part = part.strip()
        if part.isdigit() and int(part) in FUZZY_TAGS:
            ids.append(int(part))
    return {
        "classification_id": cls_id,
        "classification": FUZZY_CLASSES.get(cls_id, "unknown"),
        "tag_ids": sorted(set(ids)),
        "tags": [FUZZY_TAGS[i] for i in sorted(set(ids))],
    }


# --------------------------------------------------------------------------
# ssdeep-style hashing for the report artifact
#
# ppdeep is a pure-Python ssdeep implementation, so it adds no build
# dependency. It is used for the optional report hash rather than for the
# code fingerprint, because context-triggered piecewise hashing works well on
# text and badly on compressed archives.
# --------------------------------------------------------------------------

try:
    import ppdeep as _ppdeep
except ImportError:
    _ppdeep = None
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--user",
                        "--break-system-packages", "ppdeep"],
                       check=True, timeout=180,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import ppdeep as _ppdeep
    except Exception:
        _ppdeep = None


def report_fuzzy_hash(report_obj):
    """Fuzzy hash of a canonicalised JSON report.

    Two samples whose reports are structurally similar produce similar
    hashes, which makes this useful for clustering findings and for spotting
    a resubmission of the same analysis.

    One honest limit, since the intent behind this was partial recoverability:
    you cannot read classification back out of an ssdeep or TLSH digest. The
    digest is a rolling-hash summary, not an encoding. That is why the
    classification travels beside it as the compact flag code, which IS
    exact and IS readable. The hash tells you two reports resemble each
    other; the code tells you what the verdict was.
    """
    canonical = json.dumps(report_obj, sort_keys=True, separators=(",", ":"))
    data = canonical.encode("utf-8")
    out = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if _ppdeep is not None:
        try:
            out["ssdeep"] = _ppdeep.hash(data)
        except Exception:
            out["ssdeep"] = None
    else:
        out["ssdeep"] = None
    out["tlsh"] = tlsh_hash(data)
    return out


def report_hash_similarity(a, b):
    if not a or not b:
        return 0.0
    if _ppdeep is not None and a.get("ssdeep") and b.get("ssdeep"):
        try:
            return _ppdeep.compare(a["ssdeep"], b["ssdeep"]) / 100.0
        except Exception:
            pass
    dist = tlsh_distance(a.get("tlsh"), b.get("tlsh"))
    return max(0.0, 1.0 - (dist / 300.0)) if dist is not None else 0.0


_RE_ARTIFACT_VERSION = re.compile(r"[-_]v?\d[\w.+]*$")


def normalise_layer_name(path):
    """'META-INF/jars/fabric-api-base-2.0.4+ece06323ef.jar' -> 'fabric-api-base'.

    Version-stripping matters because byte-identity is not enough on its own:
    two mods bundling DIFFERENT versions of the same library still share most
    of their classes. Measured on real builds, ModMenu 21 matched ModMenu 20 at
    1.000 through a bundled fabric-api-base, and Iris matched ModMenu at 0.423
    the same way. Both are library overlap, neither is authorship.
    """
    base = os.path.basename(path or "").lower()
    for ext in (".jar", ".zip"):
        if base.endswith(ext):
            base = base[:-len(ext)]
    prev = None
    while prev != base:
        prev = base
        base = _RE_ARTIFACT_VERSION.sub("", base)
    return base


def compare_nested(a, b, suppress=(), suppress_names=()):
    """Best match between any embedded jar on either side, and the outer
    archives. A dropper hiding its payload inside an otherwise ordinary mod
    shares almost nothing at the outer layer and everything one level down.

    Shared dependencies are excluded, and that exclusion is the whole
    difficulty. Two unrelated mods that both bundle commons-logging via
    Fabric jar-in-jar have a byte-identical embedded layer, which naively
    scores as a perfect match: measured on real samples, that produced a
    1.000 "embedded payload matches" between two jars whose actual shared
    code was a fifth of that. Two rules keep it honest:

      - byte-identical layers (same sha256 on both sides) are a shared
        DEPENDENCY, not shared authorship. Bundling the same library proves
        nothing. A repacked or recompiled payload has a different sha256 and
        is still compared normally, which is exactly the case worth catching.
      - layers the caller has flagged as ubiquitous (seen inside two or more
        separately filed samples) are skipped outright.
    """
    best = None
    def layers(sig):
        out = [("<outer>", sig, None, "class_digests")]
        for n in sig.get("nested") or []:
            out.append((n["path"], n, n.get("sha256"), "digests"))
        return out
    for a_path, a_layer, a_sha, a_key in layers(a):
        if a_sha and a_sha in suppress:
            continue
        a_name = normalise_layer_name(a_path) if a_path != "<outer>" else None
        if a_name and a_name in suppress_names:
            continue
        for b_path, b_layer, b_sha, b_key in layers(b):
            if b_sha and b_sha in suppress:
                continue
            b_name = normalise_layer_name(b_path) if b_path != "<outer>" else None
            if b_name and b_name in suppress_names:
                continue
            if a_name and b_name and a_name == b_name:
                # Same library on both sides, whatever the version. Shipping
                # the same dependency is not shared authorship.
                continue
            if a_sha and b_sha and a_sha == b_sha:
                continue          # identical bundled dependency, not evidence
            _j, containment, inter = _layer_overlap(a_layer, b_layer, a_key)
            if not inter:
                continue
            if best is None or containment > best["containment"]:
                best = {"containment": round(containment, 4),
                        "shared": inter,
                        "left": a_path, "right": b_path,
                        "identical_layer": False}
    return best


class FuzzyStore:
    """Signature database across the three sets, plus classification.

    Persistent and never wiped, like the threat-intel DB. Sample bytes are
    NOT stored for the malware or badware sets unless explicitly enabled:
    this bridge promises that uploaded samples do not outlive the process,
    and a permanent on-disk malware folder would quietly break that.
    """

    def __init__(self, base_dir=FUZZY_DIR_DEFAULT, db_path=FUZZY_DB_DEFAULT,
                 keep_samples=False):
        self.base_dir = base_dir
        self.keep_samples = bool(keep_samples)
        self.sets_dir = {}
        for name in FUZZY_SETS:
            d = os.path.join(base_dir, name)
            os.makedirs(d, exist_ok=True)
            self.sets_dir[name] = d
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS fuzzy ("
                " sha256 TEXT PRIMARY KEY,"
                " filename TEXT,"
                " set_name TEXT NOT NULL,"
                " code TEXT,"
                " family TEXT,"
                " note TEXT,"
                " origin TEXT,"
                " added_at REAL NOT NULL,"
                " sig_json TEXT NOT NULL,"
                " report_hash TEXT"
                ")")
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS fuzzy_set ON fuzzy (set_name)")
            self.conn.commit()

    def close(self):
        try:
            self.conn.commit()
            self.conn.close()
        except Exception:
            pass

    # ---------------- storage ----------------

    def add(self, sig, set_name, code="0:", family="", note="",
            origin="local", report_hash=None, sample_bytes=None):
        if set_name not in FUZZY_SETS:
            raise ValueError("set must be one of: %s" % ", ".join(FUZZY_SETS))
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO fuzzy "
                "(sha256, filename, set_name, code, family, note, origin,"
                " added_at, sig_json, report_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (sig["sha256"], sig.get("filename", ""), set_name, code,
                 family, note, origin, time.time(),
                 json.dumps(sig, separators=(",", ":")),
                 json.dumps(report_hash) if report_hash else None))
            self.conn.commit()
        stored = False
        # Goodware is harmless to keep and useful to re-fingerprint later.
        # The other two sets need an explicit opt-in, see the class docstring.
        if sample_bytes and (set_name == "goodware" or self.keep_samples):
            try:
                target = os.path.join(self.sets_dir[set_name],
                                      sanitize_filename(sig.get("filename") or
                                                        (sig["sha256"][:16] + ".jar")))
                with open(target, "wb") as f:
                    f.write(sample_bytes)
                stored = True
            except Exception as e:
                log("fuzzy: could not store sample: %s" % e)
        return {"added": True, "sha256": sig["sha256"], "set": set_name,
                "code": code, "flags": fuzzy_decode_flags(code),
                "sample_stored": stored, "counts": self.counts()}

    def remove(self, sha256):
        with self.lock:
            cur = self.conn.execute("DELETE FROM fuzzy WHERE sha256 = ?", (sha256,))
            self.conn.commit()
        return {"deleted": cur.rowcount, "counts": self.counts()}

    def rows(self, set_name=None):
        with self.lock:
            if set_name:
                cur = self.conn.execute(
                    "SELECT sha256, filename, set_name, code, family, note,"
                    " origin, added_at, sig_json, report_hash FROM fuzzy"
                    " WHERE set_name = ?", (set_name,))
            else:
                cur = self.conn.execute(
                    "SELECT sha256, filename, set_name, code, family, note,"
                    " origin, added_at, sig_json, report_hash FROM fuzzy")
            return cur.fetchall()

    def entries(self, set_name=None):
        out = []
        for r in self.rows(set_name):
            try:
                sig = json.loads(r[8])
            except Exception:
                continue
            out.append({
                "sha256": r[0], "filename": r[1], "set": r[2], "code": r[3],
                "family": r[4], "note": r[5], "origin": r[6], "added_at": r[7],
                "signature": sig,
                "report_hash": json.loads(r[9]) if r[9] else None,
            })
        return out

    def listing(self):
        return [{k: v for k, v in e.items() if k != "signature"} |
                {"classes": e["signature"].get("classes_parsed"),
                 "nested": e["signature"].get("nested_count", 0),
                 "flags": fuzzy_decode_flags(e["code"])}
                for e in self.entries()]

    def counts(self):
        with self.lock:
            cur = self.conn.execute(
                "SELECT set_name, COUNT(*) FROM fuzzy GROUP BY set_name")
            by = dict(cur.fetchall())
        out = {s: by.get(s, 0) for s in FUZZY_SETS}
        out["total"] = sum(out.values())
        return out

    def status(self):
        return {
            "engine": "rho9-jar-fuzzy v%d" % SIGNATURE_VERSION,
            "tlsh": _tlsh is not None,
            "ssdeep": _ppdeep is not None,
            "db": self.db_path,
            "dir": self.base_dir,
            "sets": list(FUZZY_SETS),
            "counts": self.counts(),
            "keep_samples": self.keep_samples,
            "classifications": FUZZY_CLASSES,
            "tags": FUZZY_TAGS,
            "samples_on_disk": {s: len(self._files(s)) for s in FUZZY_SETS},
        }

    def _files(self, set_name):
        try:
            return [n for n in sorted(os.listdir(self.sets_dir[set_name]))
                    if n.lower().endswith((".jar", ".zip", ".class"))]
        except Exception:
            return []

    # ---------------- matching and classification ----------------

    def common_layers(self):
        """Embedded jars that are shared dependencies rather than payloads.

        Returns (sha256 set, normalised-name set). An embedded jar seen inside
        two or more separately filed samples is a library by definition, and
        matching on it is matching on Maven, not on malware. Tracked by name
        as well as hash so a version bump does not sneak the same library
        back in. Self-tuning: the more the operator files, the better it gets.
        """
        by_sha, by_name = {}, {}
        for e in self.entries():
            for n in (e["signature"].get("nested") or []):
                if n.get("sha256"):
                    by_sha.setdefault(n["sha256"], set()).add(e["sha256"])
                name = normalise_layer_name(n.get("path"))
                if name:
                    by_name.setdefault(name, set()).add(e["sha256"])
        return ({sha for sha, o in by_sha.items() if len(o) >= 2},
                {nm for nm, o in by_name.items() if len(o) >= 2})

    def match(self, sig, limit=10, min_score=0.15):
        results = []
        suppress, suppress_names = self.common_layers()
        auto = sig.get("auto_classification")
        for e in self.entries():
            other = e["signature"]
            if other.get("sha256") == sig.get("sha256"):
                continue
            cmp_result = compare(sig, other)
            nested_best = compare_nested(sig, other, suppress=suppress,
                                         suppress_names=suppress_names)
            if nested_best and nested_best["containment"] > cmp_result["containment"]:
                # A payload buried inside an otherwise ordinary archive is the
                # case the outer comparison is worst at, so let the deepest
                # matching layer speak when it has more to say.
                cmp_result["containment"] = nested_best["containment"]
                cmp_result["nested_match"] = nested_best
                cmp_result["score"] = round(min(1.0, cmp_result["score"] +
                                                0.45 * nested_best["containment"]), 4)
                if nested_best["containment"] >= 0.80:
                    cmp_result["verdict"] = "embedded payload matches"
            if cmp_result["score"] < min_score:
                continue
            cmp_result.update({
                "sha256": other.get("sha256"),
                "filename": e["filename"] or other.get("filename"),
                "set": e["set"], "code": e["code"], "family": e["family"],
                "flags": fuzzy_decode_flags(e["code"]),
                "origin": e["origin"],
            })
            results.append(cmp_result)
        results.sort(key=lambda r: -r["score"])
        by_set = {s: [r for r in results if r["set"] == s] for s in FUZZY_SETS}
        guess = self.classify(results)
        modifier = self._modifier(by_set)
        if auto:
            # An archive that cannot be parsed because it is built to break
            # parsers is a finding in itself, and it does not need a neighbour
            # in the corpus to say so.
            guess = {
                "classification": FUZZY_CLASSES.get(auto["classification"], "malware"),
                "classification_id": auto["classification"],
                "confidence": 0.9,
                "tags": list(auto["tags"]),
                "code": auto["code"],
                "basis": guess.get("basis", []),
                "provisional": True,
                "reason": auto["reason"],
                "from_bomb": True,
            }
            modifier = max(modifier, 35)
        return {
            "matches": results[:limit],
            "best": {s: (by_set[s][0] if by_set[s] else None) for s in FUZZY_SETS},
            "guess": guess,
            "bomb": sig.get("bomb"),
            "score_modifier": modifier,
            "compared_against": self.counts()["total"],
        }

    @staticmethod
    def classify(results):
        """Rapid guess, from the neighbours alone.

        Runs on the raw jar before decompilation, so an analyst gets a
        provisional family name in milliseconds while the JVM is still
        starting. Weighted vote: each neighbour contributes its similarity
        score to its own classification and to each of its tags.
        """
        # Only real neighbours get a vote. Letting "unrelated" hits at 0.15
        # cast ballots made a known-good Sodium build come back as badware
        # off a single 0.154 match, which is worse than saying nothing.
        #
        # The filter is the VERDICT, not a raw score cutoff. An earlier extra
        # requirement of score >= 0.35 meant a cross-decompiler source match
        # scoring 0.331 with verdict "same family, modified" moved the threat
        # score by +28 while the triage panel still said "unknown". The two
        # must never disagree: if it is good enough to move the score, it is
        # good enough to name.
        results = [r for r in results if r["verdict"] != "unrelated"]
        if not results:
            return {"classification": "unknown", "classification_id": 0,
                    "confidence": 0.0, "tags": [], "basis": [], "code": "0:",
                    "provisional": True,
                    "reason": "nothing in the sets resembles this sample"}
        class_votes = {}
        tag_votes = {}
        basis = []
        for r in results[:8]:
            weight = float(r["score"])
            flags = r.get("flags") or fuzzy_decode_flags(r.get("code"))
            # An entry with no explicit classification still votes via the set
            # it was filed under, which is the more reliable signal anyway.
            cls_id = flags["classification_id"] or {
                "goodware": 1, "badware": 2, "malware": 3}.get(r["set"], 0)
            class_votes[cls_id] = class_votes.get(cls_id, 0.0) + weight
            for t in flags["tags"]:
                tag_votes[t] = tag_votes.get(t, 0.0) + weight
            basis.append({"filename": r.get("filename"), "set": r["set"],
                          "score": r["score"], "verdict": r["verdict"]})
        best_id = max(class_votes, key=class_votes.get)
        total = sum(class_votes.values()) or 1.0
        confidence = class_votes[best_id] / total
        # Confidence is share-of-vote scaled by how strong the top match is.
        # Ten weak neighbours agreeing is not the same as one near-identical
        # hit, and reporting both as "100%" would be a lie.
        confidence *= min(1.0, results[0]["score"] / 0.6)
        tags = sorted(tag_votes, key=tag_votes.get, reverse=True)[:6]
        return {
            "classification": FUZZY_CLASSES.get(best_id, "unknown"),
            "classification_id": best_id,
            "confidence": round(min(1.0, confidence), 3),
            "tags": tags,
            "code": fuzzy_encode_flags(best_id, tags),
            "basis": basis[:5],
            "provisional": True,
        }

    @staticmethod
    def _modifier(by_set):
        add = 0.0
        mal = by_set.get("malware") or []
        bad = by_set.get("badware") or []
        good = by_set.get("goodware") or []
        if mal:
            v = mal[0]["verdict"]
            if v in ("same build or trivial repack", "embedded payload matches"):
                add = 40.0
            elif v in ("one contains the other", "same family, modified"):
                add = 28.0
            elif v == "possibly related":
                add = 12.0
        if bad and add < 15:
            v = bad[0]["verdict"]
            if v in ("same build or trivial repack", "one contains the other"):
                add = max(add, 12.0)
        if good:
            v = good[0]["verdict"]
            if v == "same build or trivial repack":
                add -= 20.0
            elif v == "same family, modified":
                add -= 8.0
        return int(round(max(-20.0, min(45.0, add))))

    # ---------------- artifacts ----------------

    def build_artifact(self, jar_bytes, filename, classification=0, tags=(),
                       family="", note="", report=None, source_zip=None,
                       password=None):
        """The shareable JSON document produced when an analyst hashes a sample.

        Contains the code fingerprint, the compact flag code, and optionally a
        fuzzy hash of the analyst's JSON report. Inert and compact, so it moves
        detection between people without moving an executable. Not anonymised:
        anyone holding a candidate sample can confirm a match against it.
        """
        sig = build_signature(jar_bytes, filename=filename, family=family,
                              source_zip=source_zip, password=password)
        code = fuzzy_encode_flags(classification, tags)
        artifact = {
            "kind": "rho9-fuzzy-artifact",
            "artifact_version": 1,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "generator": "rho9-modforensics-bridge %s" % SERVER_VERSION,
            "filename": filename,
            "sha256": sig["sha256"],
            "code": code,
            "flags": fuzzy_decode_flags(code),
            "family": family,
            "note": note,
            "signature": sig,
        }
        if report is not None:
            artifact["report_hash"] = report_fuzzy_hash(report)
        artifact["self_hash"] = signature_self_hash(artifact)
        return artifact

    def import_artifact(self, artifact, set_name=None, origin="imported"):
        if not isinstance(artifact, dict):
            raise ValueError("not a JSON object")
        if artifact.get("kind") == "rho9-fuzzy-artifact":
            if artifact.get("self_hash") != signature_self_hash(artifact):
                raise ValueError("self hash mismatch, artifact was altered")
            sig = artifact.get("signature")
            code = artifact.get("code") or "0:"
            report_hash = artifact.get("report_hash")
            family = artifact.get("family") or ""
            note = artifact.get("note") or ""
        elif artifact.get("kind") == "rho9-jar-signature":
            ok, why = verify_signature(artifact)
            if not ok:
                raise ValueError(why)
            sig, code, report_hash = artifact, "0:", None
            family = artifact.get("family") or ""
            note = ""
        else:
            raise ValueError("unrecognised document (expected a Rho-9 fuzzy "
                             "artifact or jar signature)")
        if not sig:
            raise ValueError("artifact carries no signature")
        flags = fuzzy_decode_flags(code)
        target = set_name or {1: "goodware", 2: "badware",
                              3: "malware"}.get(flags["classification_id"])
        if target not in FUZZY_SETS:
            raise ValueError("no set given and the artifact carries no "
                             "classification, so there is nowhere to file it")
        return self.add(sig, target, code=code, family=family, note=note,
                        origin=origin, report_hash=report_hash)

    def import_pack(self, zip_bytes, set_name=None):
        """Bulk import: a .zip of artifact/signature .json documents.

        Broken members are reported individually rather than failing the whole
        pack, because a 200-file pack with one bad document is still 199
        useful signatures.
        """
        accepted, rejected = [], []
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                infos = zf.infolist()
                if len(infos) > MAX_PACK_ENTRIES:
                    raise ValueError("archive has too many entries")
                for info in infos:
                    if info.is_dir() or not info.filename.lower().endswith(".json"):
                        continue
                    if info.file_size > MAX_ARTIFACT_BYTES:
                        rejected.append({"file": info.filename,
                                         "error": "document too large"})
                        continue
                    try:
                        doc = json.loads(zf.read(info).decode("utf-8", "replace"))
                        r = self.import_artifact(doc, set_name=set_name)
                        accepted.append({"file": info.filename,
                                         "sha256": r["sha256"], "set": r["set"]})
                    except Exception as e:
                        rejected.append({"file": info.filename,
                                         "error": str(e)[:200]})
        except zipfile.BadZipFile:
            raise ValueError("not a readable .zip archive")
        if not accepted:
            raise ValueError("no importable documents found (%d rejected)"
                             % len(rejected))
        return {"accepted": accepted, "rejected": rejected,
                "counts": self.counts()}

    def export_pack(self, set_name=None):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for e in self.entries(set_name):
                doc = {
                    "kind": "rho9-fuzzy-artifact",
                    "artifact_version": 1,
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                  time.gmtime(e["added_at"])),
                    "generator": "rho9-modforensics-bridge %s" % SERVER_VERSION,
                    "filename": e["filename"],
                    "sha256": e["sha256"],
                    "code": e["code"],
                    "flags": fuzzy_decode_flags(e["code"]),
                    "family": e["family"],
                    "note": e["note"],
                    "signature": e["signature"],
                }
                if e["report_hash"]:
                    doc["report_hash"] = e["report_hash"]
                doc["self_hash"] = signature_self_hash(doc)
                zf.writestr("%s_%s.json" % (e["set"], e["sha256"][:16]),
                            json.dumps(doc, separators=(",", ":")))
        return buf.getvalue()

    def test_entry(self, sig, expected_set, code="0:"):
        """Sanity-check a signature before filing it.

        Answers two questions the analyst actually has: does this look like
        anything already filed under the same set (corroboration), and does it
        collide with the goodware set (which would make it a false positive
        generator).
        """
        res = self.match(sig, limit=10, min_score=0.10)
        # An exact duplicate never shows up in match() because self-matches are
        # excluded by hash, so filing a sample that is ALREADY in goodware as
        # malware would sail through the collision check. Look it up directly.
        conflict = None
        for e in self.entries():
            if e["sha256"] == sig.get("sha256") and e["set"] != expected_set:
                conflict = {"sha256": e["sha256"], "filename": e["filename"],
                            "already_in": e["set"], "code": e["code"]}
                break
        same = [m for m in res["matches"] if m["set"] == expected_set]
        clashes = [m for m in res["matches"]
                   if m["set"] == "goodware" and expected_set != "goodware"
                   and m["score"] >= 0.40]
        return {
            "expected_set": expected_set,
            "code": code,
            "flags": fuzzy_decode_flags(code),
            "corroborating": same[:5],
            "goodware_collisions": clashes[:5],
            "duplicate_conflict": conflict,
            "safe_to_file": (not clashes) and conflict is None,
            "guess": res["guess"],
        }

    def rebuild_from_disk(self):
        done = {s: 0 for s in FUZZY_SETS}
        errors = []
        for s in FUZZY_SETS:
            for name in self._files(s):
                path = os.path.join(self.sets_dir[s], name)
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    sig = build_signature(data, filename=name)
                    self.add(sig, s, origin="local")
                    done[s] += 1
                except Exception as e:
                    errors.append("%s: %s" % (name, str(e)[:120]))
        return {"rebuilt": done, "errors": errors, "counts": self.counts()}


def _load_json_list(s):
    if not s:
        return []
    try:
        v = json.loads(s)
        return v if isinstance(v, list) else []
    except Exception:
        return []


# ==========================================================================
# Discord / OSINT helpers -- webhook attribution, CDN ingestion, abuse reports.
# Every outbound request here is tightly constrained: the webhook and CDN
# helpers only ever talk to Discord hostnames, redirect targets are re-validated
# against the same allowlist (no open-redirect / SSRF pivot), response sizes are
# capped, and filenames are sanitised before anything is returned to the browser.
# ==========================================================================

DISCORD_WEBHOOK_RE = re.compile(
    r"^https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api(?:/v\d+)?/webhooks/(\d+)/([A-Za-z0-9_.-]+)$"
)
DISCORD_API_HOSTS = ("discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com")
DISCORD_CDN_HOSTS = ("cdn.discordapp.com", "media.discordapp.net", "cdn.discordapp.net")
DISCORD_CDN_EXTS = (".zip", ".jar", ".litemod", ".mrpack", ".class")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)


def _sanitize_filename(name, fallback="discord_download.bin"):
    name = (name or "").split("/")[-1].split("\\")[-1].strip()
    name = _SAFE_NAME_RE.sub("_", name)
    name = name.strip("._") or fallback
    return name[:120]


def _constrained_get(url, timeout=8, max_bytes=None, allowed_hosts=None):
    """HTTP GET with a host allowlist enforced on the initial URL AND on every
    redirect hop (blocks open-redirect / SSRF pivots), plus a hard size cap.
    Returns (status, headers_dict, body_bytes)."""
    host = urllib.parse.urlparse(url).hostname or ""
    if allowed_hosts is not None and host not in allowed_hosts:
        raise ValueError("host not allowed: %s" % (host or "(none)"))

    class _Restricted(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            nh = urllib.parse.urlparse(newurl).hostname or ""
            if allowed_hosts is not None and nh not in allowed_hosts:
                raise urllib.error.HTTPError(
                    newurl, code, "redirect to disallowed host %s" % nh, hdrs, fp)
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)

    opener = urllib.request.build_opener(_Restricted)
    req = urllib.request.Request(url, headers={
        "User-Agent": "Rho9-ModForensics/%s (+https://modforensics.rho-9.com)" % SERVER_VERSION,
        "Accept": "*/*",
    })
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        # Read the (bounded) error body so callers can inspect 404/401 payloads.
        body = e.read(max_bytes + 1 if max_bytes else 65536)
        return e.code, dict(e.headers.items() if e.headers else {}), body
    with resp:
        status = getattr(resp, "status", 200)
        headers = dict(resp.headers.items())
        if max_bytes:
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ValueError("response exceeds size cap (%d bytes)" % max_bytes)
        else:
            body = resp.read()
    return status, headers, body


def fetch_webhook_info(url, timeout=8):
    """GET a Discord webhook by URL+token. Discord does NOT return the creating
    user object for token-authenticated reads, so 'who created it' is captured by
    the stable guild_id / channel_id / name fields -- these persist across every
    webhook an operator makes in that server, which is exactly the cross-sample
    attribution signal we want."""
    m = DISCORD_WEBHOOK_RE.match(url or "")
    if not m:
        return {"ok": False, "error": "not a recognised Discord webhook URL"}
    try:
        status, _, body = _constrained_get(url, timeout=timeout, max_bytes=64 * 1024,
                                           allowed_hosts=DISCORD_API_HOSTS)
    except Exception as e:
        return {"ok": False, "error": "fetch failed: %s" % e, "webhook_id": m.group(1)}
    try:
        d = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return {"ok": False, "status": status, "error": "non-JSON response from Discord",
                "webhook_id": m.group(1)}
    alive = status == 200 and isinstance(d, dict) and "id" in d
    return {
        "ok": True, "status": status, "alive": alive,
        "value": url,
        "webhook_id": (d.get("id") if isinstance(d, dict) else None) or m.group(1),
        "name": d.get("name") if isinstance(d, dict) else None,
        "channel_id": d.get("channel_id") if isinstance(d, dict) else None,
        "guild_id": d.get("guild_id") if isinstance(d, dict) else None,
        "type": d.get("type") if isinstance(d, dict) else None,
        "avatar": d.get("avatar") if isinstance(d, dict) else None,
        "application_id": d.get("application_id") if isinstance(d, dict) else None,
        "note": ("Discord does not expose the creator user via a webhook token; "
                 "guild_id / channel_id / name are the persistent operator fingerprints "
                 "and are logged so the same server links across multiple webhooks."),
    }


def fetch_discord_cdn(url, timeout=25, max_bytes=None):
    """Download a Minecraft archive from a Discord CDN host ONLY. Strict https +
    host allowlist + extension allowlist + size cap + redirect-host validation +
    sanitised filename. Returns (safe_filename, body_bytes)."""
    if max_bytes is None:
        max_bytes = MAX_UPLOAD_BYTES
    p = urllib.parse.urlparse(url or "")
    if p.scheme != "https" or (p.hostname or "") not in DISCORD_CDN_HOSTS:
        raise ValueError("URL must be an https Discord CDN link (%s)" % ", ".join(DISCORD_CDN_HOSTS))
    lower = (p.path or "").lower()
    if not any(lower.endswith(ext) for ext in DISCORD_CDN_EXTS):
        raise ValueError("filename must end in one of: %s" % ", ".join(DISCORD_CDN_EXTS))
    status, _, body = _constrained_get(url, timeout=timeout, max_bytes=max_bytes,
                                       allowed_hosts=DISCORD_CDN_HOSTS)
    if status != 200:
        raise ValueError("Discord CDN returned HTTP %s" % status)
    name = _sanitize_filename((p.path or "").split("/")[-1])
    if not any(name.lower().endswith(ext) for ext in DISCORD_CDN_EXTS):
        raise ValueError("sanitised filename lost its expected extension")
    return name, body


def _vcard_emails(entity):
    out = []
    va = entity.get("vcardArray") if isinstance(entity, dict) else None
    if isinstance(va, list) and len(va) == 2 and isinstance(va[1], list):
        for field in va[1]:
            if isinstance(field, list) and len(field) >= 4 and field[0] == "email" \
                    and isinstance(field[3], str):
                out.append(field[3])
    return out


def _vcard_fn(entity):
    va = entity.get("vcardArray") if isinstance(entity, dict) else None
    if isinstance(va, list) and len(va) == 2 and isinstance(va[1], list):
        for field in va[1]:
            if isinstance(field, list) and len(field) >= 4 and field[0] == "fn" \
                    and isinstance(field[3], str):
                return field[3]
    return None


def fetch_abuse_contact(target, timeout=10):
    """Best-effort RDAP lookup to surface abuse-contact emails for an IP or
    domain, so filing a hosting/registrar report is easy. Degrades gracefully
    when RDAP is unreachable."""
    target = (target or "").strip().lower()
    if _IPV4_RE.match(target):
        url, kind = "https://rdap.org/ip/%s" % target, "ip"
    elif _DOMAIN_RE.match(target):
        url, kind = "https://rdap.org/domain/%s" % target, "domain"
    else:
        return {"ok": False, "error": "target must be an IPv4 address or a domain"}
    try:
        status, _, body = _constrained_get(url, timeout=timeout, max_bytes=512 * 1024)
        d = json.loads(body.decode("utf-8", "replace"))
    except Exception as e:
        return {"ok": False, "error": "RDAP lookup failed: %s" % e, "target": target, "kind": kind}
    emails, org = [], None

    def walk(entities):
        for ent in entities or []:
            if isinstance(ent, dict):
                if "abuse" in (ent.get("roles") or []):
                    emails.extend(_vcard_emails(ent))
                walk(ent.get("entities"))
    walk(d.get("entities") if isinstance(d, dict) else [])
    for ent in (d.get("entities") if isinstance(d, dict) else []) or []:
        roles = ent.get("roles") or [] if isinstance(ent, dict) else []
        if "registrar" in roles or "registrant" in roles:
            org = _vcard_fn(ent) or org
    seen, uniq = set(), []
    for e in emails:
        if e not in seen:
            seen.add(e); uniq.append(e)
    return {"ok": True, "target": target, "kind": kind, "abuse_emails": uniq,
            "organization": org,
            "rdap_name": (d.get("name") or d.get("ldhName") or d.get("handle")) if isinstance(d, dict) else None}


STORE = None  # set in main()
FUZZY = None  # FuzzyStore, set in main() -- persistent, exempt from all wipes
INTEL = None  # persistent threat-intel store, set in main() -- exempt from all wipes
STATIC_DIR = None  # set in main() -- the "ModForensics" folder holding index.html


def _read_text_safe(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


def _looks_like_modforensics(html_text):
    """Signature check so we never treat an unrelated file that merely happens
    to be named index.html (very possible in a general Downloads folder) as
    something safe to move in and overwrite the app with."""
    if not html_text:
        return False
    return (BRIDGE_PURPOSE in html_text) or ("ModForensics" in html_text and "Rho-9" in html_text)


def _extract_version(html_text):
    if not html_text:
        return None
    m = re.search(r"ModForensics v([0-9]+(?:\.[0-9]+)*)", html_text)
    return m.group(1) if m else None


def setup_static_app():
    """Create <script_dir>/ModForensics if needed, then figure out its actual
    current state before touching anything:
      - already set up with a genuine ModForensics index.html?  what version?
      - is there a candidate at ~/storage/downloads/index.html, and does it
        actually look like ModForensics (not just any file with that name)?
      - if both exist, is the candidate actually different/newer, or is this
        just the same file showing up again?
    Only then decide whether to move something in, skip, or warn -- rather
    than blindly overwriting on every startup."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    app_dir = os.path.join(script_dir, "ModForensics")
    os.makedirs(app_dir, exist_ok=True)

    dest = os.path.join(app_dir, "index.html")
    src = os.path.expanduser("~/storage/downloads/index.html")

    dest_text = _read_text_safe(dest) if os.path.isfile(dest) else None
    dest_ok = _looks_like_modforensics(dest_text)
    dest_version = _extract_version(dest_text) if dest_ok else None

    if os.path.isfile(src):
        src_text = _read_text_safe(src)
        if _looks_like_modforensics(src_text):
            src_version = _extract_version(src_text)
            if dest_ok and dest_version and src_version and dest_version == src_version:
                log("ModForensics v%s already set up in %s -- an identical-version copy "
                    "is also sitting in Downloads; moving it in anyway to clear it out." %
                    (dest_version, app_dir))
            elif dest_ok:
                log("Updating ModForensics %s -> v%s in %s" %
                    ("v" + dest_version if dest_version else "(unknown version)",
                     src_version or "(unknown)", app_dir))
            else:
                log("Setting up ModForensics v%s in %s (first-time setup)" %
                    (src_version or "(unknown version)", app_dir))
            try:
                if os.path.isfile(dest):
                    os.remove(dest)
                shutil.move(src, dest)  # handles cross-filesystem moves (FUSE storage -> home)
                log("Moved %s -> %s" % (src, dest))
                dest_ok, dest_version = True, src_version
            except Exception as e:
                log("Could not move %s into %s: %s" % (src, app_dir, e))
        else:
            log("Found a file at %s but it doesn't look like ModForensics's index.html "
                "(no matching signature) -- leaving it alone and NOT touching %s." % (src, dest))

    if dest_ok:
        log("ModForensics %s is set up and ready to serve from %s" %
            ("v" + dest_version if dest_version else "(version unknown)", app_dir))
    else:
        log("No ModForensics index.html set up yet in %s. Download it to "
            "~/storage/downloads/index.html and restart, or place it directly in "
            "that folder." % app_dir)

    return app_dir


_STATIC_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8",
    ".js": "application/javascript", ".css": "text/css",
    ".json": "application/json", ".png": "image/png",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml", ".ico": "image/x-icon",
}


# ==========================================================================
# Decompilation
# ==========================================================================

class DecompileError(Exception):
    pass


# A single classfile this large is not real code. Legitimate classes run to a
# few KB; the biggest class in a bundled JNA build is around 200 KB. Anything
# far past that is a decompiler-hang vector, the same trick as a decompression
# bomb applied one layer down: the archive itself is unremarkable (0687e5cb
# declares 20 MB uncompressed across 5,483 entries, ratio 2.6x, nothing near
# the 25 MB per-entry guard) while a SINGLE 1.93 MB class hangs the engine.
# That sample timed out at 151s untouched; with this one class held back it
# decompiles in 231s and the rest of its code, a Chrome cookie and Discord
# token stealer, reads normally.
MAX_CLASS_DECOMPILE_BYTES = 1024 * 1024


def prune_decompiler_bombs(input_bytes, cap=MAX_CLASS_DECOMPILE_BYTES):
    """Hold back oversized classfiles before handing the archive to the engine.

    Returns (possibly rewritten bytes, list of skipped entries). Nothing is
    silently dropped: the skipped list travels back to the UI so an analyst
    sees exactly what was withheld and why, and an oversized class is itself
    a finding worth showing rather than a detail to hide.
    """
    skipped = []
    try:
        with zipfile.ZipFile(io.BytesIO(input_bytes)) as zf:
            oversized = [i for i in zf.infolist()
                         if i.filename.lower().endswith(".class")
                         and i.file_size > cap]
            if not oversized:
                return input_bytes, []
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if info in oversized:
                        skipped.append({
                            "path": info.filename,
                            "declared_bytes": info.file_size,
                            "compressed_bytes": info.compress_size,
                            "reason": "classfile exceeds the %d MB decompiler "
                                      "guard and was not decompiled"
                                      % (cap // (1024 * 1024)),
                        })
                        continue
                    try:
                        out.writestr(info.filename, zf.read(info))
                    except Exception:
                        continue
            return buf.getvalue(), skipped
    except zipfile.BadZipFile:
        return input_bytes, []
    except Exception as e:
        log("bomb guard: could not prune input (%s), sending it through as-is" % e)
        return input_bytes, []


def run_decompile(input_bytes, original_filename, timeout_seconds):
    with _state_lock:
        if not _state["ready"]:
            raise DecompileError(_state["setup_message"] or "Decompiler engine not ready.")
        engine = dict(_state["engine"])
        java_path = _state["java_path"]

    ext = ".jar" if original_filename.lower().endswith(".jar") else ".class"
    skipped_entries = []
    if ext == ".jar":
        input_bytes, skipped_entries = prune_decompiler_bombs(input_bytes)
        if skipped_entries:
            log("bomb guard: holding back %d oversized classfile(s): %s"
                % (len(skipped_entries),
                   ", ".join("%s (%.2f MB)" % (s["path"], s["declared_bytes"]/1e6)
                             for s in skipped_entries[:4])))
    work_dir = tempfile.mkdtemp(prefix="rho9_job_")
    try:
        src_path = os.path.join(work_dir, "input" + ext)
        with open(src_path, "wb") as f:
            f.write(input_bytes)

        out_dir = os.path.join(work_dir, "out")
        os.makedirs(out_dir, exist_ok=True)

        cmd = engine["build_cmd"](engine["jar_path"], src_path, out_dir)
        try:
            proc = subprocess.run(
                cmd, cwd=work_dir, capture_output=True, text=True, timeout=timeout_seconds
            )
        except subprocess.TimeoutExpired:
            raise DecompileError(
                "Decompile timed out after %ds (sample may be deliberately hostile "
                "to the decompiler; treat with suspicion)." % timeout_seconds
            )

        # Collect whatever the engine produced, regardless of whether it wrote
        # loose .java files (CFR) or a single jar/zip of them (Vineflower/Fernflower
        # style tools). Either way we hand back one zip.
        produced_archive = None
        loose_files = []
        for root, _dirs, files in os.walk(out_dir):
            for name in files:
                full = os.path.join(root, name)
                if produced_archive is None and name.lower().endswith((".jar", ".zip")):
                    produced_archive = full
                else:
                    loose_files.append(full)

        if produced_archive and not loose_files:
            with open(produced_archive, "rb") as f:
                result_zip_bytes = f.read()
        elif loose_files:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for full in loose_files:
                    arcname = os.path.relpath(full, out_dir)
                    zf.write(full, arcname)
            result_zip_bytes = buf.getvalue()
        else:
            stderr_tail = (proc.stderr or "")[-2000:]
            raise DecompileError(
                "Decompiler produced no output. This can happen with heavily "
                "obfuscated or non-standard bytecode. Engine stderr: %s" % stderr_tail
            )

        if skipped_entries:
            # Fold the manifest into the returned archive so the withheld
            # entries land in the analyst's file tree instead of vanishing.
            # The UI already renders decompression-bomb entries this way; an
            # oversized class is the same category of finding.
            buf = io.BytesIO(result_zip_bytes)
            with zipfile.ZipFile(buf, "a", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("RHO9-SKIPPED-ENTRIES.json",
                            json.dumps({"skipped": skipped_entries,
                                        "guard": "classfile size",
                                        "cap_bytes": MAX_CLASS_DECOMPILE_BYTES},
                                       indent=1))
            result_zip_bytes = buf.getvalue()

        return result_zip_bytes, skipped_entries
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


# ==========================================================================
# HTTP server
# ==========================================================================

MAX_UPLOAD_BYTES = 150 * 1024 * 1024
MAX_SESSION_BYTES = 250 * 1024 * 1024
MAX_INTEL_BYTES = 16 * 1024 * 1024   # intel POSTs are just IOC/metadata JSON, never file bytes
DECOMPILE_TIMEOUT = 90


def sanitize_filename(name):
    name = os.path.basename(name or "upload.jar")
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in name)
    return safe[:100] or "upload.jar"


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Rho9DecompileBridge/" + SERVER_VERSION

    def log_message(self, fmt, *args):
        log(("%s - " + fmt) % ((self.client_address[0],) + args))

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                          "Content-Type, X-Filename, X-Rho9-Purpose, X-Rho9-Set")
        self.send_header("Access-Control-Expose-Headers",
                          "X-Filename, X-Rho9-Job-Id, X-Rho9-Skipped-Entries")
        self.send_header("Access-Control-Max-Age", "600")
        # Private Network Access: Chrome (and increasingly other browsers)
        # require an explicit opt-in before a page can reach a loopback/
        # private-network server, on top of ordinary CORS. This applies not
        # just to https:// pages but also to file:// pages, which Chromium
        # classifies as "public" address space for this check -- so without
        # this header, the browser silently blocks the request before it
        # ever reaches this handler, regardless of Access-Control-Allow-Origin.
        self.send_header("Access-Control-Allow-Private-Network", "true")

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self._write_body(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _write_body(self, data):
        """Write a response body, tolerating a client that has already gone."""
        try:
            self.wfile.write(data)
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return False

    def do_GET(self):
        # Browsers request this on every page load; answering it keeps a 404
        # per visit out of the log.
        if self.path.split("?")[0] == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self._cors()
            self.end_headers()
            return

        if self.path.startswith("/rho9/"):
            self._handle_rho9_get()
            return
        self._serve_static()

    def _serve_static(self):
        if not STATIC_DIR:
            self._send_json({
                "error": "this server is running in API-only mode (--no-page)",
                "hint": "the UI is hosted elsewhere; only /rho9/* endpoints are served here",
            }, status=404)
            return

        req_path = self.path.split("?", 1)[0].split("#", 1)[0]
        rel = "index.html" if req_path in ("", "/") else req_path.lstrip("/")

        static_root = os.path.realpath(STATIC_DIR)
        target = os.path.realpath(os.path.join(static_root, rel))

        # Path-traversal guard: resolved target must stay inside static_root.
        if target != static_root and not target.startswith(static_root + os.sep):
            self._send_json({"error": "forbidden"}, status=403)
            return

        if not os.path.isfile(target):
            if rel == "index.html":
                body = (
                    "<html><body style='font-family:monospace;background:#080a0f;"
                    "color:#ccd6f0;padding:24px;'>"
                    "<h2>ModForensics index.html not found</h2>"
                    "<p>Place it at:</p><pre>%s</pre>"
                    "<p>or download it to <code>~/storage/downloads/index.html</code> "
                    "and restart this server -- it's moved in automatically on startup.</p>"
                    "</body></html>" % target
                ).encode("utf-8")
                self.send_response(404)
                self._cors()
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self._write_body(body)
            else:
                self._send_json({"error": "not found"}, status=404)
            return

        ext = os.path.splitext(target)[1].lower()
        content_type = _STATIC_CONTENT_TYPES.get(ext, "application/octet-stream")
        with open(target, "rb") as f:
            data = f.read()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self._write_body(data)

    def _handle_rho9_get(self):
        if self.path == "/rho9/capabilities":
            with _state_lock:
                caps = {
                    "service": "rho9-decompile-bridge",
                    "purpose": BRIDGE_PURPOSE,
                    "version": SERVER_VERSION,
                    "engine": _state["engine_version"],
                    "ready": _state["ready"],
                    "setup_message": _state["setup_message"],
                    "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
                    "intel": INTEL is not None,
                    "webhook_info": True,
                    "discord_fetch": True,
                    "abuse_contact": True,
                    "fuzzy": FUZZY.status() if FUZZY is not None else {
                        "disabled": True},
                }
            self._send_json(caps)
            return

        if self.path.startswith("/rho9/fuzzy/"):
            self._handle_fuzzy_get()
            return

        if self.path.startswith("/rho9/intel/"):
            self._handle_intel_get()
            return

        if self.path.startswith("/rho9/webhook-info"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            self._send_json(fetch_webhook_info((q.get("url") or [""])[0]))
            return

        if self.path.startswith("/rho9/fetch-discord"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                name, data = fetch_discord_cdn((q.get("url") or [""])[0])
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
                return
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("X-Filename", urllib.parse.quote(name))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self._write_body(data)
            return

        if self.path.startswith("/rho9/abuse-contact"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            self._send_json(fetch_abuse_contact((q.get("target") or [""])[0]))
            return

        if self.path == "/rho9/jobs":
            rows = STORE.list_jobs()
            self._send_json({"jobs": [
                {"id": r[0], "filename": r[1], "created_at": r[2], "status": r[3]}
                for r in rows
            ]})
            return

        if self.path.startswith("/rho9/result/"):
            job_id = self.path.rsplit("/", 1)[-1]
            row = STORE.get_result(job_id)
            if not row:
                self._send_json({"error": "unknown job id"}, status=404)
                return
            output_zip, status, error = row
            if status != "done" or not output_zip:
                self._send_json({"status": status, "error": error}, status=409)
                return
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition",
                              'attachment; filename="%s_decompiled.zip"' % job_id)
            self.send_header("Content-Length", str(len(output_zip)))
            self.end_headers()
            self._write_body(output_zip)
            return

        if self.path == "/rho9/session":
            row = STORE.get_session()
            if not row:
                self._send_json({"error": "no saved session"}, status=404)
                return
            data_bytes, updated_at = row
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Rho9-Session-Updated-At", str(updated_at))
            self.send_header("Content-Length", str(len(data_bytes)))
            self.end_headers()
            self._write_body(data_bytes)
            return

        self._send_json({"error": "not found"}, status=404)

    # ---- threat-intel endpoints -------------------------------------------
    def _handle_intel_get(self):
        if INTEL is None:
            self._send_json({"error": "intel store disabled (--no-intel)"}, status=404)
            return
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        def one(name, default=None):
            v = params.get(name)
            return v[0] if v else default

        try:
            if route == "/rho9/intel/iocs":
                limit = int(one("limit", "2000") or "2000")
                limit = max(1, min(limit, 10000))
                self._send_json(INTEL.list_iocs(
                    limit=limit, type_filter=one("type"), q=one("q")))
                return
            if route == "/rho9/intel/ioc":
                t = one("type")
                v = one("value")
                if not t or not v:
                    self._send_json({"error": "type and value are required"}, status=400)
                    return
                detail = INTEL.ioc_detail(t, v)
                if detail is None:
                    self._send_json({"error": "unknown indicator"}, status=404)
                    return
                self._send_json(detail)
                return
            if route == "/rho9/intel/samples":
                limit = int(one("limit", "1000") or "1000")
                limit = max(1, min(limit, 10000))
                self._send_json(INTEL.list_samples(limit=limit))
                return
            if route == "/rho9/intel/trends":
                self._send_json(INTEL.trends())
                return
        except Exception as e:
            self._send_json({"error": "intel query failed: %s" % e}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    def _handle_intel_record(self):
        if INTEL is None:
            self._send_json({"error": "intel store disabled (--no-intel)"}, status=404)
            return
        purpose = self.headers.get("X-Rho9-Purpose", "")
        if purpose != BRIDGE_PURPOSE:
            self._send_json({"error": "purpose header mismatch"}, status=400)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            self._send_json({"error": "empty body"}, status=400)
            return
        if length > MAX_INTEL_BYTES:
            self._send_json({"error": "intel payload too large"}, status=413)
            return
        data = self.rfile.read(length)
        try:
            payload = json.loads(data.decode("utf-8"))
        except Exception:
            self._send_json({"error": "body is not valid JSON"}, status=400)
            return
        try:
            result = INTEL.record(payload)
        except ValueError as e:
            self._send_json({"error": str(e)}, status=400)
            return
        except Exception as e:
            self._send_json({"error": "intel record failed: %s" % e}, status=500)
            return
        self._send_json(result)

    # ======================================================================
    # Fuzzy matching endpoints
    # ======================================================================

    def _fuzzy_or_404(self):
        if FUZZY is None:
            self._send_json({"error": "fuzzy matching is disabled on this "
                                      "bridge (--no-fuzzy)"}, status=404)
            return None
        return FUZZY

    def _fuzzy_body(self, max_bytes):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > max_bytes:
            self._send_json({"error": "body too large (cap %d bytes)" % max_bytes},
                            status=413)
            return None
        return self.rfile.read(length) if length else b""

    def _fuzzy_json_body(self, max_bytes=None):
        if max_bytes is None:
            # Generous enough that a legacy base64 sample still fits, since
            # base64 costs a third on top of the raw size.
            max_bytes = max(MAX_ARTIFACT_BYTES,
                            (MAX_UPLOAD_BYTES * 4) // 3 + 1024 * 1024)
        raw = self._fuzzy_body(max_bytes)
        if raw is None:
            return None
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json({"error": "body is not valid JSON"}, status=400)
            return None

    def _fuzzy_sample(self, query, payload=None):
        """Resolve the sample: request body, a base64 blob in JSON, or a
        job_id for something already decompiled this session."""
        filename = sanitize_filename(urllib.request.unquote(
            self.headers.get("X-Filename", "sample.jar")))
        data = None
        if payload and payload.get("sample_b64"):
            try:
                data = base64.b64decode(payload["sample_b64"], validate=False)
            except Exception:
                raise ValueError("sample_b64 is not valid base64")
            filename = payload.get("filename") or filename
        stage_id = ((payload or {}).get("stage_id")
                    or (query.get("stage_id") or [""])[0] or "").strip()
        if data is None and stage_id:
            staged, staged_name = take_staged(stage_id)
            if staged is None:
                raise ValueError("staged sample expired or unknown; upload it again")
            data = staged
            if not (payload or {}).get("filename"):
                filename = staged_name or filename
        job_id = ((payload or {}).get("job_id")
                  or (query.get("job_id") or [""])[0] or "").strip()
        source_zip = None
        if job_id:
            if data is None:
                row = STORE.get_input(job_id)
                if row:
                    data = bytes(row[0])
                    filename = row[1]
            # The bridge is already holding the decompiled output for this job,
            # so folding the source half in costs nothing and makes the
            # fingerprint match source-only uploads later.
            res = STORE.get_result(job_id)
            if res and res[0]:
                source_zip = bytes(res[0])
        return filename, data, source_zip

    def _handle_fuzzy_get(self):
        store = self._fuzzy_or_404()
        if store is None:
            return
        route = urllib.parse.urlparse(self.path).path
        if route == "/rho9/fuzzy/status":
            self._send_json(store.status())
            return
        if route == "/rho9/fuzzy/flags":
            # The codebook, so the UI can render premade flags without
            # hardcoding a second copy that drifts out of sync.
            self._send_json({"classifications": FUZZY_CLASSES,
                             "tags": FUZZY_TAGS, "sets": list(FUZZY_SETS)})
            return
        if route == "/rho9/fuzzy/list":
            self._send_json({"entries": store.listing(), "counts": store.counts()})
            return
        if route == "/rho9/fuzzy/export":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            set_name = (q.get("set") or [None])[0]
            try:
                blob = store.export_pack(set_name)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition",
                             'attachment; filename="rho9-fuzzy-%s.zip"'
                             % (set_name or "all"))
            self.send_header("Content-Length", str(len(blob)))
            self._cors()
            self.end_headers()
            self._write_body(blob)
            return
        self._send_json({"error": "not found"}, status=404)

    def _handle_fuzzy_post(self):
        store = self._fuzzy_or_404()
        if store is None:
            return
        if self.headers.get("X-Rho9-Purpose", "") != BRIDGE_PURPOSE:
            self._send_json({"error": "purpose header mismatch"}, status=400)
            return
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # ---- fingerprint and match, with a rapid provisional classification --
        if route in ("/rho9/fuzzy/scan", "/rho9/fuzzy/build"):
            raw = self._fuzzy_body(MAX_UPLOAD_BYTES)
            if raw is None:
                return
            try:
                filename, data, source_zip = self._fuzzy_sample(query)
            except ValueError as e:
                self._send_json({"error": str(e)}, status=400)
                return
            data = raw or data
            if not data:
                self._send_json({"error": "no sample supplied (send the file as "
                                          "the body, or pass ?job_id=)"}, status=400)
                return
            started = time.time()
            try:
                sig = build_signature(data, filename=filename,
                                      source_zip=source_zip,
                                      password=(query.get("password") or [None])[0])
            except ValueError as e:
                self._send_json({"error": str(e)}, status=422)
                return
            except Exception as e:
                self._send_json({"error": "fingerprint failed: %s" % e}, status=500)
                return
            out = {"signature": sig, "filename": filename,
                   "duration_ms": int((time.time() - started) * 1000)}
            if route == "/rho9/fuzzy/scan":
                out.update(store.match(sig))
                out["duration_ms"] = int((time.time() - started) * 1000)
            self._send_json(out)
            return

        # ---- generate the shareable artifact ---------------------------------
        if route == "/rho9/fuzzy/hash":
            payload = self._fuzzy_json_body()
            if payload is None:
                return
            try:
                filename, data, source_zip = self._fuzzy_sample(query, payload)
            except ValueError as e:
                self._send_json({"error": str(e)}, status=400)
                return
            if not data:
                self._send_json({"error": "no sample supplied (pass job_id or "
                                          "sample_b64)"}, status=400)
                return
            try:
                artifact = store.build_artifact(
                    data, filename, source_zip=source_zip,
                    password=payload.get("password"),
                    classification=payload.get("classification", 0),
                    tags=payload.get("tags") or (),
                    family=payload.get("family") or "",
                    note=payload.get("note") or "",
                    report=payload.get("report"))
            except ValueError as e:
                self._send_json({"error": str(e)}, status=422)
                return
            result = {"artifact": artifact}
            if payload.get("file_as"):
                try:
                    result["filed"] = store.import_artifact(
                        artifact, set_name=payload["file_as"], origin="local")
                except ValueError as e:
                    result["file_error"] = str(e)
            self._send_json(result)
            return

        # ---- file a sample into one of the three sets ------------------------
        if route == "/rho9/fuzzy/add":
            raw = self._fuzzy_body(MAX_UPLOAD_BYTES)
            if raw is None:
                return
            set_name = (self.headers.get("X-Rho9-Set")
                        or (query.get("set") or ["malware"])[0])
            filename = sanitize_filename(urllib.request.unquote(
                self.headers.get("X-Filename", "sample.jar")))
            if not raw:
                self._send_json({"error": "empty upload"}, status=400)
                return
            source_zip = None
            job_id = (query.get("job_id") or [""])[0].strip()
            if job_id:
                res = STORE.get_result(job_id)
                if res and res[0]:
                    source_zip = bytes(res[0])
            tags = [t for t in (query.get("tags") or [""])[0].split(",") if t]
            classification = (query.get("classification") or [None])[0]
            if classification is None:
                classification = {"goodware": 1, "badware": 2,
                                  "malware": 3}.get(set_name, 0)
            try:
                sig = build_signature(raw, filename=filename, source_zip=source_zip,
                                      password=(query.get("password") or [None])[0])
                code = fuzzy_encode_flags(classification, tags)
                self._send_json(store.add(
                    sig, set_name, code=code,
                    family=(query.get("family") or [""])[0],
                    note=(query.get("note") or [""])[0],
                    sample_bytes=raw))
            except ValueError as e:
                self._send_json({"error": str(e)}, status=400)
            return

        # ---- import a shared artifact ----------------------------------------
        if route == "/rho9/fuzzy/import":
            payload = self._fuzzy_json_body()
            if payload is None:
                return
            doc = payload.get("artifact") or payload.get("signature") or payload
            try:
                self._send_json(store.import_artifact(
                    doc, set_name=payload.get("set")))
            except ValueError as e:
                self._send_json({"error": str(e)}, status=400)
            return

        # ---- bulk import a pack of artifacts ---------------------------------
        if route == "/rho9/fuzzy/upload":
            raw = self._fuzzy_body(MAX_PACK_BYTES)
            if raw is None:
                return
            if not raw:
                self._send_json({"error": "empty upload"}, status=400)
                return
            set_name = (self.headers.get("X-Rho9-Set")
                        or (query.get("set") or [None])[0])
            try:
                self._send_json(store.import_pack(raw, set_name=set_name))
            except ValueError as e:
                self._send_json({"error": str(e)}, status=400)
            return

        # ---- check a signature before filing it ------------------------------
        if route == "/rho9/fuzzy/test":
            payload = self._fuzzy_json_body()
            if payload is None:
                return
            try:
                filename, data, source_zip = self._fuzzy_sample(query, payload)
            except ValueError as e:
                self._send_json({"error": str(e)}, status=400)
                return
            if not data:
                self._send_json({"error": "no sample supplied"}, status=400)
                return
            try:
                sig = build_signature(data, filename=filename,
                                      source_zip=source_zip,
                                      password=payload.get("password"))
            except ValueError as e:
                self._send_json({"error": str(e)}, status=422)
                return
            code = fuzzy_encode_flags(payload.get("classification", 0),
                                      payload.get("tags") or ())
            self._send_json(store.test_entry(
                sig, payload.get("set") or "malware", code=code))
            return

        if route == "/rho9/fuzzy/stage":
            raw = self._fuzzy_body(MAX_UPLOAD_BYTES)
            if raw is None:
                return
            if not raw:
                self._send_json({"error": "empty upload"}, status=400)
                return
            filename = sanitize_filename(urllib.request.unquote(
                self.headers.get("X-Filename", "sample.jar")))
            self._send_json({"stage_id": stage_sample(raw, filename),
                             "bytes": len(raw), "filename": filename,
                             "expires_in": STAGE_TTL_SECONDS})
            return

        if route == "/rho9/fuzzy/delete":
            payload = self._fuzzy_json_body(64 * 1024)
            if payload is None:
                return
            self._send_json(store.remove(payload.get("sha256") or ""))
            return

        if route == "/rho9/fuzzy/rebuild":
            self._send_json(store.rebuild_from_disk())
            return

        self._send_json({"error": "not found"}, status=404)

    def do_POST(self):
        if self.path == "/rho9/decompile":
            self._handle_decompile()
            return
        if self.path.split("?")[0].startswith("/rho9/fuzzy/"):
            self._handle_fuzzy_post()
            return
        if self.path == "/rho9/intel":
            self._handle_intel_record()
            return
        if self.path == "/rho9/session":
            self._handle_save_session()
            return
        if self.path == "/rho9/session/clear":
            STORE.clear_session()
            self._send_json({"cleared": True})
            return
        if self.path == "/rho9/wipe":
            STORE.purge()
            self._send_json({"wiped": True})
            return
        if self.path == "/rho9/shutdown":
            self._send_json({"shutting_down": True})
            threading.Thread(target=_request_shutdown, daemon=True).start()
            return
        self._send_json({"error": "not found"}, status=404)

    def _handle_save_session(self):
        purpose = self.headers.get("X-Rho9-Purpose", "")
        if purpose != BRIDGE_PURPOSE:
            self._send_json({"error": "purpose header mismatch"}, status=400)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            self._send_json({"error": "empty body"}, status=400)
            return
        if length > MAX_SESSION_BYTES:
            self._send_json({"error": "session too large"}, status=413)
            return
        data = self.rfile.read(length)
        try:
            json.loads(data.decode("utf-8"))  # validate it's actually JSON before storing
        except Exception:
            self._send_json({"error": "body is not valid JSON"}, status=400)
            return
        STORE.save_session(data)
        self._send_json({"saved": True, "bytes": len(data)})

    def _handle_decompile(self):
        purpose = self.headers.get("X-Rho9-Purpose", "")
        if purpose != BRIDGE_PURPOSE:
            self._send_json({"error": "purpose header mismatch"}, status=400)
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            self._send_json({"error": "empty body"}, status=400)
            return
        if length > MAX_UPLOAD_BYTES:
            self._send_json({"error": "file too large"}, status=413)
            return

        filename = sanitize_filename(
            urllib.request.unquote(self.headers.get("X-Filename", "upload.jar"))
        )
        if not (filename.lower().endswith(".jar") or filename.lower().endswith(".class")):
            self._send_json({"error": "only .jar and .class are accepted"}, status=400)
            return

        data = self.rfile.read(length)

        job_id = uuid.uuid4().hex
        STORE.create_job(job_id, filename, data)

        try:
            result_zip, skipped_entries = run_decompile(
                data, filename, DECOMPILE_TIMEOUT)
        except DecompileError as e:
            STORE.mark_error(job_id, str(e))
            self._send_json({"error": str(e), "job_id": job_id}, status=422)
            return
        except Exception as e:
            STORE.mark_error(job_id, str(e))
            self._send_json({"error": "internal error: %s" % e, "job_id": job_id}, status=500)
            return

        STORE.mark_done(job_id, result_zip)

        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition",
                          'attachment; filename="%s_decompiled.zip"' % job_id)
        self.send_header("X-Rho9-Job-Id", job_id)
        # Surfaced as a header as well as inside the archive, so the UI can
        # raise it immediately without unpacking to find out.
        self.send_header("X-Rho9-Skipped-Entries", str(len(skipped_entries)))
        self.send_header("Content-Length", str(len(result_zip)))
        self.end_headers()
        self._write_body(result_zip)


class ThreadingHTTPServerLoopback(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """A browser that navigates away mid-response closes the socket, and
        the write that was already in flight raises BrokenPipe. That is the
        client's normal behaviour, not a server fault: reloading the page
        while a saved session was being sent printed a full traceback every
        time. Genuine faults are still reported."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
            return
        return super().handle_error(request, client_address)
    allow_reuse_address = True


_httpd = None


def _request_shutdown():
    global _httpd
    time.sleep(0.2)
    if _httpd:
        _httpd.shutdown()


_cleanup_done = False


def cleanup():
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True
    log("Shutting down -- wiping all stored samples and decompiled output.")
    if STORE:
        STORE.wipe()
    log("Wipe complete.")
    # The persistent threat-intel DB is intentionally NOT wiped -- it is the one
    # store that must outlive the process. Just flush and close its connection.
    if INTEL:
        INTEL.close()
        log("Threat-intel DB flushed and left in place at %s" % INTEL.db_path)
    # Fingerprints and set membership are knowledge, not sample residue.
    if FUZZY is not None:
        FUZZY.close()
        log("Fuzzy signature DB flushed and left in place at %s" % FUZZY.db_path)


def bind_server(host, ports):
    for port in ports:
        try:
            httpd = ThreadingHTTPServerLoopback((host, port), Handler)
            return httpd, port
        except OSError:
            continue
    raise RuntimeError("Could not bind to any of ports %r on %s" % (ports, host))


def main():
    global DECOMPILE_TIMEOUT, MAX_UPLOAD_BYTES, MAX_SESSION_BYTES, STORE, INTEL, FUZZY, _httpd, STATIC_DIR
    parser = argparse.ArgumentParser(description="Rho-9 ModForensics local decompile bridge")
    parser.add_argument("--port-start", type=int, default=DEFAULT_PORTS[0])
    parser.add_argument("--tools-dir", default=os.path.join(
        os.path.expanduser("~"), ".rho9", "decompile_tools"))
    parser.add_argument("--no-auto-install", action="store_true")
    parser.add_argument("--reinstall", action="store_true")
    parser.add_argument("--timeout", type=int, default=DECOMPILE_TIMEOUT)
    parser.add_argument("--max-upload-mb", type=int, default=150)
    parser.add_argument("--max-session-mb", type=int, default=250)
    parser.add_argument("--intel-db", default=INTEL_DB_DEFAULT,
                         help="path to the persistent threat-intel SQLite DB. This "
                              "file is NEVER wiped on shutdown or by /rho9/wipe -- it "
                              "is the long-lived attacker-fingerprint knowledge base. "
                              "Default: " + INTEL_DB_DEFAULT)
    parser.add_argument("--no-intel", action="store_true",
                         help="disable the persistent threat-intel store entirely "
                              "(no logging, /rho9/intel* endpoints return 404).")
    parser.add_argument("--fuzzy-dir", default=FUZZY_DIR_DEFAULT,
                         help="where the goodware/badware/malware sample sets "
                              "live. Persistent, never wiped. Default: "
                              + FUZZY_DIR_DEFAULT)
    parser.add_argument("--fuzzy-db", default=FUZZY_DB_DEFAULT,
                         help="persistent fuzzy signature database. Default: "
                              + FUZZY_DB_DEFAULT)
    parser.add_argument("--keep-set-samples", action="store_true",
                         help="also write malware/badware sample bytes to disk. "
                              "Off by default: this bridge's guarantee is that "
                              "samples do not outlive the process, and a "
                              "permanent malware folder quietly breaks it. "
                              "Goodware is always kept, it is not a hazard.")
    parser.add_argument("--no-fuzzy", action="store_true",
                         help="disable fuzzy matching (/rho9/fuzzy/* returns 404).")
    parser.add_argument("--no-page", action="store_true",
                         help="API only -- skip creating/serving the ModForensics static "
                              "folder entirely. Use this when the UI is hosted elsewhere "
                              "(e.g. GitHub Pages) and this machine only needs to run the "
                              "decompile/session API.")
    args = parser.parse_args()

    DECOMPILE_TIMEOUT = args.timeout
    MAX_UPLOAD_BYTES = args.max_upload_mb * 1024 * 1024
    MAX_SESSION_BYTES = args.max_session_mb * 1024 * 1024

    host = "127.0.0.1"  # loopback only, deliberately not configurable via CLI

    log("Rho-9 ModForensics Decompile Bridge v%s" % SERVER_VERSION)
    log("Binding to loopback only (%s) -- never reachable off this machine." % host)

    STORE = Store()
    if args.no_intel:
        INTEL = None
        log("--no-intel: persistent threat-intel store disabled.")
    else:
        try:
            INTEL = IntelStore(args.intel_db)
            log("Threat-intel store ready (persistent, exempt from cleanup): %s"
                % args.intel_db)
        except Exception as e:
            INTEL = None
            log("Could not open threat-intel store at %s: %s -- continuing without it."
                % (args.intel_db, e))
    if args.no_fuzzy:
        FUZZY = None
        log("--no-fuzzy: fuzzy matching disabled.")
    else:
        try:
            FUZZY = FuzzyStore(args.fuzzy_dir, args.fuzzy_db,
                               keep_samples=args.keep_set_samples)
            st = FUZZY.status()
            log("Fuzzy store ready (persistent, exempt from cleanup): %s"
                % args.fuzzy_db)
            log("Fuzzy sets: %d goodware, %d badware, %d malware | TLSH %s, "
                "ssdeep %s" % (st["counts"]["goodware"], st["counts"]["badware"],
                               st["counts"]["malware"],
                               "yes" if st["tlsh"] else "MISSING",
                               "yes" if st["ssdeep"] else "MISSING"))
            if args.keep_set_samples:
                log("--keep-set-samples: malware sample bytes WILL be written "
                    "to disk under %s." % args.fuzzy_dir)
        except Exception as e:
            FUZZY = None
            log("Could not initialise the fuzzy store: %s -- continuing without "
                "it." % e)

    if args.no_page:
        STATIC_DIR = None
        log("--no-page: API only, static file hosting disabled (no ModForensics "
            "folder created, no index.html moved in).")
    else:
        STATIC_DIR = setup_static_app()
    atexit.register(cleanup)

    def _signal_handler(signum, _frame):
        log("Received signal %s" % signum)
        # IMPORTANT: BaseServer.shutdown() blocks until serve_forever()'s loop
        # observes the stop flag. serve_forever() runs on THIS thread (the
        # main thread, which is where Python signal handlers always run), so
        # calling shutdown() directly here would deadlock -- it would wait
        # for a loop iteration that can never happen because this very call
        # is blocking the thread that runs the loop. Do it from a separate
        # thread instead, same as the /rho9/shutdown endpoint does.
        def _do_shutdown():
            try:
                if _httpd:
                    _httpd.shutdown()
            except Exception:
                pass
        threading.Thread(target=_do_shutdown, daemon=True).start()

    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, _signal_handler)
            except Exception:
                pass

    setup_environment(args.tools_dir, not args.no_auto_install, args.reinstall)

    ports = list(range(args.port_start, args.port_start + 5))
    httpd, chosen_port = bind_server(host, ports)
    _httpd = httpd

    with _state_lock:
        ready = _state["ready"]
        msg = _state["setup_message"]
    log("Listening on http://%s:%d" % (host, chosen_port))
    if STATIC_DIR:
        log("Open the app at: http://%s:%d/  (serving from %s)" % (host, chosen_port, STATIC_DIR))
    else:
        log("API only -- no page served here. Point the UI (wherever it's hosted) at "
            "this address for the /rho9/* endpoints.")
    if ready:
        log("Decompiler ready. The web UI should detect this automatically.")
    else:
        log("Server is UP but decompiler is NOT ready yet: %s" % msg)
        log("The UI will show 'bridge found, engine not set up' and jars will "
            "still fall back to the manual decompiler.com flow until this is fixed.")

    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass
        cleanup()


if __name__ == "__main__":
    main()
