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
SERVER_VERSION = "1.1.0"
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


def run_decompile(input_bytes, original_filename, timeout_seconds):
    with _state_lock:
        if not _state["ready"]:
            raise DecompileError(_state["setup_message"] or "Decompiler engine not ready.")
        engine = dict(_state["engine"])
        java_path = _state["java_path"]

    ext = ".jar" if original_filename.lower().endswith(".jar") else ".class"
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

        return result_zip_bytes
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
                          "Content-Type, X-Filename, X-Rho9-Purpose")
        self.send_header("Access-Control-Expose-Headers", "X-Filename")
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
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
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
                self.wfile.write(body)
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
        self.wfile.write(data)

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
                }
            self._send_json(caps)
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
            self.wfile.write(data)
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
            self.wfile.write(output_zip)
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
            self.wfile.write(data_bytes)
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

    def do_POST(self):
        if self.path == "/rho9/decompile":
            self._handle_decompile()
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
            result_zip = run_decompile(data, filename, DECOMPILE_TIMEOUT)
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
        self.send_header("Content-Length", str(len(result_zip)))
        self.end_headers()
        self.wfile.write(result_zip)


class ThreadingHTTPServerLoopback(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
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


def bind_server(host, ports):
    for port in ports:
        try:
            httpd = ThreadingHTTPServerLoopback((host, port), Handler)
            return httpd, port
        except OSError:
            continue
    raise RuntimeError("Could not bind to any of ports %r on %s" % (ports, host))


def main():
    global DECOMPILE_TIMEOUT, MAX_UPLOAD_BYTES, MAX_SESSION_BYTES, STORE, INTEL, _httpd, STATIC_DIR
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
