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
SERVER_VERSION = "1.0.0"
DEFAULT_PORTS = [8991, 8992, 8993, 8994, 8995]

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
    """Best-effort JVM install. Never blocks on a password prompt; if it
    can't install silently, it just tells you what to run yourself."""
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
            log("Attempting passwordless: sudo -n apt-get install -y default-jre-headless")
            try:
                r = subprocess.run(
                    ["sudo", "-n", "apt-get", "install", "-y", "default-jre-headless"],
                    timeout=300, capture_output=True, text=True,
                )
                if r.returncode != 0:
                    log("No passwordless sudo (or apt failed). Run manually:\n"
                        "    sudo apt-get install -y default-jre-headless")
            except Exception as e:
                log("apt-get attempt failed: %s" % e)
        elif shutil.which("dnf"):
            log("Run manually if this doesn't auto-elevate: sudo dnf install -y java-17-openjdk")
            try:
                subprocess.run(["sudo", "-n", "dnf", "install", "-y", "java-17-openjdk"],
                                timeout=300, capture_output=True, text=True)
            except Exception:
                pass
        elif shutil.which("pacman"):
            log("Run manually if this doesn't auto-elevate: sudo pacman -S --noconfirm jre-openjdk")
            try:
                subprocess.run(["sudo", "-n", "pacman", "-S", "--noconfirm", "jre-openjdk"],
                                timeout=300, capture_output=True, text=True)
            except Exception:
                pass
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


STORE = None  # set in main()
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
                }
            self._send_json(caps)
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

    def do_POST(self):
        if self.path == "/rho9/decompile":
            self._handle_decompile()
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


def bind_server(host, ports):
    for port in ports:
        try:
            httpd = ThreadingHTTPServerLoopback((host, port), Handler)
            return httpd, port
        except OSError:
            continue
    raise RuntimeError("Could not bind to any of ports %r on %s" % (ports, host))


def main():
    global DECOMPILE_TIMEOUT, MAX_UPLOAD_BYTES, MAX_SESSION_BYTES, STORE, _httpd, STATIC_DIR
    parser = argparse.ArgumentParser(description="Rho-9 ModForensics local decompile bridge")
    parser.add_argument("--port-start", type=int, default=DEFAULT_PORTS[0])
    parser.add_argument("--tools-dir", default=os.path.join(
        os.path.expanduser("~"), ".rho9", "decompile_tools"))
    parser.add_argument("--no-auto-install", action="store_true")
    parser.add_argument("--reinstall", action="store_true")
    parser.add_argument("--timeout", type=int, default=DECOMPILE_TIMEOUT)
    parser.add_argument("--max-upload-mb", type=int, default=150)
    parser.add_argument("--max-session-mb", type=int, default=250)
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
