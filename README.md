# Rho-9 ModForensics — Local Decompile Bridge

A small, dependency-free local server that gives ModForensics real `.jar`
decompilation (via CFR/Vineflower) without ever executing the sample, and
optionally serves the app itself. Works the same on Windows, Linux, and
Termux.

## Quick start

```bash
python3 rho9_decompile_server.py
```

First run auto-installs a JVM if needed and downloads a decompiler engine
into a local tools folder. Once it logs **"Decompiler ready"**, open the
URL it prints (e.g. `http://127.0.0.1:8991/`) — that serves ModForensics
itself, already wired up to this bridge with no cross-origin fuss.

Stop with `Ctrl+C`. Every sample, decompiled output, and saved session is
wiped on shutdown — guaranteed, not best-effort.

## What it does

- **Decompiles `.jar`/`.class` statically.** No JVM ever loads or runs the
  sample — CFR/Vineflower just parse the classfile format and reconstruct
  Java source. A hard per-job timeout stops anything designed to hang the
  decompiler.
- **Auto-sets itself up.** Detects/installs a JVM (Termux `pkg`, apt/dnf/
  pacman on Linux, `winget` on Windows), downloads CFR or Vineflower, and
  verifies it actually runs before reporting ready.
- **Serves the app.** Creates a `ModForensics/` folder next to itself and
  serves `index.html` from it directly — same-origin, so there's no
  browser cross-origin/Private-Network-Access friction. If a genuine
  ModForensics `index.html` shows up at `~/storage/downloads/index.html`
  (Termux shared storage), it's moved in automatically; files that don't
  match ModForensics's signature are left alone rather than silently
  overwriting a working setup.
- **Remembers your session.** The UI can push its full working state here
  so a page refresh restores exactly where you left off. One refresh
  restores it; two refreshes within ~4 seconds is treated as "start over"
  and clears it. All of it lives only in SQLite blobs, parameterized
  queries throughout, wiped alongside everything else on shutdown.
- **Loopback only.** Binds to `127.0.0.1` and nothing else, always.

## CLI flags

| Flag | Default | What it does |
|---|---|---|
| `--port-start N` | `8991` | First port tried (scans 5 in a row) |
| `--tools-dir PATH` | `~/.rho9/decompile_tools` | Where the engine jar lives |
| `--no-auto-install` | off | Detect a JVM but don't try to install one |
| `--reinstall` | off | Wipe the tools dir and re-fetch everything |
| `--timeout N` | `90` | Per-job decompile timeout, in seconds |
| `--max-upload-mb N` | `150` | Reject uploads larger than this |
| `--max-session-mb N` | `250` | Reject saved-session reports larger than this |
| `--no-page` | off | API only — don't create/serve the `ModForensics` folder at all (use when the UI is hosted elsewhere, e.g. GitHub Pages) |

## API (all under `/rho9/`)

| Endpoint | Purpose |
|---|---|
| `GET /rho9/capabilities` | Handshake — service purpose, engine, ready state |
| `POST /rho9/decompile` | Upload a `.jar`/`.class`, get back a zip of `.java` |
| `GET /rho9/result/<id>` | Re-fetch a previous decompile result |
| `POST /rho9/session` | Save the current report (JSON body) |
| `GET /rho9/session` | Restore the last saved report |
| `POST /rho9/session/clear` | Forget the saved report only |
| `POST /rho9/wipe` | Purge all stored data now, keep the server running |
| `POST /rho9/shutdown` | Ask the server to shut down (wipes on the way out) |

## Honest limitations

- Pinned download URLs for CFR/Vineflower can go stale if those projects
  reshuffle releases — if setup fails, drop a working `cfr.jar` or
  `vineflower.jar` straight into the tools dir and it'll be used as-is.
- This eliminates "the malware runs" as a risk, not "the decompiler parser
  has a bug" as one. If that distinction matters for your threat model,
  run it inside something disposable.
