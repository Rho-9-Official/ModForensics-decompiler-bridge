# Rho-9 ModForensics, Local Decompile Bridge

A small, dependency-free local server that gives ModForensics real `.jar`
decompilation (via CFR/Vineflower) without ever executing the sample, optionally
serves the app itself, and keeps a persistent, cross-session threat-intel store
so repeat attacker infrastructure is recognised over time. Works the same on
Windows, Linux, macOS, and Termux.

Server version: **1.1.0**. Scanner it serves: **ModForensics v3.1.1**.

> This README is generated from the current server source
> (`rho9_decompile_server.py`), not from an earlier release. If the code and this
> document ever disagree, the code wins.

## Quick start

```
python3 rho9_decompile_server.py
```

First run auto-installs a JVM if needed and downloads a decompiler engine into a
local tools folder. Once it logs **"Decompiler ready"**, open the URL it prints
(for example `http://127.0.0.1:8991/`), which serves ModForensics itself, already
wired up to this bridge with no cross-origin fuss.

Stop with `Ctrl+C`. Every uploaded sample, decompiled output, and saved session is
wiped on shutdown, guaranteed, not best-effort. The one thing that is **not**
wiped is the persistent threat-intel database (see below); that is deliberate.

## What it does

- **Decompiles `.jar`/`.class` statically.** No JVM ever loads or runs the sample.
  CFR/Vineflower just parse the classfile binary format and reconstruct Java
  source. It does not load the target class, call its `main()`, or invoke any of
  its methods. A hard per-job timeout stops anything designed to hang the
  decompiler.
- **Auto-sets itself up.** Detects or installs a JVM (Termux `pkg`; apt/dnf/pacman
  on Linux; `winget` on Windows; `brew` on macOS), downloads Vineflower or CFR,
  and verifies it actually runs before reporting ready.
- **Serves the app.** Creates a `ModForensics/` folder next to itself and serves
  `index.html` from it directly, same-origin, so there is no browser
  cross-origin or Private-Network-Access friction. On Termux, a genuine
  ModForensics `index.html` dropped at `~/storage/downloads/index.html` is moved
  in automatically; the move is signature-checked and version-compared, so an
  unrelated file that merely happens to be named `index.html` is left alone
  rather than overwriting a working setup.
- **Remembers your session.** The UI can push its full working state here so a
  page refresh restores exactly where you left off. It lives only in SQLite blobs
  with parameterized queries, and is wiped alongside everything else on shutdown.
- **Keeps a persistent threat-intel store (new in 1.1.0).** After every analysis
  the app POSTs its finding set here, and the bridge logs it to a fixed-path
  SQLite database that survives restarts. This is the one store that is exempt
  from every wipe path, on purpose. Details below.
- **Attributes Discord webhooks, ingests from the Discord CDN, and looks up abuse
  contacts (new in 1.1.0).** Three tightly constrained network helpers that make
  attribution and reporting easy without opening an SSRF hole. Details below.
- **Loopback only.** Binds to `127.0.0.1` and nothing else, always. The host is
  not configurable from the CLI.

## The persistent threat-intel store (new in 1.1.0)

This is the deliberate counterpart to the throwaway jobs database. The jobs DB is
a temp file that is DELETEd, VACUUMed, and unlinked on every shutdown path. The
intel store is the opposite: a durable knowledge base at a fixed on-disk path
(default `~/.rho9/threat_intel.sqlite3`, WAL mode) that is intentionally exempt
from `cleanup()`, `POST /rho9/wipe`, and the jobs `purge()`. Attacker
fingerprints have to outlive the process for repeat infrastructure to be
recognisable across sessions, so this file is never touched by any wipe.

It records, per unique indicator value:

- the indicator itself (webhook, C2, staging link, wallet, URL, and so on),
- `times_seen`, the number of **distinct samples** that exact value has appeared
  in. This is the attacker-identification counter, and it is deduplicated per
  `(indicator, sample)`, so re-analysing the same file never inflates it,
- `first_seen` and `last_seen` timestamps.

And per malware sample (keyed by SHA-256 of the uploaded bytes):

- filename, triage score and band, signature families, and the derived
  human-readable attack methods,
- file and class counts, and how many times it has been analysed.

Plus a sample-to-indicator link table (pivot an indicator to every sample it
appeared in, and back), an append-only analyses log for trend charts, and a
`webhook_meta` table for Discord attribution.

## Discord attribution, CDN ingestion, and abuse reporting (new in 1.1.0)

Every outbound request in this group is tightly constrained: a host allowlist is
enforced on the initial URL **and re-checked on every redirect hop** (no
open-redirect or SSRF pivot), response sizes are capped, and filenames are
sanitised before anything is returned to the browser.

- **Webhook attribution.** Discord does not expose a webhook's creating user to a
  token holder, so the stable `guild_id`, `channel_id`, and `name` fields are
  captured instead. Those persist across every webhook an operator makes in that
  server, which is exactly the cross-sample signal that links multiple webhooks
  (and multiple samples) back to one operator. Synthetic `discord_guild` and
  `discord_channel` indicators are surfaced with sibling-webhook pivots.
- **Fetch from the Discord CDN.** Pulls a Minecraft archive from a Discord CDN
  host only, under a strict https plus host allowlist plus extension allowlist
  (`.zip`, `.jar`, `.litemod`, `.mrpack`, `.class`), with a size cap and a
  sanitised filename. The bytes then run through the normal static pipeline; they
  are never executed.
- **Abuse-contact lookup.** Best-effort RDAP lookup that surfaces abuse-contact
  emails for an IP or domain so filing a hosting or registrar report is easy.
  Degrades gracefully when RDAP is unreachable.

## CLI flags

| Flag                 | Default                          | What it does                                                                                        |
| -------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------- |
| `--port-start N`     | `8991`                           | First port tried (scans 5 in a row)                                                                 |
| `--tools-dir PATH`   | `~/.rho9/decompile_tools`        | Where the engine jar lives                                                                           |
| `--no-auto-install`  | off                              | Detect a JVM but do not try to install one                                                          |
| `--reinstall`        | off                              | Wipe the tools dir and re-fetch everything                                                           |
| `--timeout N`        | `90`                             | Per-job decompile timeout, in seconds                                                                |
| `--max-upload-mb N`  | `150`                            | Reject uploads larger than this                                                                      |
| `--max-session-mb N` | `250`                            | Reject saved-session reports larger than this                                                        |
| `--intel-db PATH`    | `~/.rho9/threat_intel.sqlite3`   | Path to the persistent threat-intel DB. This file is **never** wiped on shutdown or by `/rho9/wipe`  |
| `--no-intel`         | off                              | Disable the persistent threat-intel store entirely (`/rho9/intel*` return 404, nothing is logged)   |
| `--no-page`          | off                              | API only, do not create or serve the `ModForensics` folder (use when the UI is hosted elsewhere)    |

The bind host is always `127.0.0.1` and is deliberately not exposed as a flag.

## API (all under `/rho9/`)

Handshake, decompile, and session:

| Endpoint                   | Method | Purpose                                                          |
| -------------------------- | ------ | ---------------------------------------------------------------- |
| `/rho9/capabilities`       | GET    | Handshake: purpose, version, engine, ready state, feature flags  |
| `/rho9/decompile`          | POST   | Upload a `.jar`/`.class`, get back a zip of `.java`              |
| `/rho9/result/<id>`        | GET    | Re-fetch a previous decompile result                             |
| `/rho9/jobs`               | GET    | List jobs in the current run                                     |
| `/rho9/session`            | POST   | Save the current report (JSON body)                              |
| `/rho9/session`            | GET    | Restore the last saved report                                    |
| `/rho9/session/clear`      | POST   | Forget the saved report only                                     |
| `/rho9/wipe`               | POST   | Purge jobs and session now, keep the server running (not intel)  |
| `/rho9/shutdown`           | POST   | Ask the server to shut down (wipes jobs on the way out)          |

Threat intel (available unless `--no-intel`):

| Endpoint                   | Method | Purpose                                                          |
| -------------------------- | ------ | ---------------------------------------------------------------- |
| `/rho9/intel`              | POST   | Record one finished analysis (sample, IOCs, optional webhook meta) |
| `/rho9/intel/iocs`         | GET    | List indicators (filter by `type`, search with `q`, `limit`)     |
| `/rho9/intel/ioc`          | GET    | One indicator's detail: samples, co-occurring IOCs, webhook meta |
| `/rho9/intel/samples`      | GET    | List recorded samples                                            |
| `/rho9/intel/trends`       | GET    | Totals, analyses-by-day, IOC-by-type, bands, top IOCs, methods   |

Attribution and reporting helpers:

| Endpoint                   | Method | Purpose                                                          |
| -------------------------- | ------ | ---------------------------------------------------------------- |
| `/rho9/webhook-info`       | GET    | Resolve a Discord webhook (`?url=`) to guild/channel/name        |
| `/rho9/fetch-discord`      | GET    | Fetch a Minecraft archive from a Discord CDN link (`?url=`)      |
| `/rho9/abuse-contact`      | GET    | RDAP abuse-contact lookup for an IP or domain (`?target=`)       |

`POST /rho9/decompile`, `/rho9/session`, and `/rho9/intel` require the header
`X-Rho9-Purpose: rho9-modforensics-decompile-bridge-v1`; a mismatch is rejected.
Loopback Private-Network-Access is handled with the
`Access-Control-Allow-Private-Network` response header alongside ordinary CORS,
so `file://` and https pages can both reach the bridge once the browser opts in.

`GET /rho9/capabilities` now returns `version`, `engine`, `ready`,
`setup_message`, `max_upload_mb`, and the feature flags `intel`, `webhook_info`,
`discord_fetch`, and `abuse_contact`, so the UI can light up only what this build
actually supports.

## The ModForensics scanner it serves (v3.1.1)

The bridge serves the ModForensics single-file web app. The app parses decompiled
source (a `.zip` of `.java`, including the output this bridge produces) and scores
it for exfiltration indicators, signature families, remote-loader behaviour, and
obfuscation. The verdict is a triage indicator, not a final judgement, and the app
says so; it is meant to point a human at the evidence.

Recent v3.1.1 changes (this version number has covered the last two small updates
plus a larger update, and now this one):

- **Insecure downloads are forced to the top severity.** A cleartext `http://`
  download of a remote executable or archive (`.jar`, `.exe`, `.dll`, `.msi`, and
  similar) is now treated as a hard, non-cappable indicator and pinned to the
  maximum score (100, the HIGH THREAT band), overriding the corroboration gate,
  rather than the small `+5` modifier it used to be. The reasoning is that the
  intent is indeterminate: it may be a benign self-updater, or a hijacked or
  MITM'd endpoint now serving a malicious jar in place of the intended file. Once
  the transport is insecure there is no way to tell which, cleartext delivery is a
  common malware distribution channel, and the download itself is the hazard. So
  the tool stops guessing and rates it severe.
- **Crypto-wallet false positive fixed.** The wallet regex is anchored with
  non-alphanumeric boundaries, so a wallet-shaped run of characters sitting inside
  a longer hex string (for example a SHA-256 hash) no longer matches as a wallet
  address. Hashes stop being reported as crypto wallets.

Both changes are validated against the sample corpus below.

### Validation (real Chromium via Playwright)

Each sample was decompiled and the decompiled source fed through the app's actual
file pipeline in headless Chromium, then the live verdict was read back from
`threatScore()`.

| Sample                         | Before   | After         | Insecure download | Wallet FPs |
| ------------------------------ | -------- | ------------- | ----------------- | ---------- |
| EonCC AutoUpdater 1.0          | 69, SUSP | **100, HIGH** | yes (`http://` jar) | 0        |
| EonCC-Core / Eoncc (payload)   | 0, LOW   | 0, LOW        | no                | 0          |
| Sodium Extra (genuine)         | 0, LOW   | 0, LOW        | no                | 0          |
| minecash 1.0.0                 | 0, LOW   | 0, LOW        | no                | 0          |
| rcc-client                     | 0, LOW   | 0, LOW        | no                | 0          |

The AutoUpdater downloads `http://kohacdn.x10.network/builds/eoncc/EonCC-Core-1.0.jar`
and injects it into the Fabric classpath by reflection; before the change the
corroboration gate held it at 69 (SUSPICIOUS), and after it is pinned to 100
(HIGH THREAT). Nothing clean moved, and no hex hash tripped the wallet rule in any
sample.

## Honest limitations

- Pinned download URLs for CFR/Vineflower can go stale if those projects
  reshuffle their release assets. If setup fails, drop a working `cfr.jar` or
  `vineflower.jar` straight into the tools dir and it will be used as-is, with no
  re-download attempted.
- This eliminates "the malware runs" as a risk, not "the decompiler parser has a
  bug" as one. CFR and Vineflower are JVM parsers being fed untrusted binary
  input, so they carry the usual parser bug surface. If that distinction matters
  for your threat model, run this inside a VM or container you are willing to
  throw away.
- A LOW RISK verdict is not a clean bill of health. It means nothing matched a
  scoring signature or a hard indicator, which is exactly why the app tells you to
  read the file tree and strings before you trust anything. The EonCC payload in
  the table above is a good example: the dropper is loud, but the payload it
  fetches looks quiet in decompiled source.

## License

GPL-2.0. See `LICENSE`.
