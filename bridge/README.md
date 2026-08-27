# Trinetra Flask Bridge

Python Flask bridge exposing the Java `trinetra` CLI as REST endpoints for the future React UI. **No business logic is reimplemented in Python** — the Java backend remains the single source of truth; the bridge only shells out to the CLI via `subprocess` (no shell, argument list) and relays structured output.

## Architecture

```
React UI  ->  Flask bridge (bridge/app.py)  ->  subprocess ->  trinetra CLI (java -Dtrinetra.root ... Trinetra)
                                    \->  java -Dtrinetra.root ... TrinetraBridgeHelper (status, set-vendor)
```

All execution, scoring (`TrinetraComplianceScorer`), narrative validation (`TrinetraNarrativeGenerator`), and report assembly (`TrinetraAuditReportBuilder`) remain in Java. The bridge never writes to, caches, or recomputes `brain_state.json`, chain hashes, or scores.

## Requirements

- Python 3.10+
- Java 17+ (`javac` / `java`), `out/` compiled (`make compile`)
- `lib/sqlite-jdbc-*.jar` on classpath (bundled)
- `bash`, `curl`, `jq` (for underlying `trinetra` scripts)
- Optional (for full AI behavior): Gemini CLI at `~/.npm-global/bin/gemini`, `config.json` with keys

Install Python deps:

```bash
pip install -r bridge/requirements.txt
# or
pip install Flask pytest requests
```

## Configuration

Lightweight config in `bridge/config.py`, overridable via environment:

| Env var | Default | Description |
|---|---|---|
| `TRINETRA_BRIDGE_HOST` | `127.0.0.1` | Flask bind host |
| `TRINETRA_BRIDGE_PORT` | `5000` | Flask port |
| `TRINETRA_BIN` | `<repo>/trinetra` | Path to `trinetra` wrapper |
| `TRINETRA_ROOT` | `<repo>` | Project root (`-Dtrinetra.root`) |
| `TRINETRA_SUBPROCESS_TIMEOUT` | `60` | CLI timeout (s) |
| `FLASK_SECRET` | `trinetra-bridge-dev` | Flask secret |

Do **not** hardcode paths — use env or `bridge/config.py`.

## Running the Bridge

```bash
# From repo root, ensure Java is built
make compile

# Dev server (auto-reload off, single source of truth)
TRINETRA_ROOT=/home/kali/Desktop/Trinetra TRINETRA_BIN=/home/kali/Desktop/Trinetra/trinetra \
  python3 -m bridge.app
# or
python3 bridge/app.py

# With custom host/port
TRINETRA_BRIDGE_HOST=0.0.0.0 TRINETRA_BRIDGE_PORT=8080 python3 -m bridge.app
```

The server will listen on `http://127.0.0.1:5000` by default.

## Endpoints

All endpoints validate inputs with strict regex and reject injection characters (`;|&$`><'"*` and newlines) **before** any subprocess is spawned. Subprocess is invoked with an argument list (`shell=False`), never via shell interpolation. Failures are returned as `4xx/5xx` with `{"error": "...", "details": {...}}` — a `200` always means the backend call succeeded (even if the compliance result is `FAIL`).

### `POST /api/session` — create new session
```bash
curl -X POST http://127.0.0.1:5000/api/session \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo","target":"127.0.0.1"}'
# 201 -> {"message":"Session created: demo (target: 127.0.0.1)","session":"demo","target":"127.0.0.1"}
```

### `POST /api/session/<name>/run` — run selected tests
Accepts `device_id` + optional `vendor` + `test_ids` (or `devices` array for multi-vendor).

Single device:
```bash
curl -X POST http://127.0.0.1:5000/api/session/demo/run \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"127.0.0.1","vendor":"Cisco","test_ids":["V-010","V-008"],"workers":1}'
# 200 -> {"message":"tests executed","session":"demo","devices":[...],"test_ids":[...],"results":[...]}
```

Multi-vendor (combined session):
```bash
curl -X POST http://127.0.0.1:5000/api/session/demo/run \
  -H 'Content-Type: application/json' \
  -d '{"devices":[{"device_id":"10.0.0.1","vendor":"Cisco"},{"device_id":"10.0.0.2","vendor":"Juniper"}],"test_ids":["V-010"]}'
```

### `GET /api/session/<name>/status` — chain verification + metadata
```bash
curl http://127.0.0.1:5000/api/session/demo/status
# 200 -> {"session_name":"demo","target":"127.0.0.1","chain":{"intact":true,"linkCount":2,"latestHash":"..."},"normalized_results_count":2,"device_vendors":{...}}
# 404 -> {"error":"Session not found: demo"}
```

### `GET /api/session/<name>/score` — compliance-score
```bash
curl http://127.0.0.1:5000/api/session/demo/score
# 200 -> {"score":{"session_name":"demo","frameworks":{"ISO27001":{...}},"total_tests_executed":1},"score_file":"..."}
```

### `GET /api/session/<name>/report` — compliance-report (narrative + score)
```bash
curl http://127.0.0.1:5000/api/session/demo/report
# 200 -> {"session":"demo","stdout":"# Compliance Narrative Report ...","narrative_path":"...","score_path":"..."}
```

### `GET /api/session/<name>/audit-report` — audit-report (combined + per-framework)
```bash
curl http://127.0.0.1:5000/api/session/demo/audit-report
# 200 -> {"session":"demo","combined_path":".../audit_report_demo.md","framework_paths":[...],"derived_aggregate_pct":50.0,"chain_status":"INTACT: chain intact (1 link)","combined_content":"# Combined Audit Report ..."}
```

### `GET /api/doctor` — health check (structured)
```bash
curl http://127.0.0.1:5000/api/doctor
# 200 -> {"raw_stdout":"=== Trinetra Doctor ...","sections":{...},"test_definitions":{"count":124},"session_validation":{"session_errors":{...}},"ai_integration":{...}}
```

### `POST /api/session/<name>/upload-config` — config-file upload (PS26155 primary path)
```bash
# Primary demo flow: upload static config file, no live SSH required
curl -X POST http://127.0.0.1:5000/api/session/demo/upload-config \
  -F "device_id=cisco-01" -F "vendor=Cisco" -F "config=@cisco-01_running-config.txt"
# or JSON:
curl -X POST http://127.0.0.1:5000/api/session/demo/upload-config \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"cisco-01","vendor":"Cisco","config_content":"hostname R1\nenable secret 5 ...","filename":"cisco-01_config.txt"}'
# 200 -> {"device_id":"cisco-01","vendor":"Cisco","ingestion_method":"config_upload","total_checks":7,"passed":3,"failed":0,"unrecognized_count":2,"unrecognized_lines":[...]}
# ingestion_method is recorded per device (config_upload vs live_target) and shown in reports
```

### `GET /api/session/<name>/unrecognized` — list unrecognized config lines
```bash
curl http://127.0.0.1:5000/api/session/demo/unrecognized
# 200 -> {"session":"demo","unrecognized_by_device":{"cisco-01":[...]}, "total_unrecognized":2}
curl http://127.0.0.1:5000/api/session/demo/unrecognized?device_id=cisco-01
# 200 -> {"device_id":"cisco-01","unrecognized_lines":[...],"count":2}
```

### `POST /api/session/<name>/train` — label unrecognized line (no redeploy)
```bash
curl -X POST http://127.0.0.1:5000/api/session/demo/train \
  -H 'Content-Type: application/json' \
  -d '{"vendor":"Cisco","pattern":"my-custom-feature.*","security_category":"Custom Hardening","control_mapping":["CIS-v8-4.6"],"remediation":"no my-custom-feature"}'
# 201 -> {"message":"training entry added","entry":{...},"total_entries":1}
# Writes to config/vendor_training_map.json (not .java); next upload re-parses correctly
```

### `GET /api/session/<name>/audit-report/pdf` — PDF export
```bash
curl http://127.0.0.1:5000/api/session/demo/audit-report/pdf -o audit_report_demo.pdf
# 200 -> application/pdf, Content-Disposition: attachment; filename=audit_report_demo.pdf
# PDF includes device_id/hardware field, per-device evidence rows, and remediation per failed test
# Remediation is sourced from stat_script docs first; only falls back to LLM (labeled "AI-suggested — verify before use")
```

### `GET /` / `GET /ui` / `GET /upload` — minimal upload GUI (PS26155)
Plain HTML/JS served by Flask (no React needed):
- File upload form (device config + vendor select or auto-detect)
- Trigger run, results/score view, link to download PDF
- Training-loop labeling form (shows unrecognized lines, lets admin label and re-parse)
```bash
# Open in browser
xdg-open http://127.0.0.1:5000/
# or
curl http://127.0.0.1:5000/ | head -20
```

### `GET /api/health` — bridge health
```bash
curl http://127.0.0.1:5000/api/health
# 200 -> {"status":"ok","trinetra_bin":"...","trinetra_root":"..."}
```

### Error examples
```bash
# Invalid session name (injection) -> 400, no subprocess
curl -X POST http://127.0.0.1:5000/api/session \
  -H 'Content-Type: application/json' \
  -d '{"name":"bad; rm -rf /","target":"127.0.0.1"}'
# 400 -> {"error":"invalid session name: 'bad; rm -rf /' (allowed: ^[A-Za-z0-9_\\-]{1,64}$)"}

# Non-existent session for status -> 404
curl http://127.0.0.1:5000/api/session/no_such/status
# 404 -> {"error":"Session not found: no_such","details":{"stdout":"","stderr":"..."}}

# Test failure vs backend error:
# - POST /run with V-008 that returns FAIL is still 200 (compliance result)
# - POST /run with invalid test_id "bad!" is 400 (validation)
# - GET /score for missing session with bad format is 400, for valid but empty session is 200 with empty frameworks
```

## Testing

```bash
# From repo root
python3 -m pytest bridge/tests/test_bridge.py -v
# All 14 tests should pass in ~2 min (real trinetra runs, no mocks for happy paths)
```

Tests cover:
- (a) each endpoint against a real session produces correct structured output matching CLI
- (b) subprocess failure (invalid session/status) returns proper 4xx/5xx with error body
- (c) injection attempt (`; rm -rf`, `&&`, etc.) is rejected 400 **without** invoking subprocess (verified via monkeypatch)
- (d) `/api/doctor` correctly parses CLI output into structured JSON

## Security Notes

- All inputs are validated with strict regexes (`SESSION_RE`, `TEST_ID_RE`, `DEVICE_RE`, `VENDOR_RE`) and an explicit injection-character blocklist before any `subprocess.run`.
- `subprocess.run` is always called with `shell=False` and an argument list, never string interpolation.
- File paths from CLI output (e.g., `combined_path`) are validated to exist before reading.

## Development

- `bridge/app.py` is the single Flask entry; `bridge/config.py` holds env-overridable config.
- `src/TrinetraBridgeHelper.java` is the minimal Java helper for `status` and `set-vendor` (keeps Java as source of truth).
- No Python persistence layer — the bridge is stateless and relays CLI output.
