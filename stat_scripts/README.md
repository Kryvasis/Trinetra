# Stat Scripts — Canonical Contract & Hardening Guide

## 1. Purpose

`stat_scripts/` contains the per-control checks that `TrinetraStat` invokes via `statRun`/`statRunAll`. Each file `V-XXX.sh` is a single compliance check whose output feeds directly into scoring, severity, and reporting. This document defines the **single canonical contract** all 36 scripts must follow so that future scripts can be written without reverse-engineering existing ones.

## 2. Input Contract

| Item | Contract | Notes |
|---|---|---|
| **Invocation** | `bash stat_scripts/<code>.sh <target> <session_output_dir>` | `target` is the device identifier/address (IP, hostname, or URL string). `session_output_dir` is an absolute path to `sessions/<session>/` (may be empty string for ad-hoc runs). |
| **Target validation** | Scripts must **never** assume `target` is well-formed. `target` may be empty, whitespace-only, 2048+ bytes, HTML/JS (`<!DOCTYPE html><html>window.ytcfg...`), JSON error (`{"error":...}`), binary (null bytes), or contain shell metachars (`;|&$`><\``). All such cases must be handled without crash/hang and must return a clear `VERDICT` (see §3). | Java `TrinetraStat` already sanitizes `target` via `DEVICE_RE` (`^[A-Za-z0-9._\-]{1,128}$`) for stat runs, but scripts must not rely on this — they are the next defense layer and may be invoked directly. |
| **Size/line guard** | Reject `target` with `${#TARGET} > 2048` bytes or `wc -l > 1000` lines → `VERDICT: error`, `DETAILS: target too large`. | Prevents hang on pathological input. Outer Java timeout is 300s (`TrinetraStat.java:484` `execCommand(300,...)`), inner tool timeouts are 5–180s per `nmap`/`curl`/`dig` phase (e.g., `V-003.sh:50` `timeout 90 nmap`). |
| **Environment** | `TRINETRA_VENDOR`, `TRINETRA_VENDOR_REQUESTED`, `TRINETRA_CONNECTOR` are injected per-device (`TrinetraStat.java:475-477`). Scripts **should** read `TRINETRA_VENDOR` if they are vendor-specific (e.g., Cisco-only check) and return `VERDICT: manual_review` with `DETAILS: <vendor> config fed to <other> check — not applicable` when the input looks like the wrong vendor (e.g., `set system host-name` vs `hostname`). Generic checks must accept any vendor. | Audit found **0/36** scripts previously read `TRINETRA_VENDOR` (drift). All 36 now include a best-effort vendor-mismatch guard. |
| **Config content** | Scripts that need to inspect actual device config (future) should read it from `$SESSION_DIR/<device>.json` or a file argument, not from stdin. If they do read a file, they must apply the same HTML/JSON/binary/size guards (1 MB, 10000 lines) before parsing. | Current 36 scripts are network-probe style (target host) and do not read config files except `V-158.sh:126` which uses `$SESSION_DIR/kernjc_scan.log`. That script now checks `$KJC` existence and does `timeout` wrapping. |
| **Second positional** | `$2` (`SESSION_DIR`) is declared in 36/36 scripts (`SESSION_DIR="${2:-}"`) but only `V-158.sh:126-128` previously used it. All scripts now declare it and handle empty safely. | |

### Inconsistencies Found (honest report)

- **Input source drift:** 36/36 declare `TARGET="${1:?Usage}"` (positional), 0/36 read stdin or JSON file, 1/36 (`V-158`) used `$SESSION_DIR`, 0/36 read `TRINETRA_VENDOR` despite Java injecting it for every run.
- **Host sanitization drift:** 10/36 mature scripts (`V-003`, `V-004`, `V-005`, `V-006`, `V-007`, `V-009`, `V-010`, `V-011`, `V-013`, `V-056`) derived `HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')`; 26/36 stubs used raw `$TARGET` in `curl`/`nmap`/`syft` without sanitization and without quoting in `bash -c` (e.g., `V-005.sh:75` `bash -c "echo '' | nc -w3 $SCAN_TARGET $PORT"` — injection risk).
- **Empty-input handling:** Before hardening, `TARGET="${1:?Usage}"` caused `bash` to exit 1 with `Usage` to stderr and no `VERDICT`, so decision engine treated it as `ERROR` with raw parse failure, not a clean `manual_review`.
- **Size handling:** No guard; a 1 MB HTML blob (`window.ytcfg...` from Prompt 29) was fed to `curl`/`nmap` and then to `TrinetraConfigIngestor`, producing 22 `unrecognized` lines and fabricated `pass/fail`.
- **Output vocabulary:** 10 mature scripts emitted `[PASS]`/`[FAIL]` bracketed, 1 emitted `[VERDICT]`, 7 emitted `[WARN]`/`[INFO]`, 26 stubs emitted only `Tool found/not found` or raw `head -20` output. None emitted the canonical `VERDICT:` line.
- **Exit code conflation:** 6 scripts (`V-003`, `V-005`, `V-006`, `V-007`, `V-009`, `V-010`) always `exit 0` (grep-driven), 4 scripts (`V-004`, `V-011`, `V-013`, `V-056`) used `exit 1` for fail and `exit 0` for pass (`exit_code_zero` method), 25 stubs used `exit $?` (last command status, usually 0), 1 (`V-158`) used `exit 1` for missing tool. The same exit code meant both “script ran” and “compliance failed.”
- **Missing scripts:** `3_decision_engine.csv` defines ~108 V-codes, `stat_scripts/` has 36 — 72 codes have no file and correctly go to `buildStatFailure` (`verdict=error, exit_code=-1`) in `TrinetraStat.java:435-438`.

All 36 have now been standardized (see §3-§6).

## 3. Output Contract (canonical)

**Every script must write to stdout** (stderr is captured separately but ignored for verdict) **at least:**

```
VERDICT: <pass|fail|manual_review|error>
SEVERITY: <critical|high|medium|low|none>
DETAILS: <human-readable one-line reason>
```

- `VERDICT` is **authoritative**. `TrinetraStat.DecisionEngine.evaluate()` (`src/TrinetraStat.java:184`) first searches stdout for `^VERDICT:\s*(pass|fail|manual_review|error)` (case-insensitive, multiline, last occurrence wins). If found, it returns that verdict **without** consulting `pass_criteria`/`fail_criteria` or `exitCode`. If not found, it falls back to legacy `grep_present`/`grep_absent`/`exit_code_zero`/`numeric_threshold`/`regex_match` for backward compatibility.
- `SEVERITY` should match `2_static_map.json:default_severity` for that `V-XXX` when verdict is `fail` (e.g., `V-013.sh` → `medium`, `V-057.sh` → `critical`). For `pass`/`manual_review`/`error`, use `none`.
- Additional lines (`=== V-XXX ===`, `Target: $HOST`, `[PASS] ...`, `---`, tool raw output) are allowed and preserved for debugging, but must not be the sole output — the `VERDICT` line must be present.
- If a script cannot determine a result (empty input, HTML, oversized, unexpected vendor, missing tool, DNS failure, timeout), it must return `VERDICT: manual_review` or `VERDICT: error` with a clear `DETAILS` (e.g., `empty target`, `target appears to be HTML/JS`, `DNS resolution failed`, `tool not available`), **not** a silent fallthrough, not `pass`/`fail`.

### Verdict Vocabulary

| Verdict | Meaning |
|---|---|
| `pass` | Check ran, target complies with this control. |
| `fail` | Check ran, target violates this control. |
| `manual_review` | Check ran but result is inconclusive, not applicable, or needs human (e.g., empty input, DNS failure, vendor mismatch, missing tool, `tool not found` stub). |
| `error` | Check could not run correctly due to malformed/unexpected input (empty, oversized, HTML, JSON error, binary, injection characters) or execution error. |

`manual_review` and `error` are **never** treated as `pass`/`fail` in scoring; they remain in the denominator for `compliance_percentage` but do not prove compliance or failure. This prevents Prompt-29-style fabricated `pass` on HTML.

### File Artifacts

Only `V-158.sh:126-128` writes to `$SESSION_DIR/kernjc_scan.log` via `tee`. No other script should write to `$SESSION_DIR` except for debugging; the Java layer writes `*_static_raw.txt` and `normalized_results` itself.

## 4. Exit Code Contract (standardized)

- **`exit 0`** — script **executed successfully** and emitted a `VERDICT` line. The verdict itself may be `pass`, `fail`, `manual_review`, or `error` — the exit code does **not** encode compliance. This is the normal path for all 36 hardened scripts, including when `VERDICT: fail`.
- **`exit 1` / `exit 2`** — script encountered a usage error (missing arguments) or an internal execution error that prevented it from emitting a `VERDICT`. Java `execCommand` will return `exitCode=-1` on timeout and `DecisionEngine` will map it to `ERROR`. Hardened scripts avoid this by always emitting `VERDICT` and exiting `0` even for `fail`/`error` cases; non-zero is reserved for true crashes.

**Migration:** 4 legacy `exit_code_zero` scripts (`V-004`, `V-011`, `V-013`, `V-056`) previously used `exit 1` for fail. They now emit `VERDICT: fail`/`pass` and `exit 0`; `DecisionEngine` prefers `VERDICT` so behavior is preserved while satisfying the new contract. `V-088` and `V-157` were listed as `exit_code_zero` in `2_static_map.json:226,419` but their stubs always exited `0` — they now correctly emit `VERDICT: manual_review` via the footer.

## 5. Hardening Requirements (applied to all 36)

Each script must handle without crash/hang/nonsensical verdict:

- **Empty input** (`""` or whitespace-only) → `manual_review` (`DETAILS: empty target`), `exit 0`.
- **Non-config content** (HTML `<!DOCTYPE html><html>window.ytcfg...`, JSON `{"error":...}`, binary with `\x00`, random text) → `error` (`DETAILS: target appears to be HTML/JS`), `exit 0`, not `pass`/`fail` via accidental substring. Implemented via `grep -qiE '<!doctype html|<html|<script|window\.ytcfg'` and JSON/error checks before any tool invocation.
- **Unexpected vendor** (Juniper `set system host-name` fed to Cisco check or vice-versa) → `manual_review` (`DETAILS: Juniper config fed to Cisco check — not applicable`), `exit 0`. Controlled via `TRINETRA_VENDOR` env; permissive (only when clear mismatch).
- **Very large input** (`>2048` bytes or `>1000` lines) → `error` (`DETAILS: target too large`), `exit 0`, before any `nmap`/`curl` that could hang. Outer Java enforces 300s per script (`TrinetraStat.java:484` `execCommand(300,...)`), inner `timeout 5`-`180` wraps each `nmap`/`dig`/`curl`/`openssl` call (e.g., `V-003.sh:50` `timeout 90 nmap`).
- **Special characters / injection** — all expansions must be quoted (`"$TARGET"`, `"$HOST"`, `"$SCAN_TARGET"`). Any `target` containing `;|&$`><\`` is rejected with `error` before use. Existing `bash -c "echo '' | nc -w3 $SCAN_TARGET $PORT"` patterns in `V-005.sh:166`, `V-006.sh:160`, `V-007.sh:159` were fixed to `printf '' | timeout 5 nc -w3 "$SCAN_TARGET" "$PORT"` and `printf '' | timeout 10 openssl s_client -connect "${SCAN_TARGET}:${port}" -servername "$HOST"` to avoid `eval`-style injection. No script now uses `eval` or `bash -c` with interpolated target.
- **Timeout safety** — outer 300s in `TrinetraCommon.execCommand:204` (`proc.waitFor(300, SECONDS)` → `"-1"` on timeout → `ERROR`), inner `timeout 5 dig`, `timeout 10 curl`, `timeout 10 openssl`, `timeout 90 nmap` etc. Stub tools (`grype`, `syft`, `checksec`, `trufflehog`, `cloud_enum`, `prowler`, `objection`, `jadx`, `flawfinder`, `cppcheck`, `kernel-hardening-checker`, `paxtest`) now wrapped in `timeout 10`.

**Shell-injection audit result:** No `eval` found. 3 instances of `bash -c` with unquoted `$SCAN_TARGET`/`$HOST`/`$PORT` were found and fixed (`V-005.sh:166`, `V-006.sh:160`, `V-007.sh:159,174,201`, `V-009.sh:164`). All other tool invocations already used quoted `"$TARGET"`/`"$HOST"`. After header injection guard (`grep -qE '[;|&$`><\\]'`), no target containing metachars reaches a shell command.

## 6. Timeout Expectations

- **Per-script outer:** 300s (`TrinetraStat.java:484`). If exceeded, Java kills the process and records `raw_output=""`, `stderr="Command timed out after 300s"`, `exitCode=-1` → `DecisionEngine` returns `ERROR`.
- **Per-tool inner:** `dig` 5s, `curl` 5-10s (`--max-time 8 --connect-timeout 5`), `openssl` 10s, `nmap` 90-180s (`--host-timeout 120s`), `grype`/`syft`/`checksec` 10s. This ensures a single slow network target cannot stall an entire `statRunAll` batch (sequential or parallel `workers` pool in `TrinetraStat.java:679`).

## 7. Decision Engine Integration

`src/TrinetraStat.java:184-214` `DecisionEngine.evaluate(rule, rawOutput, exitCode)`:

1. Search `rawOutput` for `^VERDICT:\s*(pass|fail|manual_review|error)` (last wins). If found, return that.
2. Else, switch on `rule.evalMethod` (`grep_present`, `grep_absent`, `exit_code_zero`, `numeric_threshold`, `regex_match`) using `pass_criteria`/`fail_criteria` from `2_static_map.json`/`3_decision_engine.csv`.
3. `grep_present` on blank → `MANUAL_REVIEW`; `grep_absent` on blank → `PASS` (intentional: “no bad thing found”); `exit_code_zero` `0→PASS`, `>0→FAIL`/`MANUAL_REVIEW`, `-1→ERROR`.

New `VERDICT` takes precedence, so hardened scripts are judged by their explicit verdict while legacy scripts without `VERDICT` fall back to old text matching.

## 8. Testing Contract

Permanent regression: `bridge/tests/test_stat_hardening.py` runs **every** script (`36`) against **4** scenarios (`valid=example.invalid`, `empty=""`, `garbage=HTML from Prompt 29`, `oversized=3000×"a"`) plus injection spot-check. Asserts:

- No hang past `15s` per script.
- No crash (`rc==0` for hardened scripts).
- Output contains `VERDICT: <canonical>` and `SEVERITY:`.
- For `valid` → not `error`; for `empty`/`garbage` → `manual_review`/`error` only (never `pass`/`fail`); for `oversized` → `error`.

Run via `python3 -m pytest bridge/tests/test_stat_hardening.py -v` (146 tests: 36×4 + 2). Future V-codes must pass this without modification.

## 9. What Was Not Changed

- **Compliance logic/intent** preserved: each `V-XXX` still checks the same control (e.g., `V-013` weak password, `V-071` admin interface). Only output robustness, exit codes, and input validation were changed.
- **Manifest** (`config/compliance_manifest.json`, `2_static_map.json`, `3_decision_engine.csv`) not edited — framework mappings, severities, and `pass_criteria`/`fail_criteria` strings remain authoritative.
