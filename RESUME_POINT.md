# Resume Point

**Baseline commit:** `a9477f9` on `origin/main`
(Baseline: PS26155 alignment — config-upload ingestion, vendor training loop, CIS mapping verified (Prompt 21))

## Proven working end-to-end as of this commit

Full pipeline verified: Iskabon fingerprinting → per-device `device_vendors` + `VendorConnectorRegistry` (Cisco/Juniper) → hash-chained `normalized_results` (no cross-vendor leakage, verified via `multi_vendor_e2e` trap `T-SHARED` Cisco PASS + Juniper FAIL as distinct links, `verifyChain()` INTACT) → deterministic scorer (ISO 66.7/SOC2 33.3 etc., now with STIG) → validated Gemini narratives → audit reports with per-device evidence rows (now 10-col with Serial/Hardware/OS/Severity) and derived aggregate 50.0% labeled derived.

**Config-upload primary path (PS26155):** `POST /api/session/<name>/upload-config` → `TrinetraConfigIngestor.ingest()` → same `VendorConnector.normalizeCommand` + `VendorConnectorRegistry.resolve` logic as live-target path → `TrinetraStat.DecisionEngine.evaluate` on file content → findings + `normalized_results` appended with `ingestion_method: config_upload` + `device_details` (serial/hardware/os_version) → chain intact. Unrecognized lines tracked per-device via `TrinetraSession.setUnrecognizedLines()`. OS-version lightweight detection (`IOS XE`/`NX-OS`/`JUNOS` header scan) populates `os_version` when caller leaves blank — metadata-level awareness, not parsing branch (honest limited scope).

**Live-fetch additive path:** `POST /api/session/<name>/fetch-config` → `bridge/live_fetcher.py` (thin SSH/URL retrieval, no parsing) → same `TrinetraConfigIngestor.ingest(..., live_fetch)` → identical parsing/training-lookup/scoring/reporting as file upload, tagged `ingestion_method: live_fetch` for honest reporting. Config-file upload remains primary/recommended; fetch is optional auto-sourced convenience requiring network reachability, not a parallel fingerprinting system. Mocked integration tests prove fetched text produces the same compliance result as file upload and appears in persisted normalized results with the correct provenance.

**Vendor training loop proven:** Upload config → line flagged unrecognized → `POST /train` adds entry to `config/vendor_training_map.json` (now stores optional `os_version` per entry) → re-upload same config → line now recognized → zero `.java` file changes between train and re-parse. `VendorTrainingMap.java` mtime-cache mechanism verified.

## 7 PS-Critical Gaps Closed (Prompt 24 — audit items 1-7 + 8 partial)

### 1. DISA STIG — 4th required benchmark now real (highest priority)

**What was gap:** Manifest had 0 STIG mappings; UI showed disabled "coming soon" tab; PDF/report claimed STIG not computed — PS lists exactly 4 required frameworks, STIG was 25% missing.

**Fix:** Added real DISA STIG Group IDs `CISC-ND-xxxxxx` (Cisco) and `JUSX-ND-xxxxxx` (Juniper) to 13 of 15 V-codes in `config/compliance_manifest.json` where genuine STIG control exists:
- V-003: CISC-ND-000020, CISC-ND-000040 (disable unnecessary services, restrict management)
- V-006/007/008: CISC-ND-000130/000135/000250 + JUSX-ND-000130/000250 (approved TLS/ciphers, certificates)
- V-013: CISC-ND-000015, CISC-ND-000030, JUSX-ND-000015 (password complexity, auth)
- V-057: CISC-ND-000015/000025, JUSX-ND-000015 (protect authenticators)
- V-058: CISC-ND-000140, JUSX-ND-000140 (audit logging)
- V-070/087: CISC-ND-000160, JUSX-ND-000160 (patch)
- V-071: CISC-ND-000010/000040/000080, JUSX-ND-000010 (disable clear-text, restrict, timeout)
- V-005/105/144 etc. mapped similarly; V-106 (cloud S3) intentionally left without STIG (no NDM control) — appears in coverage_gaps honestly.

**Source cited:** `_STIG_source_note` top-level key in manifest: `DISA STIG Viewer — Cisco IOS Switch NDM STIG V2R5 (2024-01-26), Cisco IOS-XE Router NDM STIG V2R4, and Juniper SRX SG NDM STIG V2R4 / Network Device Management SRG; Group IDs CISC-ND-xxxxxx and JUSX-ND-xxxxxx correspond to Vuln IDs V-2204xx/V-2148xx. Verified via https://public.cyber.mil/stigs/` — each ID traceable in STIG Viewer HTML.

**Scorer picks up automatically:** `TrinetraComplianceScorer.java:36-80` is manifest-driven (`computeIfAbsent` per framework key). Verified live: `GET /api/session/<name>/score` now returns `"STIG": {"compliance_percentage": ..., "controls_covered": ["CISC-ND-000130", ...]}` without any scorer code change except added framework-filter overload (for item 2). Test `test_stig_scoring` asserts STIG present and controls start with `CISC-ND-`/`JUSX-ND-`.

**UI/report placeholder removed:** `frontend/src/pages/ResultsView.jsx:4` now `FRAMEWORKS = ['CIS','ISO27001','NIST_800-53','STIG','PCI-DSS','SOC2']` and `PS_REQUIRED = Set([CIS,ISO27001,NIST_800-53,STIG])` — STIG tab selectable, shows real percentage + coverage label `STIG coverage: X/Y controls mapped`. `src/TrinetraAuditReportBuilder.java:406` scope note now says `CIS, NIST 800-53, ISO 27001, and STIG are PS-required ... STIG mappings sourced from DISA STIG Viewer ...`. Partial real coverage is honest: STIG gaps reflect applicability, not placeholder.

### 2. User-Selectable Benchmarks (PS: "user-selected benchmarks")

**Gap:** All endpoints computed all frameworks together; ResultsView tabs were display-only filters, no evaluation filter.

**Fix:** 
- **Scorer:** Added `score(String session, Set<String> frameworkFilter)` and `scoreAndWrite(..., Set)` in `src/TrinetraComplianceScorer.java:26-120` — when filter non-null, only selected frameworks accumulate; also ensures selected frameworks appear even with 0 tests (0% + full coverage_gaps) so judge sees honest state. Filter normalizes case/underscore/hyphen (`NIST_800-53` == `nist 800-53`).
- **CLI:** `src/Trinetra.java:60-68` extracts `--frameworks <a,b>` via `extractFrameworkFilter()` and forwards to `handleComplianceScore/Report/AuditReport`. Default null → all frameworks (no breaking change).
- **Bridge:** `bridge/app.py:66-89` added `get_framework_filter()` reading `?frameworks=CIS,STIG` (also `framework`/`benchmarks` aliases); `GET /score`, `/report`, `/audit-report`, `/audit-report/pdf` now honor `?frameworks=`. Default all if omitted. Tests for backward compat still pass.
- **React:** `frontend/src/pages/ResultsView.jsx:8-35` adds checkbox multi-select (default all checked, 1 required), `PS`/`bonus` badges, `frameworksQuery()` builds `?frameworks=` only when subset selected. `load()` passes query to both `/score` and `/audit-report`; PDF link also includes filter. Verified live: selecting `CIS` only yields `{"CIS":...}`; selecting `CIS,STIG` yields two keys (test `test_framework_selection_filtering`).

### 3. Bulk Upload — Single Action, Per-File Status

**Gap:** File input was single `files[0]`, no `multiple`; bridge handled single file; PS says "single or bulk".

**Design choice:** **(a) Sequential single-upload endpoint calls** — reason: reuses proven `POST /upload-config` path (validation, auto-detect, hardware metadata, chain), per-file vendor auto-detect, atomic per-file error visibility, minimal backend risk, and dashboard aggregation (`GET /devices`) already works via sequential devices (confirmed Prompt 23). No new bulk endpoint needed — keeps ingestion semantics identical. Added note in `UploadView.jsx` comment.

**Fix:** `frontend/src/pages/UploadView.jsx` rewritten:
- `files: File[]` state, `<input type="file" multiple>` + `deriveDeviceId(filename)` (strip ext, sanitize).
- `isBulk = files.length > 1` — Device ID field disabled/autoderived in bulk.
- `bulkResults: [{fileName, deviceId, status: pending|uploading|success|error, message, data}]` table with badges.
- Submit: create session once (ignore 409), then `for (f of files) { POST FormData per file }` sequentially, updating per-file row and toasts; success count + fail count visible, not all-or-nothing spinner. Bulk table explains "All bulk devices appear in Session Devices dashboard".
- Tested via `test_bulk_upload_with_hardware_metadata` (2 files sequential → devices dashboard shows 2). Live: drag `cisco-lab-01.txt` + `juniper-lab-01.txt` → Bulk Scan Results table shows per-file pass/fail/unrecognized, Session Devices shows both rows.

### 4. Device Serial / Hardware / OS Version as Distinct Fields

**Gap:** Only opaque `device_id` (free-text) existed; PS requires serial numbers and hardware details as distinct fields.

**Fix:** 
- **Schema:** Added `device_details` map in `src/TrinetraSession.java:757-820` with `setDeviceDetails(session, deviceId, serialNumber, hardwareModel, osVersion)`, `getDeviceDetails`, `getAllDeviceDetails`. Stores `serial_number`, `hardware_model`, `os_version` (all optional free-text, max 128, injection-checked).
- **Ingestor:** Added overload `ingest(..., serialNumber, hardwareModel, osVersion)` `src/TrinetraConfigIngestor.java:100-130`; when caller leaves `osVersion` blank, `detectOsVersion()` header scan populates it.
- **Bridge:** `POST /upload-config` `bridge/app.py:453-532` now reads `serial_number`/`hardware_model`/`os_version` from both multipart form and JSON, validates, passes as `serial_arg`/`hardware_arg`/`os_arg` ("_" placeholder for blank) to `TrinetraBridgeHelper ingest-config`; `GET /devices` now returns `serial_number`, `hardware_model`, `os_version` per device; `BridgeHelper status` also includes `device_details`.
- **React Upload:** Added card "Distinct Hardware Fields (optional, per PS Deliverable 4)" with Serial Number, Hardware Model, OS Version inputs (OS hint: auto-detected from header if blank). In bulk mode same values apply to all files (optional).
- **React Devices:** `frontend/src/pages/SessionDevicesView.jsx:140-175` header now `Device ID | Vendor | Serial | Hardware | OS Version | Ingestion Method | Pass | Fail | Total | Actions`; empty serial shows `—`.
- **Report tables:** `src/TrinetraAuditReportBuilder.java:258-270` per-framework evidence header now `| Device | Vendor | Serial | Hardware | OS Version | Test ID | Verdict | Severity | Timestamp | Controls |` (10-col); combined evidence same without Controls column. Values sourced from `deviceDetails` map per device.
- **PDF:** `bridge/app.py:807-860` metadata now appends `Device X serial/hardware/OS version` rows; evidence table parsed dynamically from markdown header (supports old 5-col fallback + new 10-col) and rendered landscape with severity+s.hardware columns.
- Verified live: upload with `FTX12345678 / C9300-48P / IOS XE 17.6.5` → devices dashboard shows those strings; PDF metadata and evidence table show same; combined markdown contains `| Serial | Hardware | OS Version |`.

### 5. Risk Severity in Primary PDF Evidence Table

**Gap:** Severity computed (`TrinetraStat.default_severity`, `TrinetraAgr.deriveSeverity()`) but not in primary compliance PDF/markdown.

**Fix:** 
- Added `resolveSeverity(testId, entry)` `src/TrinetraAuditReportBuilder.java:575-586` — prefers entry's `default_severity`/`severity`, else looks up `TrinetraStat.getTestDefinition(testId).defaultSeverity`, fallback `medium`.
- Both `renderFrameworkReport` and `renderCombinedReport` evidence tables now include `Severity` column (between Verdict and Timestamp) with `resolveSeverity` per row. Test `test_severity_in_report_and_pdf` asserts `Severity` header and severity values (`medium` etc.) present in combined markdown.
- **PDF:** `bridge/app.py:880-910` evidence header dynamically includes Severity; fallback old 5-col path preserved. PDF table now 9-col landscape (Device+Serial+Hardware+OS+Test+Verdict+Severity+Timestamp). Severity test asserts PDF text layer contains `Severity` and `medium`.

### 6. Step-by-Step CLI Remediation Formatting

**Gap:** Remediation strings were single-paragraph hints, not numbered sequences where fix requires multiple CLI invocations.

**Fix:** Reformatted remediation to numbered step-by-step sequences (not new research, just structuring correct commands per vendor docs, command order verified):
- `bridge/app.py:902-911` `remediation_map` now for each V-code: `1. configure terminal. 2. ... 3. ... 4. verify ... 5. write memory.` HTML `<font face="Courier">` for commands.
- `src/TrinetraAgr.java:32-44` `REMEDIATION` map similarly reformatted, e.g. V-071: `1. configure terminal. 2. line vty 0 4 → no transport input telnet → transport input ssh. 3. no ip http server. 4. exec-timeout 5 0 → logging synchronous. 5. end → write memory.` V-003, V-006, V-007, V-008, V-013, V-057, V-058, V-087 similarly.
- **Before/after example (V-071):**
  - *Before:* `Disable insecure mgmt: no transport input telnet, no ip http server, set exec-timeout 5 0. (Documented)`
  - *After:* `1. configure terminal. 2. Harden vty: line vty 0 4 → no transport input telnet → transport input ssh. 3. Disable HTTP: no ip http server. 4. Set idle timeout: line vty 0 4 → exec-timeout 5 0 → logging synchronous. 5. end → write memory. (Documented)`
- PDF remediation section `bridge/app.py:915-945` extracts `verdict` index dynamically and renders remediations with HTML bold.

### 7. Generic Framework Display-Name Fallback (removes hardcoded-switch dependency)

**Gap:** `displayName()` and `practicalImpact()` switches hardcoded CIS/ISO/NIST/PCI/SOC2 — new manifest framework would need Java change.

**Fix:** 
- `src/TrinetraAuditReportBuilder.java:575` `displayName` now has explicit cases for known plus `STIG` plus generic fallback: `fw.replace("_"," ").replace("-"," ").trim()` → Title Case words, uppercase for known acronyms (STIG/CIS/NIST etc.), so `HIPAA-TEST_FRAMEWORK` → `Hipaa Test Framework` with zero code change.
- `src/TrinetraNarrativeGenerator.java:515` `practicalImpact` now switch with `STIG` case plus generic fallback that title-cases framework key: `"the associated <Readable> controls remain at risk ..."` — any new framework produces clean prose. Verified: hypothetical `HIPAA` yields `Hipaa` heading without code change (manual check via `displayName("HIPAA-COMPLIANCE") → "Hipaa Compliance"`).

### 8. OS-Version Metadata (bounded partial move)

**Gap:** Vendor flat, no OS-version axis.

**Fix (metadata-level awareness, not parsing branch — stated honestly):**
- Added `os_version` to `VendorTrainingMap.Entry` `src/VendorTrainingMap.java:20-35` (optional field, persisted to `vendor_training_map.json`), bridge train handler `bridge/app.py:690,742` accepts `os_version`.
- TrainingView `frontend/src/pages/TrainingView.jsx:20,45,105` adds `osVersionTrain` input (`IOS XE 17.6.5` etc.) stored per training entry.
- `TrinetraConfigIngestor.detectOsVersion()` `src/TrinetraConfigIngestor.java:320-350` scans first 4000 chars for `IOS XE`, `NX-OS`/`Nexus`, `JUNOS`/`Juniper`, `Cisco IOS Software`, extracts `Version 17.6.5` etc., returns `IOS XE 17.6.5`, `NX-OS 9.3(9)`, `JUNOS 20.4R3` etc. When ingest receives blank `os_version`, detected value is stored; when caller supplies explicit `os_version`, it wins. Sample configs `demo/sample_configs/cisco-lab-01.txt` now contains `! Cisco IOS XE Software, Version 17.6.5` and `demo/sample_configs/juniper-lab-01.txt` contains `/* JUNOS 20.4R3-S2.4 */` so demo shows detection live.
- **Pitch honesty:** detection is header-scan only; core parser does NOT branch on OS version — noted in code comment and in report note. Full IOS vs IOS-XE vs NX-OS parsing branches explicitly out of scope this prompt.

## 9. Live-Fetch — Auto-Sourced Config Ingestion (this prompt, additive, no new parsing path)

**What was gap:** Only file-upload ingestion existed; judges asked for a way to supply IP/URL instead of a file while still using the same compliance pipeline (not a second scanning system).

**Design decision — which module holds fetch logic and why:**
- **Module:** `bridge/live_fetcher.py` — Python bridge layer. Contains vendor-specific configuration commands, strict SSH `known_hosts` verification, password or in-memory PEM authentication, public-address URL validation on every redirect, HTTPS downgrade prevention, cross-origin credential stripping, timeouts, and a 1 MB response cap. Server-side key paths and automatically trusted host keys are intentionally rejected.
- **Why Python bridge layer, not Java:** (1) Keeps fetch isolated from ingestion/parsing core (Java) — clearly separable, single-responsibility. (2) Reuses existing Python deps `paramiko` + `requests` without adding Java deps (JSch). (3) Credential handling stays in short-lived Python request scope, never crosses to Java persistence layer; Java core remains pure config-text → parsing → scoring → reporting. (4) Matches existing bridge → Java helper pattern (`TrinetraBridgeHelper` shells out to Java).

**Shared pipeline — no duplication (cite exact shared function):**
- Both entry points call **`TrinetraConfigIngestor.ingest(session, deviceId, vendorHint, configContent, filename, serialNumber, hardwareModel, osVersion, ingestionMethod)`** in `src/TrinetraConfigIngestor.java:117` (overload at :101/:110 delegates with default `config_upload`). Java core deduplicates: `autoDetectVendor` + `VendorConnectorRegistry.resolve` + `KNOWN_PATTERNS` + `VendorTrainingMap.findMatch` + `TrinetraStat.DecisionEngine.evaluate` + hash-chain append — same for both.
- Bridge endpoint `bridge/app.py:551` `POST /api/session/<name>/fetch-config` fetches raw text via `live_fetcher.fetch_config` (returns string, no parsing), writes to temp file, then calls the **same** `TrinetraBridgeHelper:ingest-config` Java helper with extra arg `live_fetch` (`src/TrinetraBridgeHelper.java:137` now `ingest-config ... [ingestion_method]`). The helper forwards to `TrinetraConfigIngestor.ingest(..., "live_fetch")`, which stores `device_ingestion` as `live_fetch` and tags each `normalized_results` + `findings` entry. Former `ingest(..., "config_upload")` path unchanged.
- **Verification:** Mocked test `bridge/tests/test_live_fetch.py:test_fetch_via_ip_uses_same_ingestion_as_file_upload` fetches `SAMPLE_CONFIG` via mocked SSH, then uploads same text via `/upload-config` in a second session — asserts `total_checks`, `passed`, `failed`, `unrecognized_lines`, and `normalized_results` `test_id→verdict` maps are identical, but `ingestion_method` differs (`live_fetch` vs `config_upload`). This proves no fork.

**New endpoint — request/response shape:**
- `POST /api/session/<name>/fetch-config` (404 if session not found)
  - **Request JSON:** `source_type` (`"ip"` or `"url"` required), `target`, `device_id`, optional `vendor`/hardware metadata, plus `username` and a `password` or pasted PEM `ssh_key` for SSH, or optional `auth_token`/`auth_header` for URL collection.
  - **Success 200 JSON:** same compliance summary as `upload-config`, plus `ingestion_method: "live_fetch"`, `source_type`, `target`, and `config_filename` (`<device_id>_live_fetch.txt`).
  - **Errors:** 400 validation (injection/length/format), 404 session not found, 502 fetch failed (unreachable/auth/timeout — never leaks credential).

**Credential handling — verification results:**
- **Never persisted:** Unit check in `test_fetch_via_ip_uses_same_ingestion_as_file_upload` reads `sessions/<sess>/<sess>.json` + `brain_state_<sess>.json` raw text and asserts `SuperSecret123!` absent; URL test asserts `BearerToken123_mocked` absent; failure path asserts `UltraSecret999!` not in error JSON nor session file.
- **Masked in UI:** `frontend/src/pages/UploadView.jsx` uses password controls and masked PEM text with explicit Show/Hide actions. Sensitive state is cleared after successful collection or when leaving live-fetch mode.
- **No log leakage:** `bridge/live_fetcher.py` docstring and `bridge/app.py:fetch-config` comment explicitly forbid logging credentials; error path sanitizes exception string and never interpolates password/token into `error_response`. Grep verification post-test: `grep -R SuperSecret sessions/` → no hits outside test source; `grep -r BearerToken sessions/` → no hits; git-tracked `bridge/app.py` contains no `log.*password` in plaintext; `grep logs/session JSON/git-tracked` for `password` only finds policy findings and docstrings, zero credential values.
- **Local proxy:** Requests go through existing Vite proxy `frontend/vite.config.js:/api → :5000`; no new exposed surface, no extra CORS or public endpoint.

**React UI — changes:**
- `frontend/src/pages/UploadView.jsx` adds a third `fetch` mode alongside file upload (primary) and pasted text. It provides SSH/HTTPS source switching, labeled and masked credentials, client-side format/length validation, a 45-second request timeout, and the same results flow used by file ingestion—without adding a separate downstream UI.

## React Frontend (Prompt 22 + 23 + this prompt)

**Vite + React 18 app** in `frontend/` with 5 views now upgraded:
- **Upload** — bulk `multiple` file input, per-file derived device_id, per-file status table (pending/uploading/success/error), vendor auto-detect, distinct hardware fields (Serial/Hardware/OS), 60s timeout per file, OS auto-detect hint. **Now also** fetch mode: IP (SSH — `show running-config`/`display set`/generic) + URL (HTTP GET + Bearer token), masked credential inputs, network-reachability note, same results flow.
- **Results** — framework multi-select checkboxes (default all, ≥1 required) that filter `GET /score?frameworks=` and `GET /audit-report?frameworks=` and PDF link; STIG now real tab with coverage label; progress bars; remediation step-by-step visible in PDF. Fetch-sourced devices appear identically.
- **Training** — now includes OS Version field per entry, stored with training map.
- **Session Devices** — now 10-col table with Serial/Hardware/OS Version distinct columns, vendor badge, ingestion method (`config_upload` vs `live_fetch` vs `live_target`), pass/fail, compliance bars. Live-fetch devices show `live_fetch` badge honestly.
- **Dashboard/System** — unchanged, hardened.

**Vite dev server** proxies `/api` to Flask bridge (no new surface).

## Verification

**Java:** `make compile` → Build successful. `make test-java` → 11 suites all pass (now includes `ingestion_method` preservation in `normalized_results` and `tool` on UNRECOGNIZED finding for doctor clean). Sample evidence row still `| 10.10.1.10 | Cisco |  |  |  | T-CISCO | pass | medium | ... |`.

**Python:** `python3 -m pytest bridge/tests -q` → **30 passed**. This includes 4 mocked live-fetch/security tests covering shared ingestion results, provenance persistence, private-URL rejection, server-side key-path rejection, and credential-safe failures. No claim of a real external device connection is made.

**Doctor:** `trinetra -doctor` → 124 definitions, `All sessions valid`, AI integration Gemini CLI installed, GEMINI_API_KEY set, OpenRouter key set, `Chain Status: INTACT`.

**Frontend build:** `cd frontend && npm run build` → ✓ 41 modules transformed, built in ~823ms, no errors.

**Scope-hygiene:** `grep -R sqli|sqlmap|xssstrike|commix|nikto` on `frontend/src/ bridge/app.py src/` → only `sqlite` false positive.

**Credential leakage grep (explicit):**
- `grep -R SuperSecret sessions/ | grep -v test_live_fetch` → 0 hits
- `grep -R BearerToken sessions/` → 0 hits
- `grep sessions/<sess>/<sess>.json` for `password` value after live-fetch test → 0 hits (only policy finding text)
- `grep bridge/app.py` for log of password → docstring only, no `logger.info(password)`
- Response JSON after fetch never contains credential (asserted in tests).

**Integration checks (via Flask test client, mocked fetch):**
- `POST /fetch-config ip 10.0.0.1 + password` → 200 `live_fetch`, `GET /devices` shows `live_fetch`, `GET /status` `device_ingestion[dev].method == live_fetch`, `brain_state normalized_results` `ingestion_method: live_fetch`, PDF contains device.
- `POST /fetch-config url https://api.example.com/config + BearerToken` → same, no token in stored JSON.
- Same `SAMPLE_CONFIG` via fetch vs file → `total_checks/passed/failed/unrecognized` identical, `normalized_results` verdicts identical, only method differs — proves same pipeline.

## Git Tracking

`config/vendor_training_map.json` tracked. Runtime `sessions/*` gitignored (now also `sessions/tmp_*/` + `sessions/live_fetch_*/`). `frontend/node_modules/` and `frontend/dist/` gitignored. `brain_state.json` runtime not committed.

## Files Created/Modified in this Commit

Created: `bridge/live_fetcher.py` (TrinetraLiveFetcher — thin retrieval, no parsing, why Python bridge layer), `bridge/tests/test_live_fetch.py` (4 mocked tests — fetch→same ingest pipeline + credential non-persistence).

Modified: `config/compliance_manifest.json` (STIG — unchanged this prompt), `src/TrinetraConfigIngestor.java` (add `ingest(..., ingestionMethod)` overload `117`, `methodTag` handling `124`, `ingestion_method` on findings/normalized `265/298/315`, return `methodTag`; `UNRECOGNIZED` now includes `tool` for doctor; `normalized_results` now preserves `ingestion_method`), `src/TrinetraSession.java` (`doAppendNormalizedResult` now preserves `ingestion_method` for hash chain), `src/TrinetraBridgeHelper.java` (`ingest-config ... [ingestion_method]` `139`, forwards `live_fetch`), `src/Trinetra.java`/`TrinetraComplianceScorer.java`/reports — unchanged this prompt except compile remains clean, `bridge/app.py` (add `POST /fetch-config` `551` — validates, calls live_fetcher, then same `ingest-config … live_fetch`, never persists credentials), `bridge/requirements.txt` (add `paramiko` for SSH fetch), `frontend/src/pages/UploadView.jsx` (add third mode `fetch` — `fetchSourceType`/`fetchTarget`/masked credentials, `type=password`, network note, same results flow; file upload stays primary), `.gitignore` (ignore `tmp_*`, `live_fetch_*`), `README.md` (add fetch as optional additive §3 + architecture table + API + limitations), `RESUME_POINT.md` (this section + §9).

## Out of Scope (explicitly not done this prompt)

Full OS-version-aware parsing branches (IOS vs IOS-XE vs NX-OS producing different normalization logic) — too large, requires re-architecture; current is metadata-level header scan only, honestly noted. NCIIPC dataset acquisition/validation — not code, team to check nciipc.gov.in separately. No parallel live-scanning/fingerprinting system — fetch is thin retrieval only, intentionally not Iskabon-style probing.

## Next Planned Prompt

Consider: full OS-version parsing branches if time allows, production `frontend/dist` serve via Flask (`/app` static), accessibility audit, or Palo Alto/Fortinet vendor connectors.
