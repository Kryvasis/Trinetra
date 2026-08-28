# Resume Point

**Baseline commit:** `a9477f9` on `origin/main`
(Baseline: PS26155 alignment — config-upload ingestion, vendor training loop, CIS mapping verified (Prompt 21))

## Proven working end-to-end as of this commit

Full pipeline verified: Iskabon fingerprinting → per-device `device_vendors` + `VendorConnectorRegistry` (Cisco/Juniper) → hash-chained `normalized_results` (no cross-vendor leakage, verified via `multi_vendor_e2e` trap `T-SHARED` Cisco PASS + Juniper FAIL as distinct links, `verifyChain()` INTACT) → deterministic scorer (ISO 66.7/SOC2 33.3 etc.) → validated Gemini narratives → audit reports with per-device evidence rows and derived aggregate 50.0% labeled derived.

**Config-upload primary path (PS26155):** `POST /api/session/<name>/upload-config` → `TrinetraConfigIngestor.ingest()` → same `VendorConnector.normalizeCommand` + `VendorConnectorRegistry.resolve` logic as live-target path → `TrinetraStat.DecisionEngine.evaluate` on file content → findings + `normalized_results` appended with `ingestion_method: config_upload` → chain intact. Unrecognized lines tracked per-device via `TrinetraSession.setUnrecognizedLines()`.

**Vendor training loop proven:** Upload config → line flagged unrecognized → `POST /train` adds entry to `config/vendor_training_map.json` → re-upload same config → line now recognized → zero `.java` file changes between train and re-parse. `VendorTrainingMap.java` mtime-cache mechanism verified: cache reloads on file mtime change without process restart.

**CIS framework mappings verified:** 12 V-codes mapped to real CIS benchmark control IDs (CIS-v8-4.6, CIS-v8-3.10, CIS-IOS-1.1.1, CIS-IOS-XE-1.2.6, CIS-NX-OS-1.4.6, etc.). No fabricated control IDs.

**STIG discrepancy resolved:** False STIG compliance coverage claims removed from report builder (`TrinetraAuditReportBuilder.java:387`), PDF footer (`bridge/app.py:796`), and HTML UI (`bridge/app.py:954`). STIG has zero mappings in the compliance manifest and is never computed by the scorer. Report text now honestly claims only CIS, NIST 800-53, and ISO 27001 as PS-required. README updated to note STIG cert mode is a placeholder.

**PDF export verified:** ReportLab-generated PDF with valid header, device_id in evidence rows, PCI-DSS/SOC2 bonus coverage note, remediation section with documented/AI-suggested labeling, STIG-free.

**Remediation-sourcing precedence:** Documented remediations (V-003, V-006, V-007, V-008, V-013, V-057, V-058, V-071) display without "AI-suggested" label. Unknown V-codes fall back with "AI-suggested — verify before use" label. Regression test confirms V-070 (undocumented) triggers AI-suggested path, while V-057 (documented) uses documented text.

**Fail-verdict regression test (Item 2):** `bridge/tests/test_fail_remediation.py` exercises the AI-suggested remediation path end-to-end: creates session, uploads config, injects FAIL finding for V-070 (undocumented V-code in compliance manifest but NOT in bridge's remediation_map), generates audit report + PDF, verifies the FAIL appears in evidence table. Also tests control case: documented V-057 uses documented remediation, not AI-suggested.

**React frontend (Prompt 22):** Vite + React 18 app in `frontend/` with 4 views:
- **Upload view** — file/paste config upload, vendor auto-detect, session creation, processing state, scan results with pass/fail/unrecognized counts
- **Results/score view** — per-framework compliance scores with progress bars, test result tables, framework tabs, PCI-DSS/SOC2 "bonus coverage" badges, AI-suggested remediation labels preserved exactly as bridge flags them
- **Training view** — unrecognized lines list with click-to-select, labeling form (vendor, regex pattern, security category, control mapping, remediation), before/after count
- **Dashboard view** — trinetra -doctor health check, session list, AI integration status

Vite dev server proxies `/api` to Flask bridge at port 5000 (no CORS issues, no bridge changes needed). Flask HTML pages kept in place but unlinked from React nav.

**STIG placeholder in React UI:** STIG shown as disabled tab with "(coming soon)" tooltip. Never selectable, never claims coverage. Consistent with Flask HTML fallback.

**Multi-device dashboard (stretch, Item 4):** Landed in Dashboard view — shows system health, session list with click-through to results.

**Scope-hygiene sweep:** All offensive-tool references (sqli, sqlmap, xsstrike, commix, nikto, nmap) are in legacy/backup directories (`stat_scripts_backup_*`, `backup_removal_*`) or historical session data only. React frontend code has zero offensive-tool terminology.

**Minimal upload GUI:** Plain HTML/JS at `/`, `/ui`, `/upload` — session creation, config upload, training form, unrecognized-line labeling, audit report + PDF download. Unlinked from React nav but not deleted.

**Git tracking:** `config/vendor_training_map.json` tracked (not gitignored). Runtime session/report artifacts remain gitignored. `frontend/node_modules/` and `frontend/dist/` gitignored.

**Test results:** Java 11 suites all pass (`make test-java`), Python 17 tests pass (15 bridge + 2 fail-remediation regression), `trinetra -doctor` shows 124 definitions, clean state.

## Files changed in this commit

New: `frontend/` (Vite React app: `package.json`, `vite.config.js`, `index.html`, `src/main.jsx`, `src/App.jsx`, `src/index.css`, `src/components/Toast.jsx`, `src/components/Spinner.jsx`, `src/pages/UploadView.jsx`, `src/pages/ResultsView.jsx`, `src/pages/TrainingView.jsx`, `src/pages/DashboardView.jsx`, `public/vite.svg`), `bridge/tests/test_fail_remediation.py`
Modified: `.gitignore` (added `frontend/node_modules/`, `frontend/dist/`)

## Next planned prompt

Prompt 23 — consider: additional vendor connector patterns (Palo Alto, Fortinet), expanded CIS/NIST mappings, compliance-report PDF improvements, production build/serve configuration, or accessibility audit.
