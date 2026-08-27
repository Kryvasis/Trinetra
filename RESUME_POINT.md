# Resume Point

**Baseline commit:** `eb8b8a6` on `origin/main`
(Baseline: PS26155 alignment — config-upload ingestion, vendor training loop, CIS mapping verified (Prompt 21))

## Proven working end-to-end as of this commit

Full pipeline verified: Iskabon fingerprinting → per-device `device_vendors` + `VendorConnectorRegistry` (Cisco/Juniper) → hash-chained `normalized_results` (no cross-vendor leakage, verified via `multi_vendor_e2e` trap `T-SHARED` Cisco PASS + Juniper FAIL as distinct links, `verifyChain()` INTACT) → deterministic scorer (ISO 66.7/SOC2 33.3 etc.) → validated Gemini narratives → audit reports with per-device evidence rows and derived aggregate 50.0% labeled derived.

**Config-upload primary path (PS26155):** `POST /api/session/<name>/upload-config` → `TrinetraConfigIngestor.ingest()` → same `VendorConnector.normalizeCommand` + `VendorConnectorRegistry.resolve` logic as live-target path → `TrinetraStat.DecisionEngine.evaluate` on file content → findings + `normalized_results` appended with `ingestion_method: config_upload` → chain intact. Unrecognized lines tracked per-device via `TrinetraSession.setUnrecognizedLines()`.

**Vendor training loop proven:** Upload config → line flagged unrecognized → `POST /train` adds entry to `config/vendor_training_map.json` → re-upload same config → line now recognized → zero `.java` file changes between train and re-parse. `VendorTrainingMap.java` mtime-cache mechanism verified: cache reloads on file mtime change without process restart.

**CIS framework mappings verified:** 12 V-codes mapped to real CIS benchmark control IDs (CIS-v8-4.6, CIS-v8-3.10, CIS-IOS-1.1.1, CIS-IOS-XE-1.2.6, CIS-NX-OS-1.4.6, etc.). No fabricated control IDs.

**STIG discrepancy resolved:** False STIG compliance coverage claims removed from report builder (`TrinetraAuditReportBuilder.java:387`), PDF footer (`bridge/app.py:796`), and HTML UI (`bridge/app.py:954`). STIG has zero mappings in the compliance manifest and is never computed by the scorer. Report text now honestly claims only CIS, NIST 800-53, and ISO 27001 as PS-required. README updated to note STIG cert mode is a placeholder.

**PDF export verified:** ReportLab-generated PDF with valid header, device_id in evidence rows, PCI-DSS/SOC2 bonus coverage note, remediation section with documented/AI-suggested labeling, STIG-free.

**Remediation-sourcing precedence:** Documented remediations (V-003, V-006, V-007, V-008, V-013, V-057, V-058, V-071) display without "AI-suggested" label. Unknown V-codes fall back with "AI-suggested — verify before use" label.

**Scope-hygiene sweep:** All offensive-tool references (sqli, sqlmap, xsstrike, commix, nikto, nmap) are in legacy/backup directories (`stat_scripts_backup_*`, `backup_removal_*`) or historical session data only. No live/active references.

**Minimal upload GUI:** Plain HTML/JS at `/`, `/ui`, `/upload` — session creation, config upload, training form, unrecognized-line labeling, audit report + PDF download.

**Git tracking:** `config/vendor_training_map.json` tracked (not gitignored). Runtime session/report artifacts remain gitignored.

**Test results:** Java 11 suites all pass (`make test-java`), Python 15 tests pass (14 bridge + 1 training loop), `trinetra -doctor` shows 124 definitions, clean state.

## Files changed in this baseline

New: `src/TrinetraConfigIngestor.java`, `src/VendorTrainingMap.java`, `config/vendor_training_map.json`, `bridge/tests/test_training_loop.py`
Modified: `bridge/app.py`, `bridge/README.md`, `config/compliance_manifest.json`, `schema.md`, `src/TrinetraAuditReportBuilder.java`, `src/TrinetraBridgeHelper.java`, `src/TrinetraSession.java`, `src/TrinetraStat.java`, `README.md`

## Next planned prompt

Prompt 22 — consider: React upload UI (replace minimal HTML), additional vendor connector patterns, expanded CIS/NIST mappings, or compliance-report PDF improvements.
