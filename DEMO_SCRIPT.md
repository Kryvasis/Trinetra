# Trinetra Demo Script — Judge-Facing Walkthrough

**Estimated time:** 8–10 minutes  
**Pre-requisites:** Bridge running (`python3 -m bridge.app`), React dev server running (`cd frontend && npm run dev`), `make compile` done.

---

## Setup (do before judges arrive)

```bash
cd /home/kali/Desktop/Trinetra
make compile                      # ensure Java is built
python3 -m bridge.app &           # start Flask bridge on :5000
cd frontend && npm run dev &      # start React dev server on :5173
```

Open **http://localhost:5173** in the browser.

---

## Step 1 — Upload a Device Config (1.5 min)

1. Click **Upload** in the nav bar.
2. Fill in:
   - **Session Name:** `demo-judge`
   - **Device ID:** `cisco-lab-01` *(ignored in bulk — derived from filename, see step 1b)*
   - **Vendor:** Auto-detect
3. In the **Distinct Hardware Fields** card (optional, per PS Deliverable 4), fill:
   - **Serial Number:** `FTX999`
   - **Hardware Model:** `C9300`
   - **OS Version:** `IOS XE 17.6.5` — *or leave blank: the system auto-detects OS version from the config header (`Cisco IOS XE Software, Version 17.6.5` in `cisco-lab-01.txt`; `JUNOS 20.4R3-S2.4` in `juniper-lab-01.txt`) and stores it as a distinct `os_version` field visible in every report.*
4. Under **Config File(s) — bulk supported**, click **File Upload**, select `demo/sample_configs/cisco-lab-01.txt`.
5. Click **Run Compliance Scan**.
6. **Show:** Processing spinner appears, then scan results card shows pass/fail/unrecognized counts.

**What to say:** *"Trinetra ingests the config file, parses each line against known vendor patterns, and runs compliance checks using our deterministic decision engine — no live SSH required. Hardware/OS fields are distinct columns, not folded into device_id, and OS auto-detects from the banner if you leave it blank."*

## Step 1b — Bulk Upload (1 min) — per-file status, same session

1. Keep **Session Name:** `demo-judge` (same session accumulates devices).
2. Under **Config File(s)**, click **File Upload** again and **select multiple files** in one action: `demo/sample_configs/cisco-lab-01.txt` + `demo/sample_configs/juniper-lab-01.txt` (or use Ctrl/Cmd-click). The helper text confirms `Bulk mode: 2 devices, each filename → device ID`.
3. Click **Run Bulk Compliance Scan (2 files)**.
4. **Show:** The **Bulk Scan Results (per-file)** table appears below the form and updates live: each row `File / Device` shows `pending → uploading` (spinner) `→ success` (`3 passed, 0 failed, 1 unrecognized`) or `failed`. This is the sequential-bucket upload reusing the proven single-file endpoint (`bridge/app.py:450`, `UploadView.jsx:119`).
5. Click **View Session Devices** → verify 2 rows `cisco-lab-01` / `juniper-lab-01` each with Vendor, Ingestion `config_upload`, `Hardware/OS` columns.

**What to say:** *"Bulk is one click — each filename becomes a device ID, each file gets its own Vendor auto-detect and chain entry, all in the same session. Per-file badges make failures obvious without losing the session."*

## Step 1c — Live Collection (Optional, 1 min) — same pipeline, tagged `live_fetch`

*This step is additive — you can skip it and the file-upload demo is complete. It proves the “unified ingestion” claim that live-fetch shares the identical scoring path.*

1. Stay on **Upload**, switch **Input method** to **Collect from Network** (third mode, additive — file upload remains primary per `README.md:72`).
2. Choose **SSH device** (`IP`):
   - **IP/hostname:** `10.0.0.1` (or any lab device you control; `127.0.0.1` is blocked by SSRF policy and will show `collection target rejected`)
   - **Username:** `admin` / **Password:** `••••` (or paste PEM key; credentials are masked, never persisted — see `bridge/live_fetcher.py:84` `RejectPolicy`)
   - **Device ID:** `live-01` / **Vendor:** Auto-detect
   - Or choose **Configuration URL** (`URL`): `https://example.com/config` with optional `Authorization: Bearer …` (requires `https`, private RFC1918 URLs like `http://10.0.0.1/` are blocked → `400`)
3. Click **Collect & Scan**.
4. **Show:** Same **Scan Results** card (`passed/failed/unrecognized`) and same **Session Devices** row, but `Ingestion` now shows `live_fetch` (`bridge/app.py:551` → same `TrinetraConfigIngestor.ingest(..., live_fetch)` `src/TrinetraConfigIngestor.java:118`, `src/TrinetraSession.java:771` `device_ingestion`).
5. Click **View Session Devices** → verify `live-01 | Cisco | live_fetch` vs `cisco-lab-01 | Cisco | config_upload` in the same session; **Download PDF** and **Results** both include the live device with identical evidence columns plus `Ingestion` column.

**What to say:** *“Same pipeline — file or live, it’s one `ingest` function. Live is thin retrieval only: SSH `known_hosts` strict, URL blocks private/SSRF and strips creds on redirect (`bridge/live_fetcher.py:136`), 1 MB cap. Credentials exist for one request and never touch disk or the report.”*

---

## Step 2 — View Results & Framework Scores (2 min)

1. Click **View Detailed Results** (or navigate to Results, type `demo-judge`, click Load). Keep the **Benchmarks to evaluate** checkboxes at default **all six** — `CIS`, `ISO27001`, `NIST 800-53`, `STIG` (PS-required, blue `PS` badge) + `PCI-DSS`, `SOC2` (bonus, grey `bonus` badge) — or uncheck to filter `?frameworks=` live.
2. **Show:** Overall score cards — **CIS, NIST 800-53, ISO 27001 *and* STIG** percentages (all four PS-required), plus bonus PCI-DSS/SOC2.
3. Click through framework tabs `CIS → NIST 800-53 → ISO 27001 → STIG` (then `PCI-DSS`/`SOC2` bonus). The STIG tab is **enabled**: header shows `CIS/NIST/ISO/STIG` per-framework `compliance_percentage` from `TrinetraComplianceScorer.java:41` against `config/compliance_manifest.json` (source note DisA STIG Viewer V2R5/V2R4).
4. In the STIG card, point out `STIG coverage: 3/7 controls mapped` (example) and the controls list `CISC-ND-000015`, `JUSX-ND-000015` etc. — real DISA Group IDs, not fabricated. Note the honest gap: **14 of 15 V-codes have STIG mappings; `V-106` (Public cloud storage `aws s3api`) has no NDM STIG control, so it appears in `coverage_gaps` — genuine, not an oversight** (`_STIG_source_note` in manifest).
5. **Show:** PCI-DSS and SOC2 tabs have **Bonus Coverage** badges (bonus/additional only, not PS-required).
6. **Show:** Test result table with pass/fail badges and remediation text. If any V-code shows "AI-suggested — verify before use", point it out: *"For undocumented patterns, the system generates AI-suggested remediation, clearly labeled so auditors know to verify."*
7. Demo filtering: uncheck all but `CIS`, click **Load Results** → stat cards + `Frameworks scored: 1` show only CIS; re-check `STIG` → `?frameworks=CIS,STIG` shows two cards. The same `?frameworks=` filters the PDF download link.

**What to say:** *"Results are scored per-framework against the compliance manifest — CIS, NIST, ISO27001, and STIG are all live from real DISA Group IDs. V-106 cloud S3 honestly has no NDM control, so it stays in the gaps instead of faking a mapping. Every remediation is sourced from documented hardening guides where available, and PCI-DSS/SOC2 are bonus coverage only."*

---

## Step 3 — Show the Unrecognized Line (1 min)

1. Click **Training** in the nav bar.
2. Type `demo-judge` and click **Load Unrecognized Lines**.
3. **Show:** The unrecognized line `custom-vendor-feature enable zone-trust` appears in the list with the device label `cisco-lab-01`.

**What to say:** *"Trinetra flagged this line as unrecognized — it's a vendor-specific command not in our pattern database. Instead of discarding it, we let the operator teach the system."*

---

## Step 4 — Train the Unrecognized Line Live (2 min)

1. Click the unrecognized line to select it.
2. The form auto-fills with a regex pattern. Fill in:
   - **Vendor:** Cisco
   - **Security Category:** `Vendor-Specific Hardening`
   - **Control Mapping:** `CIS-v8-4.6`
   - **Remediation:** `Enable zone-trust for vendor-specific hardening`
3. Click **Add Training Entry**.
4. **Show:** Toast "Training entry added", before/after count drops by 1.
5. Navigate back to **Upload**, re-upload the same `cisco-lab-01.txt` config to the same session.
6. **Show:** Unrecognized count is now 0 — the line is recognized.

**What to say:** *"Zero Java code changes. The training entry is stored in a JSON file and takes effect immediately on re-upload. This is how we teach Trinetra new vendor patterns without redeployment."*

---

## Step 5 — Multi-Device Session Dashboard (1 min)

1. Click **Devices** in the nav bar.
2. Type `demo-judge` and click **Load Devices**.
3. **Show:** Device table with `cisco-lab-01`, vendor "Cisco", ingestion method "Config Upload", pass/fail counts, and per-device compliance progress bars.
4. If you uploaded a second device (juniper-lab-01), show both rows.

**What to say:** *"For fleet audits, Trinetra tracks every device independently — ingestion method, vendor, and per-device compliance scores — giving a unified view across a multi-vendor network."*

---

## Step 6 — Download PDF Report (1 min)

1. Click **Results** in the nav, load `demo-judge`.
2. Click **Download PDF Report** (or the filtered `Download PDF Report (CIS,STIG)` link if you demoed filtering).
3. **Show:** PDF opens in new tab (ReportLab `landscape(letter)` `bridge/app.py:786`) with:
   - Session metadata (name, target, timestamp)
   - Per-framework compliance tables (respects the `?frameworks=` filter if used)
   - Evidence rows with **distinct columns** `Device | Vendor | Serial | Hardware | OS Version | Ingestion | Test ID | Verdict | Severity | Timestamp | Controls` — e.g., `cisco-lab-01 | Cisco | FTX999 | C9300 | IOS XE 17.6.5 | config_upload | V-013 | pass | medium | ...` (`live_fetch` for Step 1c devices, not folded into `device_id`)
   - Remediation section with **numbered step-by-step CLI sequences** `1. configure terminal … 5. write memory` (`bridge/app.py:990` 15 V-codes, `V-106` uses `aws s3api`) and documented/AI-suggested labels
   - Bonus coverage note for PCI-DSS/SOC2 (PS-required are CIS/NIST/ISO27001/STIG) + honest STIG 14/15 note
   - Tamper-evidence chain status `INTACT (N links)` / `BROKEN at index`

**What to say:** *"The PDF is generated server-side from the audit report builder — landscape for the 10-col evidence table, Serial/Hardware/OS/Severity as their own columns. Every figure is machine-validated against the scorer — no LLM hallucinated numbers."*

---

## Step 7 — System Health (30 sec)

1. Click **System** in the nav bar.
2. Click **Run trinetra -doctor**.
3. **Show:** Test definition count (124), session validation status, AI integration status.

**What to say:** *"The doctor command validates the entire pipeline — test definitions, session integrity, and AI connectivity — in one shot."*

---

## Known Rough Edges (avoid during live demo)

- **Empty config upload:** The bridge returns a clear error, but the React UI shows it as a toast. Don't upload an empty file.
- **Session name conflicts:** If the session already exists, the upload silently continues (409 is handled). This is fine — don't re-create sessions mid-demo.
- **Bridge timeout:** Config ingestion can take 10–30 seconds for large configs. The spinner handles this, but avoid uploading very large files (>1000 lines) during the demo.
- **Flask fallback at :5000:** If a judge navigates to `localhost:5000` directly, they'll see the plain HTML page. This is the working fallback — not broken, just unbranded.

---

## Quick Recovery

If anything goes wrong:
1. **React page won't load:** Fall back to `localhost:5000` (Flask HTML page).
2. **Bridge down:** `python3 -m bridge.app` from project root.
3. **Java not compiled:** `make compile` from project root.
4. **Session corrupted:** `rm -rf sessions/demo-judge` and start from Step 1.

---

## Sample Configs

Located in `demo/sample_configs/`:
- `cisco-lab-01.txt` — Cisco IOS config with intentional unrecognized line for training demo
- `juniper-lab-01.txt` — Juniper JunOS config for multi-device demo

Both are realistic network device configs with intentional security weaknesses (weak SNMP community strings, etc.) to trigger compliance findings.
