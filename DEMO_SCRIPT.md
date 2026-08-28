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

## Step 1 — Upload a Device Config (1 min)

1. Click **Upload** in the nav bar.
2. Fill in:
   - **Session Name:** `demo-judge`
   - **Device ID:** `cisco-lab-01`
   - **Vendor:** Auto-detect
3. Click **File Upload**, select `demo/sample_configs/cisco-lab-01.txt`.
4. Click **Run Compliance Scan**.
5. **Show:** Processing spinner appears, then scan results card shows pass/fail/unrecognized counts.

**What to say:** *"Trinetra ingests the config file, parses each line against known vendor patterns, and runs compliance checks using our deterministic decision engine — no live SSH required."*

---

## Step 2 — View Results & Framework Scores (2 min)

1. Click **View Detailed Results** (or navigate to Results, type `demo-judge`, click Load).
2. **Show:** Overall score cards — CIS, NIST 800-53, ISO 27001 percentages.
3. Click through framework tabs (CIS, NIST, ISO27001).
4. **Show:** PCI-DSS and SOC2 tabs have "Bonus Coverage" badges.
5. Point out the **STIG tab** — disabled with "coming soon" tooltip. *"STIG support is on the roadmap; we don't claim coverage we haven't implemented."*
6. **Show:** Test result table with pass/fail badges and remediation text. If any V-code shows "AI-suggested — verify before use", point it out: *"For undocumented patterns, the system generates AI-suggested remediation, clearly labeled so auditors know to verify."*

**What to say:** *"Results are scored per-framework against the compliance manifest. Every remediation is sourced from documented hardening guides where available."*

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
2. Click **Download PDF Report**.
3. **Show:** PDF opens in new tab with:
   - Session metadata (name, target, timestamp)
   - Per-framework compliance tables
   - Evidence rows with device_id, vendor, test ID, verdict
   - Remediation section with documented/AI-suggested labels
   - Bonus coverage note for PCI-DSS/SOC2
   - Tamper-evidence chain status

**What to say:** *"The PDF is generated server-side from the audit report builder. Every figure is machine-validated against the scorer — no LLM hallucinated numbers."*

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
