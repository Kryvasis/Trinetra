# Cortex two-minute demonstration script

Record a fresh session. Keep the pointer still while speaking and let each view
settle before the next action.

## 0:00–0:15 — Problem

“Network configurations use different vendor syntax. Cortex turns authorized
exports into one reviewable security assessment without treating missing
evidence as a pass.” Open the workspace.

## 0:15–0:40 — Multi-vendor upload

Open **Upload & collect**. Upload the Cisco, Juniper, and FortiOS insecure
fixtures together with vendor set to Auto. Select CIS, NIST SP 800-53, STIG, and
ISO/IEC 27001. Point out automatic vendor detection and the visible processing
trace. Never enter real credentials in the recording.

## 0:40–1:05 — Findings and reports

Open **Results** and show explicit failed directives, unresolved reason codes,
and framework mappings. Open **Devices**, compare two snapshots for one device,
and download its PDF. Say: “Cortex evaluates 28 mapped controls. Unsupported or
live-only checks remain unresolved.”

## 1:05–1:35 — Training loop

Upload a synthetic configuration containing one unknown command. In **Training**,
select the line, assign its manifest control and allowlisted baseline field, add
one non-matching example, and save the draft. Enter a different reviewer name,
run checks, and activate. Re-upload without restarting Cortex and show the new
semantic outcome.

## 1:35–1:52 — Integrity

Open **Assurance**. Show the 28-control evaluation matrix, generate a signed
receipt, then verify it. Explain that the signature and Merkle root protect the
local evidence set; Cortex does not claim an external blockchain anchor.

## 1:52–2:00 — Close

“Cortex combines deterministic evidence, human-governed learning, and honest
coverage boundaries in one multi-vendor workflow.” End on the overview.

## Recording checklist

- Use only synthetic files from `demo/security-test-pack/`.
- Restart the backend first and create a new session.
- Confirm browser zoom is 100 percent and no personal tabs or notifications show.
- Rehearse once below 1:55 to leave time for transitions.
- Do not claim universal vendor support, certification, autonomous remediation,
  measured production accuracy, or external blockchain anchoring.
