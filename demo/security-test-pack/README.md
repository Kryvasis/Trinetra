# Cortex upload test pack

Created and tested 2026-09-04. All files are synthetic. No real credentials,
customer data, malware, or live scanning targets are included. Do not deploy
these snippets to a router. The hardened excerpt is deliberately incomplete,
not a vendor-approved baseline or a claim of framework compliance.

## Try the files in the website

1. Open Cortex, choose Open workspace, then Upload & collect.
2. Select the file-upload input, not network collection or website analysis.
3. Use a new session name such as `cortex-demo-20260904` and vendor Auto.
4. Upload the four device `.txt` files together to exercise bulk upload.
   For a single upload, supply a unique device ID matching the filename stem.
5. Inspect Overview, Devices, Results, and the PDF for the same session.
   Compare device IDs, vendor, evidence counts, and unresolved findings.
6. Try `blank.txt` separately: it should be rejected as empty (HTTP 400).
7. Try `not-a-config.html`: the backend rejects web documents (HTTP 422).
   If the browser picker excludes HTML, this case is covered by the script.

Upload only fixture files, not this README, the script, or the ZIP itself.
Keep all frameworks selected for the first run. Then filter to CIS and verify
the results and downloaded report use the same selection. Browser interactions,
bulk UI behavior and PDF visual layout still need manual verification; the
automated checks below exercise the backend with Flask's test client.

## Expected security behavior versus observed behavior

| File | Purpose / expected security behavior | Observed on current code |
| --- | --- | --- |
| cisco-insecure.txt | Explicit Telnet, SSHv1, default SNMP communities, cleartext demo password and disabled idle timeout should produce actionable findings | Accepted; 2 passes, 0 failures, 5 manual-review checks: accuracy FAIL |
| juniper-insecure.txt | Junos set syntax with Telnet, SSHv1 and public/private SNMP should produce actionable findings | Accepted, detected Juniper; 2 passes, 0 failures, 5 manual-review checks: accuracy FAIL |
| cisco-hardened-excerpt.txt | Contrast case with SSHv2, SSH-only VTY and disabled HTTP/SNMP; missing runtime/full-config evidence must stay unresolved | Accepted; same 2 passes, 0 failures, 5 manual-review checks; no meaningful distinction |
| cisco-incomplete.txt | Hostname alone must not establish any security control as passed | Accepted; 2 passes, 0 failures, 5 manual-review checks: accuracy FAIL |
| blank.txt | Reject whitespace-only input | HTTP 400: PASS |
| not-a-config.html | Reject a webpage masquerading as device evidence | HTTP 422: PASS |

Unrecognized line counts are parser coverage diagnostics, not vulnerability
counts. The current parser also marks ordinary supported-vendor configuration
lines unrecognized; do not train these as "secure" merely to remove warnings.

## Repeatable isolated test

From `/home/mystic/Trinetra`:

```bash
.venv/bin/python demo/security-test-pack/verify_demo.py
```

Requires the existing Python dependencies and JDK. It recompiles Java into a
fresh `/tmp/cortex-demo-*` directory, copies rule data, and uses an isolated
session. It does not modify existing user sessions, call AI, or scan networks.
The temporary directory is retained with `verification.json` and a generated
`demo-report.pdf`; the script prints its exact path. No cleanup is automatic.

Exit code 1 currently means the security acceptance checks correctly detected
the known accuracy defects. It must not be represented as a passing audit suite.

## Findings and verification record

- Four multipart configuration uploads succeeded; vendor and OS detection worked.
- Devices API contained four devices; the session evidence chain was intact.
- Status, score and unrecognized APIs returned successfully.
- PDF endpoint produced a PDF (header checked); visual layout not inspected.
- An over-1-MiB synthetic upload was rejected with HTTP 413.
- 23 security-boundary regression tests passed; one session-writing test was
  intentionally excluded from that run. Dashboard summary regression module passed.
- Three security acceptance checks failed: insecure Cisco detection, insecure
  Juniper detection, and absence of unsupported passes for incomplete evidence.
- Evidence provenance defect: stored device filenames expose temporary names
  such as `tmp....txt` instead of the original upload filenames.

### Root cause and next engineering step

`src/TrinetraConfigIngestor.java` feeds the full config to the live-tool
`TrinetraStat.DecisionEngine`. Those definitions use descriptions of tool
output, not vendor-aware configuration semantics. Its `matchesCriteria`
also interprets criteria beginning with `no ` as absence checks, allowing
unrelated/incomplete evidence to satisfy some rules.

The next fix should separate configuration checks from live-tool checks,
require positive scoped evidence for passes, respect command negation and
vendor syntax, and preserve manual-review status for unsupported checks.
Keep these failing tests as acceptance criteria. Do not simply change the
expected results to match the current incorrect behavior. Application scoring
code has not been changed as part of this test-pack task.
