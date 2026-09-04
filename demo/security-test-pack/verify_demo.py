"""Offline integration checks using a fresh temporary root; no live scans or AI calls.

Run: .venv/bin/python demo/security-test-pack/verify_demo.py
Outputs remain in a new /tmp/cortex-demo-* directory for inspection.
"""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

PACK = Path(__file__).resolve().parent
ROOT = PACK.parent.parent
TEST_ROOT = Path(tempfile.mkdtemp(prefix="cortex-demo-"))
for name in ("config", "out", "lib"):
    shutil.copytree(ROOT / name, TEST_ROOT / name)
for name in ("1_classification.csv", "2_static_map.json", "3_decision_engine.csv", "trinetra"):
    shutil.copy2(ROOT / name, TEST_ROOT / name)
subprocess.run(["javac", "-d", str(TEST_ROOT / "out"), *map(str, (ROOT / "src").glob("*.java"))], check=True)
os.environ["TRINETRA_ROOT"] = str(TEST_ROOT)
os.environ["TRINETRA_BIN"] = str(TEST_ROOT / "trinetra")
sys.path.insert(0, str(ROOT))
import bridge.app as bridge_module
bridge_module.JAVA_OUT = str(TEST_ROOT / "out")
bridge_module.JAVA_LIB = str(TEST_ROOT / "lib" / "*")
app = bridge_module.app

client = app.test_client()
session = "demo-fixtures"
assert client.post("/api/session", json={"name": session, "target": "offline-fixtures"}).status_code == 201
report = {"isolated_root": str(TEST_ROOT), "uploads": {}, "checks": {}}
for filename, expected in {
    "cisco-insecure.txt": 200,
    "cisco-hardened-excerpt.txt": 200,
    "juniper-insecure.txt": 200,
    "cisco-incomplete.txt": 200,
    "not-a-config.html": 422,
    "blank.txt": 400,
}.items():
    response = client.post(f"/api/session/{session}/upload-config", data={
        "device_id": Path(filename).stem, "vendor": "auto",
        "config": (io.BytesIO((PACK / filename).read_bytes()), filename),
    }, content_type="multipart/form-data")
    report["uploads"][filename] = {"http_status": response.status_code, "body": response.get_json()}
    assert response.status_code == expected, (filename, response.status_code, response.get_json())
for endpoint in ("status", "devices", "score", "unrecognized", "audit-report/pdf"):
    response = client.get(f"/api/session/{session}/{endpoint}")
    assert response.status_code == 200, (endpoint, response.get_data(as_text=True)[:400])
    if endpoint.endswith("pdf"):
        assert response.data.startswith(b"%PDF-")
        report["checks"][endpoint] = {"status": 200, "bytes": len(response.data)}
        (TEST_ROOT / "demo-report.pdf").write_bytes(response.data)
    else:
        report["checks"][endpoint] = response.get_json()
oversized = client.post(f"/api/session/{session}/upload-config", data={
    "device_id": "oversized", "config": (io.BytesIO(b"x" * (1024 * 1024 + 1)), "oversized.txt"),
}, content_type="multipart/form-data")
assert oversized.status_code == 413
report["checks"]["oversized"] = 413
assert report["checks"]["status"]["chain"]["intact"] is True
assert report["checks"]["devices"]["device_count"] == 4
report["security_acceptance"] = {
    "insecure_cisco_produces_failures": report["uploads"]["cisco-insecure.txt"]["body"]["failed"] > 0,
    "insecure_juniper_produces_failures": report["uploads"]["juniper-insecure.txt"]["body"]["failed"] > 0,
    "incomplete_evidence_has_no_passes": report["uploads"]["cisco-incomplete.txt"]["body"]["passed"] == 0,
}
regressions = subprocess.run([
    sys.executable, "-m", "pytest", "bridge/tests/test_security_review.py", "-q",
    "-k", "not manual_review",
], cwd=ROOT, capture_output=True, text=True)
report["boundary_regressions"] = {"exit_code": regressions.returncode, "output": regressions.stdout + regressions.stderr}
(TEST_ROOT / "verification.json").write_text(json.dumps(report, indent=2))
print("Evidence directory:", TEST_ROOT)
for filename, result in report["uploads"].items():
    body = result["body"]
    print(filename, result["http_status"], "pass=", body.get("passed"), "fail=", body.get("failed"))
print(json.dumps(report["security_acceptance"], indent=2))
print(report["boundary_regressions"]["output"])
sys.exit(0 if all(report["security_acceptance"].values()) and regressions.returncode == 0 else 1)
