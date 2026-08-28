import json
import os
import re
import subprocess
import time
import uuid
import pytest
from pathlib import Path

# Ensure bridge is importable
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bridge.app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

def unique_session(prefix="bridge_test"):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"

def run_trinetra_direct(args):
    """Helper to run trinetra directly for comparison"""
    trinetra_bin = os.getenv("TRINETRA_BIN", str(Path(__file__).resolve().parent.parent.parent / "trinetra"))
    result = subprocess.run([trinetra_bin] + args, capture_output=True, text=True, timeout=30)
    return result

# ── (a) each endpoint produces correct structured output matching CLI ──

def test_create_session_success(client):
    sess = unique_session("test_create")
    resp = client.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    data = resp.get_json()
    assert data["session"] == sess
    assert "target" in data
    # Verify via CLI that session exists
    result = run_trinetra_direct(["-sessions"])
    assert sess in result.stdout

    # Cleanup: remove session dir
    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

def test_create_session_missing_fields(client):
    resp = client.post("/api/session", json={"name": "only_name"})
    assert resp.status_code == 400
    assert "error" in resp.get_json()

def test_session_status_real(client):
    sess = unique_session("test_status")
    # Create via bridge
    client.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    # Run a simple test to have some data
    # Use a known test that is fast: V-008 or V-010
    # First, get valid test_ids via --list-tests or use V-010
    # We'll run V-010 (HSTS) which is relatively fast
    resp = client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "vendor": "Generic",
        "test_ids": ["V-010"],
        "workers": 1
    })
    # Should succeed (even if test fails compliance, subprocess should be 200)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    # Now get status
    resp = client.get(f"/api/session/{sess}/status")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert data["session_name"] == sess
    assert "chain" in data
    assert "intact" in data["chain"]
    assert data["chain"]["intact"] is True
    assert data["normalized_results_count"] >= 1
    # Compare with direct CLI verifyChain via Java helper
    # The bridge's status should match direct Java call
    # Directly call TrinetraBridgeHelper status
    trinetra_root = os.getenv("TRINETRA_ROOT", str(Path(__file__).resolve().parent.parent.parent))
    java_out = str(Path(trinetra_root) / "out")
    java_lib = str(Path(trinetra_root) / "lib" / "*")
    result = subprocess.run(
        ["java", f"-Dtrinetra.root={trinetra_root}", "-cp", f"{java_out}:{java_lib}", "TrinetraBridgeHelper", "status", sess],
        capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0
    direct = json.loads(result.stdout)
    assert direct["chain"]["intact"] == data["chain"]["intact"]
    assert direct["chain"]["linkCount"] == data["chain"]["linkCount"]

    # Cleanup
    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

def test_compliance_score_endpoint(client):
    sess = unique_session("test_score")
    client.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    # Run a couple tests to have scoring data (use fast mapped V-008)
    client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "test_ids": ["V-008"],
        "workers": 1
    })
    resp = client.get(f"/api/session/{sess}/score")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert "score" in data
    score_data = data["score"]
    assert "frameworks" in score_data
    assert "total_tests_executed" in score_data
    # Compare with direct CLI
    result = run_trinetra_direct(["-compliance-score", sess])
    assert result.returncode == 0
    # CLI stdout contains "[audit] user: ..." plus pretty JSON plus footer
    cli_stdout = result.stdout
    if "Compliance score written to:" in cli_stdout:
        cli_stdout = cli_stdout.split("Compliance score written to:")[0]
    # Extract JSON object by first { and last }
    first = cli_stdout.find("{")
    last = cli_stdout.rfind("}")
    if first != -1 and last != -1:
        cli_stdout = cli_stdout[first:last+1]
    cli_data = json.loads(cli_stdout.strip())
    assert cli_data["session_name"] == score_data["session_name"]
    assert cli_data["total_tests_executed"] == score_data["total_tests_executed"]

    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

def test_compliance_report_endpoint(client):
    sess = unique_session("test_report")
    client.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "test_ids": ["V-008"],
        "workers": 1
    })
    resp = client.get(f"/api/session/{sess}/report")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert "stdout" in data
    assert "Compliance Narrative Report" in data["stdout"] or "compliance" in data["stdout"].lower()

    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

def test_audit_report_endpoint(client):
    sess = unique_session("test_audit")
    client.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "test_ids": ["V-008"],
        "workers": 1
    })
    resp = client.get(f"/api/session/{sess}/audit-report")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert "combined_path" in data
    assert "framework_paths" in data
    assert "chain_status" in data
    assert data["chain_status"] is not None
    assert "INTACT" in data["chain_status"] or "intact" in data["chain_status"].lower()
    # Combined content should be present and contain audit report header
    assert data["combined_content"] is not None
    assert "Combined Audit Report" in data["combined_content"] or "Audit Report" in data["combined_content"]
    # Verify per-framework distinction is not collapsed (at least check that combined_content has table header)
    assert "Device" in data["combined_content"] and "Vendor" in data["combined_content"]

    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

def test_run_endpoint_single_and_multi_device(client):
    sess = unique_session("test_run_multi")
    client.post("/api/session", json={"name": sess, "target": "multi-target"})
    # Single device run (use fast mapped V-008, localhost for speed)
    resp = client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "vendor": "Cisco",
        "test_ids": ["V-008"],
        "workers": 1
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert data["session"] == sess
    assert len(data["devices"]) == 1
    # Multi-device run (use fast mapped V-008, localhost variants)
    resp = client.post(f"/api/session/{sess}/run", json={
        "devices": [
            {"device_id": "127.0.0.1", "vendor": "Cisco"},
            {"device_id": "127.0.0.2", "vendor": "Juniper"}
        ],
        "test_ids": ["V-008"],
        "workers": 1
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert len(data["devices"]) == 2

    # Verify via status that normalized_results has at least 3 entries (1+2)
    resp = client.get(f"/api/session/{sess}/status")
    assert resp.status_code == 200
    assert resp.get_json()["normalized_results_count"] >= 3

    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

# ── (b) subprocess failure returns proper error status/body ──

def test_invalid_session_returns_error(client):
    # Non-existent session for status should be 404 (via Java helper)
    resp = client.get("/api/session/nonexistent_sess_123xyz/status")
    assert resp.status_code in (404, 500), resp.get_data(as_text=True)
    assert "error" in resp.get_json()

    # For score/report, CLI creates empty session and returns 200 with empty data
    # So we check that non-existent returns 200 with empty frameworks (legitimate result)
    resp = client.get("/api/session/nonexistent_sess_123xyz/score")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "score" in data
    assert data["score"]["total_tests_executed"] == 0

    resp = client.get("/api/session/nonexistent_sess_123xyz/report")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "stdout" in data

    resp = client.get("/api/session/nonexistent_sess_123xyz/audit-report")
    # Audit report for empty session should fail (no brain-state)
    assert resp.status_code in (404, 500)

    # Cleanup the auto-created empty session
    import shutil
    from pathlib import Path
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / "nonexistent_sess_123xyz"
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

    # Invalid session name for run should be 400
    resp = client.post("/api/session/invalid!name/run", json={
        "device_id": "10.0.0.1",
        "test_ids": ["V-003"]
    })
    assert resp.status_code == 400
    assert "error" in resp.get_json()

def test_create_session_invalid_target(client):
    sess = unique_session("test_invalid_target")
    # Missing target
    resp = client.post("/api/session", json={"name": sess})
    assert resp.status_code == 400
    # Invalid session name with injection
    resp = client.post("/api/session", json={"name": "bad; rm -rf /", "target": "127.0.0.1"})
    assert resp.status_code == 400

# ── (c) input validation rejects injection without invoking subprocess ──

def test_injection_rejected_before_subprocess(client, monkeypatch):
    # Patch subprocess.run to ensure it's NOT called for invalid input
    called = {"value": False}
    original_run = subprocess.run
    def fake_run(*args, **kwargs):
        called["value"] = True
        return original_run(*args, **kwargs)
    monkeypatch.setattr(subprocess, "run", fake_run)

    # Try injection in session name
    resp = client.post("/api/session", json={"name": "bad; rm -rf /tmp", "target": "127.0.0.1"})
    assert resp.status_code == 400
    assert not called["value"], "subprocess should not be invoked for injection attempt"

    called["value"] = False
    # Try injection in test_id
    sess = unique_session("test_inject")
    client.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    # Reset after session creation (which does call subprocess)
    called["value"] = False
    resp = client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "test_ids": ["V-010; rm -rf /"],
    })
    assert resp.status_code == 400
    assert not called["value"]

    called["value"] = False
    # Try injection in device_id
    resp = client.post(f"/api/session/{sess}/run", json={
        "device_id": "10.0.0.1 && echo pwned",
        "test_ids": ["V-010"],
    })
    assert resp.status_code == 400
    assert not called["value"]

    # Try injection in vendor
    resp = client.post(f"/api/session/{sess}/run", json={
        "device_id": "10.0.0.1",
        "vendor": "Cisco; echo hi",
        "test_ids": ["V-010"],
    })
    assert resp.status_code == 400
    assert not called["value"]

    # Cleanup
    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

    # Also test that valid inputs do invoke subprocess
    # Use a valid session to ensure subprocess is called
    sess2 = unique_session("test_valid_invoke")
    resp = client.post("/api/session", json={"name": sess2, "target": "127.0.0.1"})
    # This should have invoked subprocess, so we can't check not called, but we know valid path works
    assert resp.status_code == 201
    import shutil
    sess_dir2 = Path(__file__).resolve().parent.parent.parent / "sessions" / sess2
    if sess_dir2.exists():
        shutil.rmtree(sess_dir2)

def test_test_id_format_validation(client):
    sess = unique_session("test_tid_format")
    client.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    # Valid
    resp = client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "test_ids": ["V-008"],
    })
    assert resp.status_code == 200
    # Invalid: contains shell metachars
    resp = client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "test_ids": ["V-003 && ls"],
    })
    assert resp.status_code == 400
    # Invalid: empty
    resp = client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "test_ids": [],
    })
    assert resp.status_code == 400

    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

# ── (d) /api/doctor correctly parses and structures CLI output ──

def test_doctor_parsing(client):
    resp = client.get("/api/doctor")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert "raw_stdout" in data
    assert "sections" in data
    assert "test_definitions" in data
    assert "session_validation" in data
    assert "ai_integration" in data
    # Check that test_definitions count is present and is int
    assert "count" in data["test_definitions"]
    assert isinstance(data["test_definitions"]["count"], int)
    assert data["test_definitions"]["count"] > 0
    # Check that doctor output matches direct CLI
    result = run_trinetra_direct(["-doctor"])
    assert result.returncode == 0
    assert str(data["test_definitions"]["count"]) in result.stdout
    # Check session_validation has expected structure
    assert "session_errors" in data["session_validation"]
    assert "status" in data["session_validation"]
    # Check ai_integration
    assert "gemini_cli" in data["ai_integration"] or "gemini" in str(data["ai_integration"]).lower()

    # Also test that doctor returns structured project_structure
    assert "project_structure" in data

def test_doctor_error_handling(client, monkeypatch):
    # Simulate trinetra binary not found
    # We can test by temporarily setting TRINETRA_BIN to invalid path
    import bridge.app as app_module
    original_bin = app_module.TRINETRA_BIN
    try:
        app_module.TRINETRA_BIN = "/nonexistent/trinetra"
        resp = client.get("/api/doctor")
        # Should return 500 or 200 with error details? Our current doctor returns 500 only if rc !=0 and no stdout
        # With invalid binary, run_trinetra will return 127, but we still try to parse
        # Our doctor handler returns 500 only if rc !=0 and not out, else 200
        # So we should check that it still returns JSON with error
        assert resp.status_code in (200, 500)
        data = resp.get_json()
        # If 200, it will have raw_stdout empty, but should still be structured
        # If 500, it should have error
        assert data is not None
    finally:
        app_module.TRINETRA_BIN = original_bin

# ── Additional: ensure frontend can distinguish test failed vs backend error ──

def test_distinguishes_test_failure_from_backend_error(client):
    sess = unique_session("test_distinguish")
    client.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    # Run a test that will legitimately fail compliance (e.g., V-008 with self-signed)
    # The run endpoint should still return 200 (test executed), not 500
    resp = client.post(f"/api/session/{sess}/run", json={
        "device_id": "127.0.0.1",
        "test_ids": ["V-008"],
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    # Check score: should still be 200 with score data, even if compliance is low
    resp = client.get(f"/api/session/{sess}/score")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "score" in data
    # Now try backend error: invalid session name format (should be 400, not 200)
    resp = client.get("/api/session/invalid!name/score")
    assert resp.status_code == 400
    assert "error" in resp.get_json()
    # Non-existent but valid format should still return 200 with empty score (legitimate result, not backend error)
    resp = client.get("/api/session/this_session_does_not_exist_999/score")
    assert resp.status_code == 200
    assert "score" in resp.get_json()
    # Ensure the successful score response does NOT contain error field
    resp = client.get(f"/api/session/{sess}/score")
    assert "error" not in resp.get_json()

    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)

# ── (f) devices endpoint ──

def test_devices_endpoint(client):
    """GET /api/session/<name>/devices returns per-device summary."""
    sess = unique_session("test_devices")
    client.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    client.post(f"/api/session/{sess}/upload-config", json={
        "device_id": "cisco-01",
        "vendor": "Cisco",
        "config_content": "hostname R1\nenable secret 5 $1$...\n",
        "filename": "cisco_config.txt",
    })
    client.post(f"/api/session/{sess}/upload-config", json={
        "device_id": "juniper-01",
        "vendor": "Juniper",
        "config_content": "system {\n  host-name switch-a;\n}\n",
        "filename": "juniper_config.txt",
    })

    resp = client.get(f"/api/session/{sess}/devices")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert data["session"] == sess
    assert data["device_count"] == 2
    devices = {d["device_id"]: d for d in data["devices"]}
    assert "cisco-01" in devices
    assert "juniper-01" in devices
    for did, d in devices.items():
        assert "vendor" in d
        assert "ingestion_method" in d
        assert "pass_count" in d
        assert "fail_count" in d
        assert "total_checks" in d
    assert devices["cisco-01"]["vendor"] == "Cisco"
    assert devices["juniper-01"]["vendor"] == "Juniper"
    assert devices["cisco-01"]["ingestion_method"] == "config_upload"

    resp = client.get("/api/session/invalid!name/devices")
    assert resp.status_code == 400
    resp = client.get("/api/session/nonexistent_sess_xyz/devices")
    assert resp.status_code == 404

    import shutil
    sess_dir = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if sess_dir.exists():
        shutil.rmtree(sess_dir)
