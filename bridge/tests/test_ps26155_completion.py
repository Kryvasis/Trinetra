import json
import shutil
import uuid
from pathlib import Path

import pytest

from bridge.app import app


ROOT = Path(__file__).resolve().parents[2]


def _session(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def test_configuration_upload_accounts_for_every_manifest_control():
    client = app.test_client()
    session = _session("manifest_coverage")
    try:
        assert client.post("/api/session", json={"name": session, "target": "edge-01"}).status_code == 201
        response = client.post(f"/api/session/{session}/upload-config", json={
            "device_id": "edge-01",
            "vendor": "Cisco",
            "config_content": "hostname edge-01\nip ssh version 2\nswitchport mode access\n",
        })
        assert response.status_code == 200, response.get_data(as_text=True)
        assessment_id = response.get_json()["assessment_id"]
        assert assessment_id.startswith("asm-")
        session_data = json.loads((ROOT / "sessions" / session / f"{session}.json").read_text())
        manifest = json.loads((ROOT / "config" / "compliance_manifest.json").read_text())
        expected = {key for key in manifest if key.startswith("V-")}
        findings = {
            row["v_code"]: row
            for row in session_data["findings"]
            if str(row.get("v_code", "")) in expected
        }
        assert set(findings) == expected
        assert findings["V-006"]["evidence_reason"] == "explicit_secure_directive"
        assert findings["V-070"]["evidence_reason"] == "requires_live_evidence"
        assert findings["V-088"]["evidence_reason"] == "unsupported_assessment_type"
        assert findings["V-104"]["verdict"] == "pass"
        brain = json.loads((ROOT / "sessions" / session / f"brain_state_{session}.json").read_text())
        assessment_rows = [row for row in brain["normalized_results"] if row.get("assessment_id") == assessment_id]
        assert len(assessment_rows) == len(expected)
        assert all(row.get("evidence_reason") and row.get("chain_hash") for row in assessment_rows)
        snapshot = ROOT / "sessions" / session / "artifacts" / "assessments" / f"{assessment_id}.json"
        assert snapshot.exists()
        assert json.loads(snapshot.read_text())["config_sha256"] == assessment_rows[0]["config_sha256"]
    finally:
        shutil.rmtree(ROOT / "sessions" / session, ignore_errors=True)


def test_training_activation_rejects_missing_regression_examples(tmp_path, monkeypatch):
    from bridge import app as app_module

    config = tmp_path / "config"
    config.mkdir()
    (config / "vendor_training_map.json").write_text('{"entries": []}', encoding="utf-8")
    (config / "compliance_manifest.json").write_text('{"V-006": {}}', encoding="utf-8")
    monkeypatch.setattr(app_module, "TRINETRA_ROOT", str(tmp_path))
    client = app_module.app.test_client()
    created = client.post("/api/session/regression-demo/train", json={
        "vendor": "Cisco",
        "pattern": "^custom ssh version (\\d+)$",
        "security_category": "Cryptography",
        "v_code": "V-006",
        "baseline_field": "management_plane.ssh_version",
        "value": "$1",
        "author": "author-one",
    })
    assert created.status_code == 201
    rule_id = created.get_json()["entry"]["rule_id"]
    approval = client.post(f"/api/training-rules/{rule_id}/review", json={
        "action": "approve", "reviewer": "reviewer-two"
    })
    assert approval.status_code == 422
    assert "regression" in approval.get_json()["error"].lower()


def test_training_rejects_unsafe_regex(tmp_path, monkeypatch):
    from bridge import app as app_module

    config = tmp_path / "config"
    config.mkdir()
    (config / "vendor_training_map.json").write_text('{"entries": []}', encoding="utf-8")
    monkeypatch.setattr(app_module, "TRINETRA_ROOT", str(tmp_path))
    response = app_module.app.test_client().post("/api/session/regex-demo/train", json={
        "vendor": "Cisco", "pattern": "^(a+)+$", "security_category": "Test"
    })
    assert response.status_code == 400
    assert "unsafe" in response.get_json()["error"].lower()


@pytest.mark.parametrize(("fixture", "vendor"), [
    ("juniper-hardened-excerpt.txt", "Juniper"),
    ("juniper-incomplete.txt", "Juniper"),
    ("juniper-ambiguous-last-wins.txt", "Juniper"),
    ("fortios-hardened-excerpt.txt", "FortiOS"),
    ("fortios-insecure.txt", "FortiOS"),
    ("fortios-incomplete.txt", "FortiOS"),
    ("fortios-ambiguous-last-wins.txt", "FortiOS"),
    ("cisco-ambiguous-last-wins.txt", "Cisco"),
])
def test_new_multivendor_fixtures_pass_real_upload_boundary(fixture, vendor):
    client = app.test_client()
    session = _session("fixture_upload")
    try:
        assert client.post("/api/session", json={"name": session, "target": fixture}).status_code == 201
        content = (ROOT / "demo" / "security-test-pack" / fixture).read_text()
        response = client.post(f"/api/session/{session}/upload-config", json={
            "device_id": "fixture-device", "vendor": "auto",
            "filename": fixture, "config_content": content,
        })
        assert response.status_code == 200, response.get_data(as_text=True)
        body = response.get_json()
        assert body["vendor"] == vendor
        assert body["assessment_id"].startswith("asm-")
    finally:
        shutil.rmtree(ROOT / "sessions" / session, ignore_errors=True)
