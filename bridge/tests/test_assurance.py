import json

from bridge import app as app_module
from bridge import ml_knn
from bridge.assurance import build_receipt, capability_report, verify_receipt


def test_signed_receipt_detects_tampering(tmp_path):
    brain = {"normalized_results": [
        {"chain_hash": "a" * 64},
        {"chain_hash": "b" * 64},
        {"chain_hash": "c" * 64},
    ]}
    receipt = build_receipt(str(tmp_path), "assurance-demo", brain)
    valid, _ = verify_receipt(receipt)
    assert valid is True
    assert receipt["entry_count"] == 3
    assert receipt["external_anchor"] is None
    assert receipt["trust_scope"] == "local_assessor_signature"

    altered = dict(receipt)
    altered["entry_count"] = 4
    valid, detail = verify_receipt(altered)
    assert valid is False
    assert "altered" in detail.lower()


def test_capability_report_never_invents_accuracy():
    report = capability_report(app_module.TRINETRA_ROOT)
    assert report["manifest_controls"] > 0
    assert report["probe_scripts"] > 0
    assert report["accuracy"]["status"] == "not_independently_measured"
    assert report["accuracy"]["precision"] is None
    assert "not certification" in report["claims"]["scoring"].lower()
    assert "not independently anchored" in report["claims"]["integrity"].lower()


def test_receipt_api_requires_intact_chain_and_compares_current_evidence(tmp_path, monkeypatch):
    session = "receipt-demo"
    folder = tmp_path / "sessions" / session
    folder.mkdir(parents=True)
    brain = {"normalized_results": [{"chain_hash": "d" * 64}]}
    (folder / f"brain_state_{session}.json").write_text(json.dumps(brain), encoding="utf-8")
    monkeypatch.setattr(app_module, "TRINETRA_ROOT", str(tmp_path))
    monkeypatch.setattr(app_module, "run_java_helper", lambda *args, **kwargs: (
        0, json.dumps({"chain": {"intact": True, "detail": "chain intact"}}), ""
    ))
    client = app_module.app.test_client()
    generated = client.get(f"/api/session/{session}/integrity-receipt")
    assert generated.status_code == 200
    receipt = generated.get_json()["receipt"]
    assert receipt["chain_verified_before_signing"] is True
    verified = client.post("/api/assurance/verify-receipt", json={"receipt": receipt})
    assert verified.status_code == 200
    assert verified.get_json()["valid"] is True
    assert verified.get_json()["current_evidence_matches"] is True

    monkeypatch.setattr(app_module, "run_java_helper", lambda *args, **kwargs: (
        0, json.dumps({"chain": {"intact": False, "detail": "entry mismatch"}}), ""
    ))
    refused = client.get(f"/api/session/{session}/integrity-receipt")
    assert refused.status_code == 409


def test_training_rule_requires_independent_review(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.mkdir()
    (config / "vendor_training_map.json").write_text('{"entries": []}', encoding="utf-8")
    monkeypatch.setattr(app_module, "TRINETRA_ROOT", str(tmp_path))
    monkeypatch.setattr(app_module, "run_java_helper", lambda *args, **kwargs: (0, "{}", ""))
    monkeypatch.setattr(ml_knn, "train", lambda *args, **kwargs: True)
    client = app_module.app.test_client()

    created = client.post("/api/session/review-demo/train", json={
        "vendor": "Cisco",
        "pattern": "^service timestamps.*$",
        "security_category": "Logging integrity",
        "control_mapping": ["CIS-v8-8.2"],
        "remediation": "Review timestamp configuration.",
        "status": "draft",
        "author": "analyst-one",
        "source_reference": "https://www.cisco.com/",
        "confidence": 0.8,
    })
    assert created.status_code == 201
    entry = created.get_json()["entry"]
    assert entry["status"] == "draft"
    assert entry["version"] == 1

    listed = client.get("/api/training-rules?status=draft")
    assert listed.status_code == 200
    assert listed.get_json()["total"] == 1

    same_person = client.post(f"/api/training-rules/{entry['rule_id']}/review", json={
        "action": "approve", "reviewer": "analyst-one",
    })
    assert same_person.status_code == 409

    approved = client.post(f"/api/training-rules/{entry['rule_id']}/review", json={
        "action": "approve", "reviewer": "analyst-two",
    })
    assert approved.status_code == 200
    approved_entry = approved.get_json()["entry"]
    assert approved_entry["status"] == "active"
    assert approved_entry["reviewer"] == "analyst-two"
    assert approved_entry["version"] == 2
    saved = json.loads((config / "vendor_training_map.json").read_text(encoding="utf-8"))
    assert saved["entries"][0]["status"] == "active"


def test_built_workspace_serves_spa_without_masking_api_404s(tmp_path, monkeypatch):
    dist = tmp_path / "frontend" / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text('<main id="root">Cortex</main>', encoding="utf-8")
    (assets / "workspace.css").write_text("body{color:white}", encoding="utf-8")
    monkeypatch.setattr(app_module, "TRINETRA_ROOT", str(tmp_path))
    client = app_module.app.test_client()

    assert client.get("/").status_code == 200
    deep_link = client.get("/assurance")
    assert deep_link.status_code == 200
    assert b"Cortex" in deep_link.data
    assert client.get("/assets/workspace.css").status_code == 200
    api_missing = client.get("/api/does-not-exist")
    assert api_missing.status_code == 404
    assert api_missing.is_json
