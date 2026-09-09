import json
import uuid
import shutil
import pytest
from pathlib import Path
from bridge.app import app

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def training_files_guard():
    map_path = ROOT / "config" / "vendor_training_map.json"
    corpus_path = ROOT / "config" / "ml_corpus.json"
    original_map = map_path.read_bytes()
    original_corpus = corpus_path.read_bytes()
    yield map_path, corpus_path
    map_path.write_bytes(original_map)
    corpus_path.write_bytes(original_corpus)


def test_training_loop_no_code_change(training_files_guard):
    """
    End-to-end training loop proof:
    1. Feed a config line no existing connector recognizes -> flagged unrecognized
    2. Simulate training-map entry being added
    3. Re-parse same line -> correctly categorized, zero code changes
    """
    client = app.test_client()
    _ = training_files_guard
    sess = f"train_loop_{uuid.uuid4().hex[:6]}"
    # Create session
    resp = client.post("/api/session", json={"name": sess, "target": "cisco-train-01"})
    assert resp.status_code == 201

    # Use a unique custom pattern that is definitely not in known patterns
    custom_line = f"my-unique-train-feature-{uuid.uuid4().hex[:4]} enable"
    pattern = custom_line.replace(" enable", ".*")  # regex pattern

    config_before = f"hostname R1\n{custom_line}\n"

    # Upload before training -> should be unrecognized
    resp = client.post(f"/api/session/{sess}/upload-config", json={
        "device_id": "cisco-train-01",
        "vendor": "Cisco",
        "config_content": config_before
    })
    assert resp.status_code == 200
    data_before = resp.get_json()
    assert custom_line in data_before["unrecognized_lines"], f"Expected {custom_line!r} to be unrecognized before training, got {data_before['unrecognized_lines']}"

    # Verify via GET unrecognized
    resp = client.get(f"/api/session/{sess}/unrecognized?device_id=cisco-train-01")
    assert resp.status_code == 200
    unrec_before = resp.get_json()["unrecognized_lines"]
    assert custom_line in unrec_before

    # Save a governed normalization rule as a draft.
    resp = client.post(f"/api/session/{sess}/train", json={
        "vendor": "Cisco",
        "pattern": pattern,
        "security_category": "Custom Training Test",
        "control_mapping": ["CIS-v8-4.6"],
        "remediation": "no my-unique-train-feature",
        "v_code": "V-003",
        "baseline_field": "management_plane.http_enabled",
        "value": "true",
        "author": "training-author",
        "positive_examples": [custom_line],
        "negative_examples": ["hostname R1"],
    })
    assert resp.status_code == 201, resp.get_json()
    assert resp.get_json()["entry"]["pattern"] == pattern
    entry = resp.get_json()["entry"]

    # A different operator runs regression examples before activation.
    resp = client.post(f"/api/training-rules/{entry['rule_id']}/review", json={
        "action": "approve", "reviewer": "training-reviewer"
    })
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["entry"]["regression"]["passed"] is True

    # Re-parse same line -> should now be recognized
    resp = client.post(f"/api/session/{sess}/upload-config", json={
        "device_id": "cisco-train-01",
        "vendor": "Cisco",
        "config_content": config_before
    })
    assert resp.status_code == 200
    data_after = resp.get_json()
    assert custom_line not in data_after["unrecognized_lines"], f"Expected {custom_line!r} to be recognized after training, still unrecognized: {data_after['unrecognized_lines']}"

    # Verify via GET
    resp = client.get(f"/api/session/{sess}/unrecognized?device_id=cisco-train-01")
    assert custom_line not in resp.get_json()["unrecognized_lines"]

    # Cleanup session using the repository root, independent of pytest's cwd.
    shutil.rmtree(ROOT / "sessions" / sess, ignore_errors=True)
