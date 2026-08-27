import json
import uuid
import shutil
from pathlib import Path
from bridge.app import app

def test_training_loop_no_code_change():
    """
    End-to-end training loop proof:
    1. Feed a config line no existing connector recognizes -> flagged unrecognized
    2. Simulate training-map entry being added
    3. Re-parse same line -> correctly categorized, zero code changes
    """
    client = app.test_client()
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

    # Simulate training: add entry to training map
    resp = client.post(f"/api/session/{sess}/train", json={
        "vendor": "Cisco",
        "pattern": pattern,
        "security_category": "Custom Training Test",
        "control_mapping": ["CIS-v8-4.6"],
        "remediation": "no my-unique-train-feature"
    })
    assert resp.status_code == 201, resp.get_json()
    assert resp.get_json()["entry"]["pattern"] == pattern

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

    # Cleanup: remove training entry
    map_path = Path("config/vendor_training_map.json")
    if map_path.exists():
        data = json.loads(map_path.read_text())
        data["entries"] = [e for e in data["entries"] if e.get("pattern") != pattern]
        map_path.write_text(json.dumps(data, indent=2))

    # Cleanup session
    shutil.rmtree(Path("sessions") / sess, ignore_errors=True)
    # Also clean up any other test sessions
    for p in Path("sessions").glob("train_loop_*"):
        shutil.rmtree(p, ignore_errors=True)
