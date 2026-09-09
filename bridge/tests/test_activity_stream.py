import json
import uuid
from pathlib import Path

import pytest

import bridge.app as bridge_app


@pytest.fixture
def activity_client(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge_app, "TRINETRA_ROOT", str(tmp_path))
    monkeypatch.setattr(
        bridge_app,
        "run_java_helper",
        lambda *_args, **_kwargs: (
            0,
            json.dumps({
                "device_id": "edge-01",
                "passed": 2,
                "failed": 1,
                "total_checks": 5,
                "unrecognized_count": 2,
            }),
            "",
        ),
    )
    bridge_app.app.config["TESTING"] = True
    name = f"activity_{uuid.uuid4().hex[:8]}"
    session_dir = tmp_path / "sessions" / name
    session_dir.mkdir(parents=True)
    (session_dir / f"{name}.json").write_text(json.dumps({"session_name": name}), encoding="utf-8")
    with bridge_app.app.test_client() as client:
        yield client, name, session_dir


def test_activity_trace_records_sanitized_real_stages(activity_client):
    client, name, session_dir = activity_client
    operation_id = f"op-{uuid.uuid4()}"

    started = client.post(
        f"/api/session/{name}/activity/start",
        json={"operation_id": operation_id, "mode": "paste", "item_count": 1},
    )
    assert started.status_code == 202

    secret = "SENSITIVE-DEMO-PASSWORD"
    uploaded = client.post(
        f"/api/session/{name}/upload-config",
        json={
            "device_id": "edge-01",
            "vendor": "Cisco",
            "filename": "edge.cfg",
            "config_content": f"hostname edge-01\nusername demo password 0 {secret}\nip ssh version 1\n",
        },
        headers={"X-Cortex-Operation": operation_id},
    )
    assert uploaded.status_code == 200, uploaded.get_data(as_text=True)

    completed = client.post(
        f"/api/session/{name}/activity/{operation_id}/complete",
        json={"status": "success", "succeeded": 1, "failed": 0},
    )
    assert completed.status_code == 200

    response = client.get(f"/api/session/{name}/activity")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    trace = response.get_json()
    assert trace["operation_id"] == operation_id
    assert trace["status"] == "success"
    assert trace["summary"] == {"succeeded": 1, "failed": 0}
    assert [event["stage"] for event in trace["events"]] == [
        "intake", "validate", "fingerprint", "stage", "evaluate", "persist", "complete",
    ]
    serialized = json.dumps(trace)
    assert secret not in serialized
    assert "username demo" not in serialized
    assert "staged-evidence" in serialized
    assert str(session_dir) not in serialized


def test_activity_rejects_invalid_operation_and_bounds_completion(activity_client):
    client, name, _ = activity_client
    invalid = client.post(
        f"/api/session/{name}/activity/start",
        json={"operation_id": "bad", "mode": "file", "item_count": 1},
    )
    assert invalid.status_code == 400

    missing = client.post(
        f"/api/session/{name}/activity/op-12345678/complete",
        json={"status": "success", "succeeded": 1, "failed": 0},
    )
    assert missing.status_code == 404


def test_activity_empty_state_is_stable(activity_client):
    client, name, _ = activity_client
    response = client.get(f"/api/session/{name}/activity")
    assert response.status_code == 200
    assert response.get_json() == {
        "session": name,
        "operation_id": None,
        "status": "idle",
        "events": [],
    }
