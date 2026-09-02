import json
import shutil
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from bridge import live_fetcher
from bridge.app import app


SAMPLE_CONFIG = """! Cisco IOS XE Software, Version 17.6.5
hostname R1
enable secret 5 $1$mocked$abc123
ip ssh version 2
snmp-server community public RO
logging host 10.10.1.100
line vty 0 4
 exec-timeout 5 0
"""
ROOT = Path(__file__).resolve().parents[2]


def unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def cleanup(*sessions):
    for session in sessions:
        shutil.rmtree(ROOT / "sessions" / session, ignore_errors=True)


def test_fetcher_rejects_private_urls_and_server_key_paths():
    with pytest.raises(ValueError, match="public network"):
        live_fetcher._validate_url("http://127.0.0.1/config")
    with pytest.raises(ValueError, match="embedded"):
        live_fetcher._validate_url("https://admin:secret@example.com/config")
    with pytest.raises(ValueError, match="file paths"):
        live_fetcher._read_private_key(object(), "/etc/ssh/ssh_host_rsa_key", None)


def test_vendor_commands_have_safe_fallback():
    assert live_fetcher.get_vendor_command("Juniper") == "show configuration | display set"
    assert live_fetcher.get_vendor_command("unknown") == "show running-config"


def test_mocked_live_fetch_uses_upload_pipeline_without_persisting_credentials():
    client = app.test_client()
    live_session = unique("test_fetch_ip")
    upload_session = unique("test_fetch_upload")
    try:
        assert client.post("/api/session", json={"name": live_session, "target": "live-device"}).status_code == 201
        assert client.post("/api/session", json={"name": upload_session, "target": "upload-device"}).status_code == 201

        with patch("bridge.live_fetcher.fetch_config", return_value=SAMPLE_CONFIG) as mocked_fetch:
            response = client.post(f"/api/session/{live_session}/fetch-config", json={
                "source_type": "ip",
                "target": "10.0.0.1",
                "vendor": "Cisco",
                "device_id": "edge-live-01",
                "username": "admin",
                "password": "DoNotPersistThis!",
                "hardware_model": "C9300-48P",
            })
        assert response.status_code == 200, response.get_data(as_text=True)
        live_result = response.get_json()
        assert live_result["ingestion_method"] == "live_fetch"
        mocked_fetch.assert_called_once()

        upload_response = client.post(f"/api/session/{upload_session}/upload-config", json={
            "device_id": "edge-live-01",
            "vendor": "Cisco",
            "config_content": SAMPLE_CONFIG,
            "filename": "edge-live-01.txt",
            "hardware_model": "C9300-48P",
        })
        assert upload_response.status_code == 200, upload_response.get_data(as_text=True)
        upload_result = upload_response.get_json()
        assert upload_result["ingestion_method"] == "config_upload"
        assert (live_result["total_checks"], live_result["passed"], live_result["failed"]) == (
            upload_result["total_checks"], upload_result["passed"], upload_result["failed"],
        )

        live_session_file = ROOT / "sessions" / live_session / f"{live_session}.json"
        live_brain_file = ROOT / "sessions" / live_session / f"brain_state_{live_session}.json"
        persisted = live_session_file.read_text() + live_brain_file.read_text()
        assert "DoNotPersistThis!" not in persisted
        brain = json.loads(live_brain_file.read_text())
        device_results = [r for r in brain["normalized_results"] if r["device_id"] == "edge-live-01"]
        assert device_results
        assert all(r["ingestion_method"] == "live_fetch" for r in device_results)
    finally:
        cleanup(live_session, upload_session)


def test_fetch_failure_is_generic_and_does_not_echo_secret():
    client = app.test_client()
    session = unique("test_fetch_failure")
    secret = "NeverEchoThisCredential!"
    try:
        assert client.post("/api/session", json={"name": session, "target": "live-device"}).status_code == 201
        with patch("bridge.live_fetcher.fetch_config", side_effect=RuntimeError(f"failed with {secret}")):
            response = client.post(f"/api/session/{session}/fetch-config", json={
                "source_type": "ip",
                "target": "10.0.0.2",
                "vendor": "Cisco",
                "device_id": "edge-live-02",
                "username": "admin",
                "password": secret,
            })
        assert response.status_code == 502
        assert secret not in response.get_data(as_text=True)
    finally:
        cleanup(session)
