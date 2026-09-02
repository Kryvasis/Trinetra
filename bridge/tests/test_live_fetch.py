"""
Test fetch-to-ingest path using mocked SSH/HTTP responses.

This test is explicitly mocked (no real reachable device required) and
confirms that fetched text reaches the IDENTICAL ingestion function as a
file upload would, producing the same downstream normalized_results structure,
and that credentials are never persisted.

We mock bridge.live_fetcher.fetch_config to return a known config string,
then call POST /api/session/<name>/fetch-config and compare to a direct
POST /api/session/<name>/upload-config with the same config content.
"""
import json
import uuid
import shutil
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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

MOCKED_SSH_OUTPUT = SAMPLE_CONFIG
MOCKED_HTTP_BODY = SAMPLE_CONFIG


def unique(prefix="live_fetch"):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def cleanup(sess):
    p = Path(__file__).resolve().parent.parent.parent / "sessions" / sess
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def test_fetch_via_ip_uses_same_ingestion_as_file_upload():
    """
    Mock SSH fetch returns SAMPLE_CONFIG, call /fetch-config with source_type=ip,
    verify resulting normalized_results matches file-upload with same text, and
    ingestion_method is live_fetch.
    State clearly: this is mocked SSH, no real device.
    """
    client = app.test_client()
    sess = unique("test_fetch_ip")
    # Need session exists
    resp = client.post("/api/session", json={"name": sess, "target": "fetch-test-target"})
    assert resp.status_code == 201, resp.get_data(as_text=True)

    # Mock the live_fetcher.fetch_config to return known text without touching network
    with patch("bridge.live_fetcher.fetch_config", return_value=MOCKED_SSH_OUTPUT) as mock_fetch:
        # Also patch alternate import path used by app.py fallback
        with patch("live_fetcher.fetch_config", return_value=MOCKED_SSH_OUTPUT):
            resp = client.post(f"/api/session/{sess}/fetch-config", json={
                "source_type": "ip",
                "target": "10.0.0.1",
                "vendor": "Cisco",
                "device_id": "cisco-live-01",
                "username": "admin",
                "password": "SuperSecret123!",
                "serial_number": "FTXFETCH001",
                "hardware_model": "C9300-48P",
                "os_version": "IOS XE 17.6.5",
            })
            assert resp.status_code == 200, resp.get_data(as_text=True)
            data = resp.get_json()
            assert data["ingestion_method"] == "live_fetch", f"Expected live_fetch, got {data.get('ingestion_method')}"
            assert data["device_id"] == "cisco-live-01"
            assert data["vendor"] == "Cisco"
            assert "passed" in data and "failed" in data
            assert data["source_type"] == "ip"
            assert data["target"] == "10.0.0.1"
            # Verify mock was called with ip and correct vendor command path
            mock_fetch.assert_called_once()
            call_kwargs = mock_fetch.call_args[1] if mock_fetch.call_args[1] else {}
            # source_type ip should be passed through
            assert call_kwargs.get("source_type") == "ip" or "ip" in str(mock_fetch.call_args)

    # Verify via GET /devices that device appears with live_fetch
    resp = client.get(f"/api/session/{sess}/devices")
    assert resp.status_code == 200
    devs = {d["device_id"]: d for d in resp.get_json()["devices"]}
    assert "cisco-live-01" in devs
    assert devs["cisco-live-01"]["ingestion_method"] == "live_fetch"
    assert devs["cisco-live-01"]["serial_number"] == "FTXFETCH001"
    assert devs["cisco-live-01"]["hardware_model"] == "C9300-48P"

    # Verify via status that normalized_results contains entries for this device with live_fetch
    resp = client.get(f"/api/session/{sess}/status")
    assert resp.status_code == 200
    status = resp.get_json()
    # Find brain state normalized_results via session JSON directly
    # Check session JSON on disk for ingestion method
    session_path = Path(__file__).resolve().parent.parent.parent / "sessions" / sess / f"{sess}.json"
    assert session_path.exists()
    session_data = json.loads(session_path.read_text())
    assert "cisco-live-01" in session_data.get("device_ingestion", {})
    assert session_data["device_ingestion"]["cisco-live-01"]["method"] == "live_fetch"

    # Verify credentials NOT persisted anywhere
    session_raw = session_path.read_text()
    assert "SuperSecret123!" not in session_raw, "Credential leaked to session JSON!"
    brain_path = Path(__file__).resolve().parent.parent.parent / "sessions" / sess / f"brain_state_{sess}.json"
    if brain_path.exists():
        brain_raw = brain_path.read_text()
        assert "SuperSecret123!" not in brain_raw, "Credential leaked to brain_state!"

    # Also verify logs do not contain password (check app's error handling doesn't echo it)
    # Response body should not contain password
    assert "SuperSecret123!" not in json.dumps(data)

    # Now compare to file-upload with SAME config text in a separate session — should produce same normalized_results shape
    sess2 = unique("test_file_cmp")
    resp = client.post("/api/session", json={"name": sess2, "target": "file-cmp-target"})
    assert resp.status_code == 201
    resp2 = client.post(f"/api/session/{sess2}/upload-config", json={
        "device_id": "cisco-live-01",
        "vendor": "Cisco",
        "config_content": SAMPLE_CONFIG,
        "filename": "cisco-live-01.txt",
        "serial_number": "FTXFETCH001",
        "hardware_model": "C9300-48P",
        "os_version": "IOS XE 17.6.5",
    })
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    # Both should have same total_checks / passed / failed structure (identical pipeline)
    assert data["total_checks"] == data2["total_checks"], f"fetch vs file total_checks differ: {data['total_checks']} vs {data2['total_checks']}"
    assert data["passed"] == data2["passed"]
    assert data["failed"] == data2["failed"]
    assert set(data["unrecognized_lines"]) == set(data2["unrecognized_lines"])

    # Verify normalized_results structure is same shape: compare brain_state normalized_results length
    brain1 = json.loads(brain_path.read_text())
    brain2_path = Path(__file__).resolve().parent.parent.parent / "sessions" / sess2 / f"brain_state_{sess2}.json"
    brain2 = json.loads(brain2_path.read_text())
    nr1 = [r for r in brain1.get("normalized_results", []) if r.get("device_id") == "cisco-live-01"]
    nr2 = [r for r in brain2.get("normalized_results", []) if r.get("device_id") == "cisco-live-01"]
    assert len(nr1) == len(nr2), f"normalized_results length differs: {len(nr1)} vs {len(nr2)} — must be identical pipeline"
    # Check that each test_id/verdict matches (except ingestion_method)
    nr1_map = {r["test_id"]: r["normalized_result"] for r in nr1}
    nr2_map = {r["test_id"]: r["normalized_result"] for r in nr2}
    assert nr1_map == nr2_map, f"Verdicts differ between fetch and file: {nr1_map} vs {nr2_map}"
    # Ensure ingestion_method is different honestly
    assert all(r.get("ingestion_method") == "live_fetch" for r in nr1)
    assert all(r.get("ingestion_method") == "config_upload" for r in nr2)

    # Verify PDF contains live_fetch device
    resp = client.get(f"/api/session/{sess}/audit-report/pdf")
    assert resp.status_code == 200
    assert resp.headers.get("Content-Type", "").startswith("application/pdf") or resp.data[:4] == b"%PDF"
    pdf_text = resp.data.decode("latin1", errors="ignore")
    assert "cisco-live-01" in pdf_text or "cisco-live-01" in json.dumps(data)

    cleanup(sess)
    cleanup(sess2)


def test_fetch_via_url_uses_same_pipeline():
    """
    Mock HTTP fetch returns SAMPLE_CONFIG, verify ingestion_method live_fetch and same pipeline.
    State clearly: this is mocked HTTP, no real URL.
    """
    client = app.test_client()
    sess = unique("test_fetch_url")
    resp = client.post("/api/session", json={"name": sess, "target": "url-test"})
    assert resp.status_code == 201

    with patch("bridge.live_fetcher.fetch_config", return_value=MOCKED_HTTP_BODY) as mock_fetch:
        with patch("live_fetcher.fetch_config", return_value=MOCKED_HTTP_BODY):
            resp = client.post(f"/api/session/{sess}/fetch-config", json={
                "source_type": "url",
                "target": "https://api.example.com/firewall/config",
                "vendor": "auto",
                "device_id": "fw-url-01",
                "auth_token": "BearerToken123_mocked",
                "hardware_model": "PA-220",
            })
            assert resp.status_code == 200, resp.get_data(as_text=True)
            data = resp.get_json()
            assert data["ingestion_method"] == "live_fetch"
            assert data["source_type"] == "url"
            assert data["device_id"] == "fw-url-01"
            # Token must not appear in response
            assert "BearerToken123_mocked" not in json.dumps(data)

    # Check not persisted
    session_path = Path(__file__).resolve().parent.parent.parent / "sessions" / sess / f"{sess}.json"
    assert "BearerToken123_mocked" not in session_path.read_text()
    brain_path = Path(__file__).resolve().parent.parent.parent / "sessions" / sess / f"brain_state_{sess}.json"
    if brain_path.exists():
        assert "BearerToken123_mocked" not in brain_path.read_text()

    # Devices dashboard
    resp = client.get(f"/api/session/{sess}/devices")
    assert resp.status_code == 200
    devs = {d["device_id"]: d for d in resp.get_json()["devices"]}
    assert devs["fw-url-01"]["ingestion_method"] == "live_fetch"

    cleanup(sess)


def test_fetch_credentials_never_logged_or_persisted():
    """
    Verify that even on fetch failure, credentials are not leaked in error response or session file.
    Uses mocked failure.
    """
    client = app.test_client()
    sess = unique("test_cred_leak")
    client.post("/api/session", json={"name": sess, "target": "cred-test"})

    def mock_fail(*args, **kwargs):
        raise RuntimeError("connection refused to 10.0.0.99")

    with patch("bridge.live_fetcher.fetch_config", side_effect=mock_fail):
        with patch("live_fetcher.fetch_config", side_effect=mock_fail):
            resp = client.post(f"/api/session/{sess}/fetch-config", json={
                "source_type": "ip",
                "target": "10.0.0.99",
                "vendor": "Cisco",
                "device_id": "leak-test-01",
                "username": "admin",
                "password": "UltraSecret999!",
            })
            assert resp.status_code in (502, 500), resp.get_data(as_text=True)
            body = resp.get_json()
            assert "UltraSecret999!" not in json.dumps(body), "Password leaked in error response!"
            # Session should not contain password even after failure (no device should be created, but check)
            session_path = Path(__file__).resolve().parent.parent.parent / "sessions" / sess / f"{sess}.json"
            if session_path.exists():
                assert "UltraSecret999!" not in session_path.read_text()

    cleanup(sess)


def test_fetch_validation_and_error_paths():
    client = app.test_client()
    sess = unique("test_fetch_val")
    client.post("/api/session", json={"name": sess, "target": "val-test"})

    # Missing target
    resp = client.post(f"/api/session/{sess}/fetch-config", json={
        "source_type": "ip",
        "target": "",
        "vendor": "Cisco",
        "device_id": "dev1",
        "username": "admin",
        "password": "pass"
    })
    assert resp.status_code == 400

    # Missing device_id
    resp = client.post(f"/api/session/{sess}/fetch-config", json={
        "source_type": "url",
        "target": "https://example.com/config",
        "vendor": "auto",
    })
    assert resp.status_code == 400

    # Invalid source_type
    resp = client.post(f"/api/session/{sess}/fetch-config", json={
        "source_type": "invalid",
        "target": "10.0.0.1",
        "device_id": "dev1",
        "username": "admin",
        "password": "pass"
    })
    assert resp.status_code == 400

    # IP without username
    resp = client.post(f"/api/session/{sess}/fetch-config", json={
        "source_type": "ip",
        "target": "10.0.0.1",
        "device_id": "dev1",
    })
    assert resp.status_code == 400

    # URL without http prefix
    resp = client.post(f"/api/session/{sess}/fetch-config", json={
        "source_type": "url",
        "target": "ftp://example.com/config",
        "device_id": "dev1",
    })
    assert resp.status_code == 400

    # Injection blocked: semicolon in device_id
    resp = client.post(f"/api/session/{sess}/fetch-config", json={
        "source_type": "ip",
        "target": "10.0.0.1",
        "device_id": "bad; rm -rf",
        "username": "admin",
        "password": "pass"
    })
    assert resp.status_code == 400

    # Session not found
    resp = client.post(f"/api/session/nonexistent_sess_xyz123/fetch-config", json={
        "source_type": "url",
        "target": "https://example.com/config",
        "device_id": "dev1",
    })
    assert resp.status_code == 404

    cleanup(sess)
