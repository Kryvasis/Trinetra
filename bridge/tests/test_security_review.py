"""Regression tests: run from an isolated repository, never against user sessions."""
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit
import socket
import ssl
import json
import uuid

import pytest

from bridge.app import app, markdown_cells
from bridge import live_fetcher


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://localhost.evil.example:5173", "http://localhost:9999", "http://user@localhost:5173", "http://localhost:5173/path"])
def test_hostile_browser_cannot_mutate(origin):
    with patch("bridge.app.run_trinetra") as command:
        response = app.test_client().post("/api/session", json={"name": "blocked"}, headers={"Origin": origin})
    assert response.status_code == 403
    command.assert_not_called()


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5174", "http://[::1]:4173"])
def test_local_ui_origin_reaches_validation(origin):
    response = app.test_client().post("/api/session", json={}, headers={"Origin": origin})
    assert response.status_code == 400
    assert response.headers["Cache-Control"] == "no-store"


def test_rebinding_host_and_remote_peer_are_blocked():
    client = app.test_client()
    assert client.get("/api/status", headers={"Host": "evil.example:5000"}).status_code == 403
    assert client.get("/api/status", environ_overrides={"REMOTE_ADDR": "10.0.0.2"}).status_code == 403
    assert client.post("/api/session", json={}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


@pytest.mark.parametrize("url,header,token,match", [
    ("http://example.com/config", "Authorization", "secret", "HTTPS"),
    ("https://example.com/config", "Host", "secret", "headers must"),
    ("https://example.com/config", "Cookie", "secret", "headers must"),
    ("https://example.com/config", "Authorization", "secret\r\nx: value", "control characters"),
])
def test_unsafe_credentials_rejected_before_request(url, header, token, match):
    with patch.object(live_fetcher, "_validate_url", return_value=url), patch.object(live_fetcher.requests, "Session") as session:
        with pytest.raises(ValueError, match=match):
            live_fetcher.fetch_via_url(url, token, header)
        session.assert_not_called()


def address(ip):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]


def test_dns_rebinding_cannot_reach_private_address(monkeypatch):
    monkeypatch.delenv("TRINETRA_LIVE_FETCH_ALLOW_PRIVATE_URLS", raising=False)
    with patch.object(live_fetcher.socket, "getaddrinfo", side_effect=[address("93.184.216.34"), address("127.0.0.1")]), patch.object(live_fetcher.requests, "Session") as session:
        with pytest.raises(ValueError, match="public network"):
            live_fetcher.fetch_via_url("https://example.com/config")
        session.return_value.get.assert_not_called()


def test_pinned_pool_retains_tls_hostname():
    adapter = live_fetcher._PinnedAdapter(urlsplit("https://example.com/config"), "93.184.216.34")
    try:
        assert adapter.pinned_pool.host == "93.184.216.34"
        assert adapter.pinned_pool.assert_hostname == "example.com"
        assert adapter.pinned_pool.conn_kw["server_hostname"] == "example.com"
    finally:
        adapter.close()


def test_ssh_partial_failed_command_is_not_ingested():
    paramiko = MagicMock()
    stdout = MagicMock()
    stdout.read.return_value = b"partial configuration"
    stdout.channel.recv_exit_status.return_value = 1
    paramiko.SSHClient.return_value.exec_command.return_value = (None, stdout, MagicMock())
    with patch.dict("sys.modules", {"paramiko": paramiko}):
        with pytest.raises(live_fetcher.LiveFetchError, match="remote configuration command failed"):
            live_fetcher.fetch_via_ssh("router", "admin", "secret")
    paramiko.SSHClient.return_value.close.assert_called_once()


def test_unicode_upload_limit_is_bytes():
    with patch("bridge.app.run_java_helper") as helper:
        response = app.test_client().post("/api/session/size_test/upload-config", data=json.dumps({
            "device_id": "router", "config_content": "é" * (512 * 1024 + 1),
        }, ensure_ascii=False).encode("utf-8"), content_type="application/json")
    assert response.status_code == 413
    helper.assert_not_called()


def test_evidence_columns_preserve_missing_hardware_and_escaped_pipes():
    assert markdown_cells("| router | Cisco | | | | V-003 | manual_review | high | now |") == [
        "router", "Cisco", "", "", "", "V-003", "manual_review", "high", "now",
    ]
    assert markdown_cells(r"| router | IOS\|XE | |") == ["router", "IOS|XE", ""]


def test_tls_adapter_requires_certificate_verification():
    adapter = live_fetcher._PinnedAdapter(urlsplit("https://example.com/config"), "93.184.216.34")
    try:
        adapter.cert_verify(adapter.pinned_pool, "https://example.com/config", True, None)
        assert adapter.pinned_pool.cert_reqs == "CERT_REQUIRED"
        context = adapter.pinned_pool.conn_kw["ssl_context"]
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        assert context.get_ca_certs()
    finally:
        adapter.close()


@pytest.mark.parametrize("destination,expected_token", [
    ("https://example.com/next", True), ("https://other.example/config", False),
])
def test_redirect_auth_scope(destination, expected_token):
    first, last = MagicMock(), MagicMock()
    first.is_redirect = True
    first.headers = {"Location": destination}
    last.is_redirect = last.is_permanent_redirect = False
    last.headers = {}
    last.encoding = "utf-8"
    last.iter_content.return_value = [b"hostname router\n"]
    with patch.object(live_fetcher, "_validate_url", side_effect=lambda url: url), patch.object(live_fetcher, "_pin_destination", return_value=(MagicMock(), "example.com")), patch.object(live_fetcher.requests, "Session") as session:
        session.return_value.get.side_effect = [first, last]
        assert live_fetcher.fetch_via_url("https://example.com/config", "secret") == "hostname router\n"
        second_headers = session.return_value.get.call_args_list[1].kwargs["headers"]
        assert ("Authorization" in second_headers) == expected_token


def test_https_redirect_downgrade_rejected():
    first = MagicMock()
    first.is_redirect = True
    first.headers = {"Location": "http://example.com/config"}
    with patch.object(live_fetcher, "_validate_url", side_effect=lambda url: url), patch.object(live_fetcher, "_pin_destination", return_value=(MagicMock(), "example.com")), patch.object(live_fetcher.requests, "Session") as session:
        session.return_value.get.return_value = first
        with pytest.raises(ValueError, match="insecure"):
            live_fetcher.fetch_via_url("https://example.com/config", "secret")
        assert session.return_value.get.call_count == 1


def test_manual_review_is_not_a_failure_in_framework_score():
    client = app.test_client()
    session = "review_" + uuid.uuid4().hex[:10]
    assert client.post("/api/session", json={"name": session, "target": "router"}).status_code == 201
    response = client.post(f"/api/session/{session}/upload-config", json={
        "device_id": "router", "vendor": "Cisco", "config_content": "hostname router\n! incomplete evidence\n",
    })
    assert response.status_code == 200, response.get_json()
    score = client.get(f"/api/session/{session}/score").get_json()["score"]
    assert "not framework compliance" in score["score_basis"]
    frameworks = score["frameworks"].values()
    assert any(fw["tests_manual_review"] for fw in frameworks)
    for fw in frameworks:
        assert sum(fw[k] for k in ("tests_passed", "tests_failed", "tests_manual_review", "tests_errors", "tests_not_tested")) == fw["total_tests_mapped"]
        assert fw["tests_not_passed"] == fw["total_tests_mapped"] - fw["tests_passed"]
