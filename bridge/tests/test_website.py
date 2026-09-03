"""Deterministic website assessments: no external requests in the test suite."""
from copy import deepcopy
from io import BytesIO
import socket
import ssl
from unittest.mock import patch, MagicMock
import subprocess
from pathlib import Path

import pytest
from bridge import website
from bridge.app import app
from bridge.config_validation import is_web_document
from bridge.website_report import build_pdf


def observation(url="https://example.com/", status=200, **updates):
    result = dict(url=url, status=status, headers={"content-type": "text/html", "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; script-src 'nonce-secret'", "x-content-type-options": "nosniff"}, tls={"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "verification": "Verified", "certificate_expires": "Jan 1 00:00:00 2027 GMT"}, cookies=["session=do-not-expose; Secure; HttpOnly; SameSite=Lax"], location=None, peer_ip="93.184.216.34")
    result.update(updates)
    return result


def sample_report():
    with patch.object(website, "observe", return_value=observation()):
        return website.assess("https://example.com/?private=secret")


@pytest.mark.parametrize("url", [None, "", "file:///etc/passwd", "https://user:secret@example.com", "http://example.com:22", "https://example.com:80", "https://example.com/\nX:a", "https://example.com\\@localhost", "https://[bad", "https://example.com/" + "a" * 2048])
def test_url_validation(url):
    with pytest.raises(website.WebsiteError):
        website.validate_url(url)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "0.0.0.0"])
def test_private_targets_rejected_even_with_config_override(address, monkeypatch):
    monkeypatch.setenv("TRINETRA_LIVE_FETCH_ALLOW_PRIVATE_URLS", "true")
    with patch.object(socket, "getaddrinfo", return_value=[(2, 1, 6, "", (address, 443))]):
        with pytest.raises(website.WebsiteError, match="public"):
            website.public_address("example.com", 443)


def test_connects_to_pinned_ip_and_keeps_tls_hostname():
    conn = MagicMock()
    conn.getresponse.return_value.getheaders.return_value = [("Content-Type", "text/html")]
    conn.getresponse.return_value.status = 200
    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = {}
    tls_socket.cipher.return_value = ("cipher", "TLSv1.3", 256)
    with patch.object(website, "public_address", return_value="93.184.216.34"), patch.object(socket, "create_connection") as connect, patch.object(ssl, "create_default_context") as context, patch.object(website.http.client, "HTTPConnection", return_value=conn):
        context.return_value.wrap_socket.return_value = tls_socket
        website.observe("https://example.com/")
        connect.assert_called_once_with(("93.184.216.34", 443), timeout=8)
        assert context.return_value.wrap_socket.call_args.kwargs["server_hostname"] == "example.com"
        conn.getresponse.return_value.read.assert_not_called()
        conn.close.assert_called_once()


def test_redirect_and_redaction():
    hops = [observation(url="http://example.com/", status=301, tls=None, location="https://example.com/"), observation()]
    with patch.object(website, "observe", side_effect=hops):
        report = website.assess("http://example.com/?token=secret")
    assert report["findings"][0]["verdict"] == "fail"
    assert report["findings"][3]["verdict"] == "manual_review"
    assert "token=secret" not in str(report)
    assert "nonce-secret" not in str(report)
    assert "do-not-expose" not in str(report)
    assert "compliance_percentage" not in report
    assert sum(report["counts"].values()) == 10


def test_private_redirect_is_revalidated():
    with patch.object(website, "observe", side_effect=[observation(status=302, location="https://127.0.0.1/"), website.WebsiteError("public only")]) as observe:
        with pytest.raises(website.WebsiteError, match="public"):
            website.assess("https://example.com/")
        assert observe.call_args.args[0] == "https://127.0.0.1/"


@pytest.mark.parametrize("location", ["http://example.com/", "file:///etc/passwd", "https://user:pass@example.com/"])
def test_unsafe_redirect_stops(location):
    with patch.object(website, "observe", return_value=observation(status=302, location=location)) as observe:
        with pytest.raises(website.WebsiteError):
            website.assess("https://example.com/")
        assert observe.call_count == 1


def test_redirect_limit():
    with patch.object(website, "observe", side_effect=[observation(status=302, location="/again") for _ in range(4)]) as observe:
        with pytest.raises(website.WebsiteError, match="three redirects"):
            website.assess("https://example.com/")
        assert observe.call_count == 4


@pytest.mark.parametrize("hsts", ["", "max-age=0", "max-age=nonsense", "max-age=20, max-age=30"])
def test_invalid_hsts_is_not_pass(hsts):
    hop = observation()
    hop["headers"]["strict-transport-security"] = hsts
    assert website.findings_for([hop])[2]["verdict"] == "manual_review"


def test_absent_cookies_and_tls_are_not_tested():
    findings = website.findings_for([observation(tls=None, cookies=[])])
    assert findings[1]["verdict"] == findings[7]["verdict"] == "not_tested"


@pytest.mark.parametrize("html", ["<!DOCTYPE html><html>youtube</html>", "\ufeff  <!-- comment --> <HTML lang='en'>", "<head><title>error</title>"])
def test_html_rejected_before_java(html):
    assert is_web_document(html)
    with patch("bridge.app.run_java_helper") as java:
        response = app.test_client().post("/api/session/test/upload-config", json={"device_id": "device", "config_content": html})
        assert response.status_code == 422
        java.assert_not_called()
    with patch("bridge.app.os.path.exists", return_value=True), patch("bridge.app.run_java_helper") as java, patch("bridge.live_fetcher.fetch_config", return_value=html):
        response = app.test_client().post("/api/session/test/fetch-config", json={"device_id": "device", "source_type": "url", "target": "https://example.com/", "vendor": "auto"})
        assert response.status_code == 422
        java.assert_not_called()


def test_device_configs_are_not_html():
    assert not is_web_document("hostname edge\nip ssh version 2\n!")
    assert not is_web_document("set system host-name edge\nset system services ssh")


def test_api_success_and_pdf_uses_same_signed_observation():
    client = app.test_client()
    with patch.object(website, "observe", return_value=observation()), patch("bridge.app.run_java_helper") as java:
        response = client.post("/api/website/analyze", json={"url": "https://example.com/", "acknowledged": True})
        assert response.status_code == 200
        data = response.get_json()
        java.assert_not_called()
    with patch.object(website, "observe") as observe:
        pdf = client.post("/api/website/report/pdf", json={"report_token": data["report_token"]})
        assert pdf.status_code == 200
        assert pdf.data.startswith(b"%PDF")
        assert pdf.headers["Cache-Control"] == "no-store"
        observe.assert_not_called()
    assert client.post("/api/website/report/pdf", json={"report_token": data["report_token"] + "tampered"}).status_code == 400


@pytest.mark.parametrize("payload", [None, [], {}, {"url": "https://example.com/", "acknowledged": "yes"}])
def test_api_requires_explicit_scope_acknowledgement(payload):
    assert app.test_client().post("/api/website/analyze", json=payload).status_code == 400


def test_certificate_failure_does_not_create_findings():
    with patch.object(website, "assess", side_effect=ssl.SSLCertVerificationError("secret target details")):
        response = app.test_client().post("/api/website/analyze", json={"url": "https://example.com/", "acknowledged": True})
    assert response.status_code == 502
    assert "secret" not in response.get_data(as_text=True)
    assert "report" not in response.get_json()


def test_pdf_text_contains_evidence_actions_and_scope():
    PdfReader = pytest.importorskip("pypdf", reason="Optional PDF text verification dependency").PdfReader
    report = sample_report()
    text = "\n".join(page.extract_text() for page in PdfReader(BytesIO(build_pdf(report))).pages)
    for value in ["CORTEX", "Observed evidence", "Recommended action", "How to verify", "Scope and limitations", "WEB-10"]:
        assert value in text
    assert "do-not-expose" not in text


def test_pdf_handles_long_escaped_evidence():
    report = deepcopy(sample_report())
    report["findings"][0]["evidence"] = "<script>&" * 400
    assert build_pdf(report).startswith(b"%PDF")


def test_java_ingestion_rejects_html_before_session_mutation(tmp_path):
    root = Path(__file__).resolve().parents[2]
    config = tmp_path / "webpage.html"
    config.write_text("<!doctype html><html>not a device</html>")
    result = subprocess.run(["java", f"-Dtrinetra.root={tmp_path}", "-cp", str(root / "out"), "TrinetraBridgeHelper", "ingest-config", "website_guard", "device", "Cisco", str(config)], capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert "Webpages are not device configurations" in result.stdout + result.stderr
    assert not (tmp_path / "sessions" / "website_guard").exists()


def test_pdf_rejects_expired_token():
    with patch.object(website.time, "time", return_value=1000):
        token = website._signer.dumps(sample_report())
    assert app.test_client().post("/api/website/report/pdf", json={"report_token": token}).status_code == 400


def test_busy_assessment_has_retryable_response():
    website._slots.acquire()
    website._slots.acquire()
    try:
        response = app.test_client().post("/api/website/analyze", json={"url": "https://example.com/", "acknowledged": True})
        assert response.status_code == 429
    finally:
        website._slots.release()
        website._slots.release()
