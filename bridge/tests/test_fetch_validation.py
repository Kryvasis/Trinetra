"""Regression tests for fetch-config validation bypass (target 'aa' bug).

Bug: submitting an invalid target (\"aa\") to /fetch-config was not rejected and
resulted in HTML/JS being ingested as config with fabricated findings. This
suite ensures server-side validation rejects malformed targets before any fetch
and that content sanity catches HTML/error pages post-fetch.
"""
import shutil
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from bridge.app import app
from bridge.config_validation import is_plausible_config, looks_like_html


ROOT = Path(__file__).resolve().parents[2]
SAMPLE_CONFIG = """! Cisco IOS XE Software, Version 17.6.5
hostname R1
enable secret 5 $1$mocked$abc123
ip ssh version 2
"""

HTML_CONTENT = """<!DOCTYPE html><html><head><script>window.ytcfg.set('EMERGENCY_BASE_URL', '/error_204')</script></head><body><script>window.onerror=function(){}</script></body></html>"""

JS_ERROR_HTML = """window.ytcfg.set('EMERGENCY_BASE_URL', '/error_204?t=jserror&level=ERROR')
window.onerror=function(msg,url,line){var err=error;combinedLineAndColumn=err.lineNumber;}
values[key];if(value)parts.push(key+"="+encodeURIComponent(value))}img.src=parts
"""

def unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"

def cleanup(*sessions):
    for s in sessions:
        shutil.rmtree(ROOT / "sessions" / s, ignore_errors=True)

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

# ── 1. Server-side target validation — must reject before fetch ──

def test_rejects_target_aa_for_ip_without_fetch(client):
    sess = unique("test_val_aa_ip")
    try:
        assert client.post("/api/session", json={"name": sess, "target": "t"}).status_code == 201
        with patch("bridge.live_fetcher.fetch_config") as mocked:
            resp = client.post(f"/api/session/{sess}/fetch-config", json={
                "source_type": "ip",
                "target": "aa",
                "vendor": "Cisco",
                "device_id": "dev-01",
                "username": "admin",
                "password": "secret",
            })
        assert resp.status_code == 400, resp.get_data(as_text=True)
        assert "invalid" in resp.get_json()["error"].lower()
        mocked.assert_not_called()
    finally:
        cleanup(sess)

def test_rejects_target_aa_for_url_without_fetch(client):
    sess = unique("test_val_aa_url")
    try:
        assert client.post("/api/session", json={"name": sess, "target": "t"}).status_code == 201
        with patch("bridge.live_fetcher.fetch_config") as mocked:
            resp = client.post(f"/api/session/{sess}/fetch-config", json={
                "source_type": "url",
                "target": "aa",
                "vendor": "auto",
                "device_id": "dev-01",
            })
        assert resp.status_code == 400, resp.get_data(as_text=True)
        mocked.assert_not_called()
    finally:
        cleanup(sess)

def test_rejects_empty_target(client):
    sess = unique("test_val_empty")
    try:
        assert client.post("/api/session", json={"name": sess, "target": "t"}).status_code == 201
        with patch("bridge.live_fetcher.fetch_config") as mocked:
            for source_type, target in [("ip", ""), ("url", ""), ("ip", "   "), ("url", "   ")]:
                resp = client.post(f"/api/session/{sess}/fetch-config", json={
                    "source_type": source_type,
                    "target": target,
                    "vendor": "auto",
                    "device_id": "dev-01",
                    "username": "admin" if source_type == "ip" else None,
                    "password": "secret" if source_type == "ip" else None,
                })
                assert resp.status_code == 400, f"expected 400 for {source_type} {target!r}: {resp.get_data(as_text=True)}"
            mocked.assert_not_called()
    finally:
        cleanup(sess)

def test_rejects_not_a_url_and_http_prefix_only(client):
    sess = unique("test_val_malformed_url")
    try:
        assert client.post("/api/session", json={"name": sess, "target": "t"}).status_code == 201
        with patch("bridge.live_fetcher.fetch_config") as mocked:
            cases = [
                ("url", "not a url"),
                ("url", "http://"),
                ("url", "https://"),
                ("url", "http:///"),
                ("url", "ftp://example.com/config"),
                ("ip", "not a url"),  # spaces -> invalid hostname
                ("ip", "http://"),  # not a hostname
            ]
            for source_type, target in cases:
                body = {"source_type": source_type, "target": target, "vendor": "auto", "device_id": "dev-01"}
                if source_type == "ip":
                    body.update({"username": "admin", "password": "secret"})
                resp = client.post(f"/api/session/{sess}/fetch-config", json=body)
                assert resp.status_code == 400, f"expected 400 for {source_type} {target!r}: {resp.get_data(as_text=True)}"
            mocked.assert_not_called()
    finally:
        cleanup(sess)

def test_accepts_valid_ip_and_hostname_still_work(client):
    sess = unique("test_val_valid")
    try:
        assert client.post("/api/session", json={"name": sess, "target": "t"}).status_code == 201
        valid_cases = [
            ("ip", "10.0.0.1"),
            ("ip", "192.168.1.100"),
            ("ip", "edge-router.local"),
            ("ip", "cisco-lab-01.example.com"),
            ("url", "http://example.com/config"),
            ("url", "https://example.com/export/config.txt"),
        ]
        for source_type, target in valid_cases:
            with patch("bridge.live_fetcher.fetch_config", return_value=SAMPLE_CONFIG) as mocked:
                body = {"source_type": source_type, "target": target, "vendor": "auto", "device_id": "dev-01"}
                if source_type == "ip":
                    body.update({"username": "admin", "password": "secret"})
                resp = client.post(f"/api/session/{sess}/fetch-config", json=body)
                assert resp.status_code == 200, f"expected 200 for valid {source_type} {target!r}: {resp.get_data(as_text=True)}"
                mocked.assert_called_once()
            # cleanup device for next iteration by using unique device_id
            # we reuse same device_id but ingestion will append; that's fine
    finally:
        cleanup(sess)

# ── 2. Content sanity check after fetch ──

def test_rejects_html_content_after_fetch(client):
    sess = unique("test_sanity_html")
    try:
        assert client.post("/api/session", json={"name": sess, "target": "t"}).status_code == 201
        with patch("bridge.live_fetcher.fetch_config", return_value=HTML_CONTENT):
            resp = client.post(f"/api/session/{sess}/fetch-config", json={
                "source_type": "url",
                "target": "https://example.com/config",
                "vendor": "auto",
                "device_id": "dev-01",
            })
        # Should be 422, not 200 with fabricated findings
        assert resp.status_code == 422, resp.get_data(as_text=True)
        err = resp.get_json()["error"]
        assert ("does not appear to be a device configuration" in err or "webpage" in err.lower())
        # Ensure no findings were ingested (session should still have 0 findings)
        sess_file = ROOT / "sessions" / sess / f"{sess}.json"
        if sess_file.exists():
            import json
            data = json.loads(sess_file.read_text())
            assert len(data.get("findings", [])) == 0, "HTML should not have produced findings"
    finally:
        cleanup(sess)

def test_rejects_js_error_content_after_fetch(client):
    sess = unique("test_sanity_js")
    try:
        assert client.post("/api/session", json={"name": sess, "target": "t"}).status_code == 201
        with patch("bridge.live_fetcher.fetch_config", return_value=JS_ERROR_HTML):
            resp = client.post(f"/api/session/{sess}/fetch-config", json={
                "source_type": "ip",
                "target": "10.0.0.1",
                "vendor": "auto",
                "device_id": "dev-01",
                "username": "admin",
                "password": "secret",
            })
        assert resp.status_code == 422, resp.get_data(as_text=True)
    finally:
        cleanup(sess)

def test_content_sanity_heuristic_unit():
    # Direct unit test of heuristic
    assert looks_like_html(HTML_CONTENT) is True
    assert looks_like_html(JS_ERROR_HTML) is True
    assert looks_like_html(SAMPLE_CONFIG) is False
    ok, _ = is_plausible_config(SAMPLE_CONFIG)
    assert ok is True
    ok2, reason = is_plausible_config(HTML_CONTENT)
    assert ok2 is False
    assert "html" in reason.lower() or "config likeness" in reason.lower()
    # Config likeness ratio for SAMPLE_CONFIG should be >0.3, HTML should be <0.3
    from bridge.config_validation import config_likeness_ratio
    assert config_likeness_ratio(SAMPLE_CONFIG) > 0.30
    assert config_likeness_ratio(HTML_CONTENT) < 0.30

def test_valid_config_still_ingested_after_sanity(client):
    sess = unique("test_sanity_valid")
    try:
        assert client.post("/api/session", json={"name": sess, "target": "t"}).status_code == 201
        with patch("bridge.live_fetcher.fetch_config", return_value=SAMPLE_CONFIG):
            resp = client.post(f"/api/session/{sess}/fetch-config", json={
                "source_type": "ip",
                "target": "10.0.0.5",
                "vendor": "Cisco",
                "device_id": "valid-01",
                "username": "admin",
                "password": "secret",
            })
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert resp.get_json()["ingestion_method"] == "live_fetch"
    finally:
        cleanup(sess)
