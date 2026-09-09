"""Regression: /compare endpoint uses last-two-per-V-code history with four-way terms.

Fast, no network probes: builds brain_state normalized_results directly.
"""
import json
import shutil
import uuid
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bridge.app import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SESSIONS_DIR = PROJECT_ROOT / "sessions"


def _client():
    app.config["TESTING"] = True
    return app.test_client()


def _mk_session(c, sess):
    r = c.post("/api/session", json={"name": sess, "target": "127.0.0.1"})
    assert r.status_code == 201, r.get_data(as_text=True)


def _write_chain(sess, entries):
    p = SESSIONS_DIR / sess / f"brain_state_{sess}.json"
    d = json.load(open(p))
    d["normalized_results"] = entries
    json.dump(d, open(p, "w"), indent=2)


def _e(dev, tid, verdict, ts, kind="configuration_only"):
    return {"device_id": dev, "vendor": "Cisco", "test_id": tid,
            "raw_output": "x", "normalized_result": verdict,
            "assessment_kind": kind, "timestamp": ts}


def test_compare_resolved_unresolved():
    c = _client()
    sess, dev = f"cmp_{uuid.uuid4().hex[:8]}", "r1"
    try:
        _mk_session(c, sess)
        _write_chain(sess, [
            _e(dev, "V-003", "fail", "2026-01-01T00:00:00Z"),
            _e(dev, "V-003", "pass", "2026-01-02T00:00:00Z"),
            _e(dev, "V-005", "manual_review", "2026-01-01T00:00:00Z"),
            _e(dev, "V-005", "manual_review", "2026-01-02T00:00:00Z"),
            _e(dev, "V-006", "pass", "2026-01-02T00:00:00Z"),
        ])
        r = c.get(f"/api/session/{sess}/compare?device_id={dev}")
        assert r.status_code == 200, r.get_data(as_text=True)
        d = r.get_json()
        by = {x["test_id"]: x for x in d["comparisons"]}
        assert by["V-003"]["transition"] == "resolved", by["V-003"]
        assert by["V-003"]["before"]["finding_class"] == "confirmed risk"
        assert by["V-003"]["after"]["finding_class"] == "verified pass"
        assert by["V-005"]["transition"] == "still unresolved", by["V-005"]
        assert by["V-005"]["after"]["finding_class"] == "unsupported check"
        assert by["V-006"]["transition"] == "unchanged", by["V-006"]
        assert d["summary"]["resolved"] == 1
        assert "no new storage" in d["basis"]
    finally:
        p = SESSIONS_DIR / sess
        if p.exists():
            shutil.rmtree(p)


def test_compare_regression():
    c = _client()
    sess, dev = f"cmp_{uuid.uuid4().hex[:8]}", "r1"
    try:
        _mk_session(c, sess)
        _write_chain(sess, [
            _e(dev, "V-071", "pass", "2026-01-01T00:00:00Z"),
            _e(dev, "V-071", "fail", "2026-01-02T00:00:00Z"),
        ])
        r = c.get(f"/api/session/{sess}/compare?device_id={dev}")
        assert r.status_code == 200
        by = {x["test_id"]: x for x in r.get_json()["comparisons"]}
        assert by["V-071"]["transition"] == "newly failing", by["V-071"]
    finally:
        p = SESSIONS_DIR / sess
        if p.exists():
            shutil.rmtree(p)
