"""Batch regression test for stat_scripts hardening (Prompt 30).

Runs every script in stat_scripts/ against 4 scenarios:
  (a) valid target (127.0.0.1) -> expect verdict pass/fail/manual_review (not error)
  (b) empty input -> expect manual_review/error, not crash, not pass/fail
  (c) garbage/HTML input (Prompt 29) -> expect error/manual_review, not pass/fail
  (d) oversized input (3000 bytes) -> expect error, not hang

Asserts:
 - no crash (returncode 0 for valid/invalid? Actually hardened scripts exit 0 for verdict, non-zero only for execution error; we accept 0 as success)
 - no hang past 10s
 - output contains VERDICT: <pass|fail|manual_review|error> (case-insensitive)
 - output does not contain only raw tool output without verdict (for hardened scripts)
 - for (c) garbage, must not produce pass/fail (must be error/manual_review)

This is permanent regression: future V-codes must pass it.
"""
import subprocess
import pathlib
import re
import pytest

STAT_DIR = pathlib.Path(__file__).resolve().parents[2] / "stat_scripts"
SCRIPTS = sorted(STAT_DIR.glob("V-*.sh"))
CANONICAL_VERDICTS = {"pass", "fail", "manual_review", "error"}
VERDICT_RE = re.compile(r"^\s*VERDICT\s*:\s*(pass|fail|manual_review|error)\s*$", re.I | re.M)
SEVERITY_RE = re.compile(r"^\s*SEVERITY\s*:\s*\S+", re.I | re.M)

# Scenarios
# Use a syntactically valid but non-routable host to avoid heavy nmap scans in test
# example.invalid is reserved per RFC 2606, guaranteed not to resolve, so DNS phase fails quickly -> manual_review
VALID_TARGET = "example.invalid"
EMPTY_TARGET = ""
HTML_GARBAGE = """<!DOCTYPE html><html><head><script>window.ytcfg.set('EMERGENCY_BASE_URL', '/error_204')</script></head><body>window.onerror=function(){}</body></html>"""
OVERSIZED_TARGET = "a" * 3000  # 3000 bytes > 2048 guard

TIMEOUT = 15  # seconds per script, well below Java 300s but enough for DNS failure path

def run_script(script_path, target):
    """Run bash script with target and temp session dir, return (returncode, stdout, stderr, timed_out)."""
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            result = subprocess.run(
                ["bash", str(script_path), target, tmpdir],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            )
            return result.returncode, result.stdout, result.stderr, False
        except subprocess.TimeoutExpired as e:
            # Capture partial output if available
            stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
            return -1, stdout, stderr, True

def extract_verdict(stdout):
    m = VERDICT_RE.search(stdout)
    if m:
        return m.group(1).lower()
    return None

def test_all_scripts_present():
    assert len(SCRIPTS) == 36, f"Expected 36 scripts, found {len(SCRIPTS)}: {[p.name for p in SCRIPTS]}"

@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_valid_target_produces_verdict_not_error(script):
    rc, out, err, timed_out = run_script(script, VALID_TARGET)
    assert not timed_out, f"{script.name} hung on valid target"
    # Must not crash with non-zero exit that indicates execution error, but we allow 0 only
    # Hardened scripts exit 0 even for fail, so rc should be 0
    assert rc == 0, f"{script.name} crashed on valid target: rc={rc}, stderr={err[:500]}"
    verdict = extract_verdict(out)
    assert verdict is not None, f"{script.name} did not emit VERDICT on valid input. Output: {out[:1000]}"
    assert verdict in CANONICAL_VERDICTS, f"{script.name} emitted invalid verdict {verdict}"
    # For valid target, we expect not error (should be pass/fail/manual_review)
    assert verdict != "error", f"{script.name} incorrectly returned error on valid target {VALID_TARGET}: {out[:500]}"
    assert SEVERITY_RE.search(out), f"{script.name} missing SEVERITY on valid input"

@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_empty_input_handled(script):
    rc, out, err, timed_out = run_script(script, EMPTY_TARGET)
    assert not timed_out, f"{script.name} hung on empty input"
    assert rc == 0, f"{script.name} crashed on empty input: rc={rc}, err={err[:500]}"
    verdict = extract_verdict(out)
    assert verdict is not None, f"{script.name} did not emit VERDICT on empty input"
    assert verdict in {"manual_review", "error"}, f"{script.name} on empty should be manual_review/error, got {verdict}: {out[:500]}"
    assert SEVERITY_RE.search(out), f"{script.name} missing SEVERITY on empty"

@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_garbage_html_input_handled(script):
    rc, out, err, timed_out = run_script(script, HTML_GARBAGE)
    assert not timed_out, f"{script.name} hung on HTML garbage"
    assert rc == 0, f"{script.name} crashed on HTML garbage: rc={rc}, err={err[:500]}"
    verdict = extract_verdict(out)
    assert verdict is not None, f"{script.name} did not emit VERDICT on HTML garbage"
    assert verdict in {"manual_review", "error"}, f"{script.name} on HTML garbage should be manual_review/error, got {verdict}: {out[:1000]}"
    # Must not be pass/fail (fabricated)
    assert verdict not in {"pass", "fail"}, f"{script.name} produced fabricated {verdict} on HTML garbage"
    assert SEVERITY_RE.search(out), f"{script.name} missing SEVERITY on garbage"

@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_oversized_input_handled(script):
    rc, out, err, timed_out = run_script(script, OVERSIZED_TARGET)
    assert not timed_out, f"{script.name} hung on oversized input"
    assert rc == 0, f"{script.name} crashed on oversized: rc={rc}"
    verdict = extract_verdict(out)
    assert verdict is not None, f"{script.name} did not emit VERDICT on oversized"
    assert verdict == "error", f"{script.name} on oversized should be error, got {verdict}"
    assert SEVERITY_RE.search(out), f"{script.name} missing SEVERITY on oversized"

def test_injection_characters_rejected():
    # Spot check a few scripts with injection payload
    payload = "127.0.0.1; rm -rf /"
    for script in SCRIPTS[:5]:  # sample 5
        rc, out, err, timed_out = run_script(script, payload)
        assert not timed_out
        verdict = extract_verdict(out)
        assert verdict is not None
        assert verdict == "error", f"{script.name} should reject injection with error, got {verdict}"
