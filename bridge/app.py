import re
import subprocess
import json
import os
import shlex
from pathlib import Path
from flask import Flask, request, jsonify

try:
    from bridge.config import (
        TRINETRA_BIN,
        TRINETRA_ROOT,
        JAVA_OUT,
        JAVA_LIB,
        SUBPROCESS_TIMEOUT,
        FLASK_SECRET,
    )
except ImportError:
    from config import (
        TRINETRA_BIN,
        TRINETRA_ROOT,
        JAVA_OUT,
        JAVA_LIB,
        SUBPROCESS_TIMEOUT,
        FLASK_SECRET,
    )

app = Flask(__name__)
app.secret_key = FLASK_SECRET

# ── Validation regexes (reject before subprocess) ──
SESSION_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
TEST_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")  # e.g. V-003, T-SHARED, T_CISCO
# device_id: allow IP, hostname, simple identifiers; reject shell metachars
DEVICE_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")
VENDOR_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")

# Block obvious injection characters even if regex would allow (defense in depth)
INJECTION_CHARS = set(';|&$`><\\\'"*\n\r')

def contains_injection(s: str) -> bool:
    if not isinstance(s, str):
        return True
    return any(c in s for c in INJECTION_CHARS)

def validate_session(name: str):
    if not isinstance(name, str) or not SESSION_RE.match(name) or contains_injection(name):
        return False
    return True

def validate_test_id(tid: str):
    if not isinstance(tid, str) or not TEST_ID_RE.match(tid) or contains_injection(tid):
        return False
    # Enforce typical test_id shape: at least one hyphen or at least 2 chars
    return True

def validate_device(did: str):
    if not isinstance(did, str) or not DEVICE_RE.match(did) or contains_injection(did):
        return False
    return True

def validate_vendor(v: str):
    if not isinstance(v, str) or not VENDOR_RE.match(v) or contains_injection(v):
        return False
    return True

# ── Subprocess helpers ──
def run_trinetra(args, timeout=SUBPROCESS_TIMEOUT):
    """
    Run trinetra CLI via subprocess without shell.
    args: list of CLI args, e.g. ["-new", "sess", "target"]
    Returns (returncode, stdout, stderr)
    """
    cmd = [TRINETRA_BIN] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "", f"trinetra timed out after {timeout}s: {e}"
    except FileNotFoundError as e:
        return 127, "", f"trinetra binary not found at {TRINETRA_BIN}: {e}"
    except Exception as e:
        return 1, "", f"subprocess error: {e}"

def run_java_helper(class_name, args, timeout=SUBPROCESS_TIMEOUT):
    """
    Run a Java helper class via java -Dtrinetra.root -cp out:lib/* <class> <args>
    """
    java_bin = "java"
    cp = f"{JAVA_OUT}:{JAVA_LIB}"
    cmd = [java_bin, f"-Dtrinetra.root={TRINETRA_ROOT}", "-cp", cp, class_name] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "", f"java helper timed out after {timeout}s: {e}"
    except Exception as e:
        return 1, "", f"java helper error: {e}"

def error_response(message, status=400, details=None):
    body = {"error": message}
    if details:
        body["details"] = details
    return jsonify(body), status

# ── Health ──
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "trinetra_bin": TRINETRA_BIN, "trinetra_root": TRINETRA_ROOT})

# ── POST /api/session — create new session ──
@app.route("/api/session", methods=["POST"])
def create_session():
    data = request.get_json(silent=True) or {}
    # Support both "name" and "session_name"
    name = data.get("name") or data.get("session_name") or data.get("session")
    target = data.get("target") or data.get("device_id") or data.get("address")

    if not name or not target:
        return error_response("missing required fields: name and target", 400)
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r} (allowed: {SESSION_RE.pattern})", 400)
    if not isinstance(target, str) or contains_injection(target) or len(target) > 256 or len(target) < 1:
        return error_response(f"invalid target: {target!r}", 400)
    # Sanitize target for subprocess: we pass as single arg, but validate no injection
    if any(c in target for c in [';', '&', '|', '$', '`', '>', '<', '\n', '\r']):
        return error_response("target contains illegal characters", 400)

    rc, out, err = run_trinetra(["-new", name, target])
    if rc != 0:
        # Distinguish 4xx vs 5xx: if session already exists or invalid, 400; else 500
        msg = (err.strip() or out.strip()) or "failed to create session"
        # Check if session already exists (common case)
        if "already exists" in msg.lower() or "failed to create" in msg.lower():
            return error_response(msg, 409)
        return error_response(msg, 500, {"stdout": out, "stderr": err, "returncode": rc})
    return jsonify({"message": out.strip(), "session": name, "target": target, "stderr": err.strip()}), 201

# ── POST /api/session/<name>/run — run tests ──
@app.route("/api/session/<name>/run", methods=["POST"])
def run_tests(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)

    data = request.get_json(silent=True) or {}
    # Support multiple input shapes
    # - single device: { "device_id": "...", "vendor": "...", "test_ids": [...] }
    # - multi-device: { "devices": [{"device_id": "...", "vendor": "..."} ], "test_ids": [...] }
    # - legacy: { "target": "...", "test_ids": [...] }
    test_ids = data.get("test_ids") or data.get("tests") or data.get("test_id") or []
    if isinstance(test_ids, str):
        test_ids = [test_ids]
    if not isinstance(test_ids, list) or not test_ids:
        return error_response("missing or empty test_ids (list of test ids required)", 400)
    # Validate each test_id
    for tid in test_ids:
        if not validate_test_id(tid):
            return error_response(f"invalid test_id: {tid!r}", 400)

    # Workers (optional)
    workers = data.get("workers", 1)
    try:
        workers = int(workers)
        if workers < 1 or workers > 32:
            raise ValueError
    except:
        return error_response("workers must be integer 1..32", 400)

    # Device handling
    devices = []
    # Case 1: explicit devices array
    if "devices" in data and isinstance(data["devices"], list):
        for entry in data["devices"]:
            if not isinstance(entry, dict):
                return error_response("each device entry must be an object with device_id", 400)
            did = entry.get("device_id") or entry.get("target") or entry.get("id")
            ven = entry.get("vendor") or entry.get("vendor_hint")
            if not did:
                return error_response("device entry missing device_id", 400)
            if not validate_device(did):
                return error_response(f"invalid device_id: {did!r}", 400)
            if ven and not validate_vendor(ven):
                return error_response(f"invalid vendor: {ven!r}", 400)
            devices.append((did, ven))
    else:
        # Single device case
        did = data.get("device_id") or data.get("target") or data.get("address")
        ven = data.get("vendor") or data.get("vendor_hint")
        # If no device_id provided, fallback to session's target (use name as device?)
        # Require at least device_id for clarity
        if not did:
            return error_response("missing device_id (or target) for run", 400)
        if not validate_device(did):
            return error_response(f"invalid device_id: {did!r}", 400)
        if ven and not validate_vendor(ven):
            return error_response(f"invalid vendor: {ven!r}", 400)
        devices.append((did, ven))

    # For each device, if vendor hint provided, set device vendor via Java helper
    # This must happen before stat run, and we must propagate failures as 4xx/5xx
    for did, ven in devices:
        if ven:
            rc, out, err = run_java_helper("TrinetraBridgeHelper", ["set-vendor", name, did, ven])
            if rc != 0:
                msg = (err.strip() or out.strip()) or f"failed to set vendor for device {did}"
                return error_response(msg, 500, {"stdout": out, "stderr": err, "device_id": did, "vendor": ven})

    # Now run tests per device
    # Use --tests comma-separated via run-all for each device
    # For single device with single test_id, we could use -stat run, but run-all with --tests is more uniform
    all_results = []
    overall_stdout = []
    overall_stderr = []
    last_rc = 0
    for did, ven in devices:
        # Build args: trinetra -stat run-all <session> <target> --tests a,b --workers N
        tests_arg = ",".join([t.upper() for t in test_ids])
        args = ["-stat", "run-all", name, did, "--tests", tests_arg, "--workers", str(workers)]
        rc, out, err = run_trinetra(args, timeout=300)
        # Note: trinetra may exit 0 even if tests fail (compliance result) — that's not an error
        # Only treat non-zero as backend error; but also capture stdout
        overall_stdout.append(out)
        overall_stderr.append(err)
        if rc != 0:
            last_rc = rc
            # Don't break immediately; collect but return error
            return error_response(f"stat run failed for device {did}", 500, {"stdout": out, "stderr": err, "returncode": rc, "device_id": did})
        # Try to collect per-device results (if any)
        all_results.append({"device_id": did, "vendor": ven, "stdout": out, "stderr": err})

    return jsonify({
        "message": "tests executed",
        "session": name,
        "devices": [{"device_id": d, "vendor": v} for d, v in devices],
        "test_ids": test_ids,
        "results": all_results,
        "combined_stdout": "\n".join(overall_stdout),
        "combined_stderr": "\n".join(overall_stderr),
    }), 200

# ── GET /api/session/<name>/status — chain verification + metadata ──
@app.route("/api/session/<name>/status", methods=["GET"])
def session_status(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)

    rc, out, err = run_java_helper("TrinetraBridgeHelper", ["status", name])
    if rc != 0:
        msg = (err.strip() or out.strip()) or "failed to get session status"
        # If session not found, return 404
        if "not found" in msg.lower() or "no such" in msg.lower():
            return error_response(msg, 404, {"stdout": out, "stderr": err})
        return error_response(msg, 500, {"stdout": out, "stderr": err})
    # Helper outputs JSON
    try:
        data = json.loads(out.strip())
        return jsonify(data), 200
    except Exception as e:
        return error_response(f"failed to parse status output: {e}", 500, {"raw_stdout": out, "raw_stderr": err})

# ── GET /api/session/<name>/score — compliance-score ──
@app.route("/api/session/<name>/score", methods=["GET"])
def compliance_score(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)
    rc, out, err = run_trinetra(["-compliance-score", name])
    if rc != 0:
        msg = (err.strip() or out.strip()) or "compliance-score failed"
        if "not found" in msg.lower() or "no such" in msg.lower() or "session" in msg.lower() and "not" in msg.lower():
            return error_response(msg, 404, {"stdout": out, "stderr": err})
        return error_response(msg, 500, {"stdout": out, "stderr": err})
    # The CLI prints prettyJson + extra line "Compliance score written to: ..."
    # We need to extract the JSON part (first JSON object)
    # Try to find the first { ... } that is valid JSON
    # The output starts with {, so we can try to parse the whole stdout up to the extra line
    # Approach: extract JSON object by finding the last } that closes the first object before the extra line
    # CLI output contains "[audit] user: ..." on first line, then pretty JSON, then footer line.
    # Extract JSON by finding first '{' and matching last '}' before footer.
    json_part = out
    if "Compliance score written to:" in json_part:
        json_part = json_part.split("Compliance score written to:")[0]
    # Find first '{' and last '}' to isolate JSON object
    first_brace = json_part.find("{")
    last_brace = json_part.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        json_part = json_part[first_brace:last_brace+1]
    else:
        json_part = json_part.strip()
    try:
        data = json.loads(json_part)
        # Also include the file path if available
        score_path = None
        for line in (out + "\n" + err).splitlines():
            if "Compliance score written to:" in line:
                score_path = line.split("Compliance score written to:")[-1].strip()
                break
        resp = {"score": data}
        if score_path:
            resp["score_file"] = score_path
        # Include raw for debugging
        resp["_raw_stderr"] = err.strip()
        return jsonify(resp), 200
    except Exception as e:
        return error_response(f"failed to parse compliance-score output: {e}", 500, {"raw_stdout": out, "raw_stderr": err})

# ── GET /api/session/<name>/report — compliance-report ──
@app.route("/api/session/<name>/report", methods=["GET"])
def compliance_report(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)
    rc, out, err = run_trinetra(["-compliance-report", name], timeout=120)
    if rc != 0:
        msg = (err.strip() or out.strip()) or "compliance-report failed"
        if "not found" in msg.lower():
            return error_response(msg, 404, {"stdout": out, "stderr": err})
        return error_response(msg, 500, {"stdout": out, "stderr": err})
    # CLI prints [1/2] ... [2/2] ... === Compliance Narrative Report === ... + markdown
    # We should return the markdown content plus metadata
    # Try to extract the narrative file path and score path
    narrative_path = None
    score_path = None
    for line in (out + "\n" + err).splitlines():
        if "Narrative:" in line and "/" in line:
            narrative_path = line.split("Narrative:")[-1].strip()
        if "Score JSON:" in line and "/" in line:
            score_path = line.split("Score JSON:")[-1].strip()
    # The markdown is between "Compliance Narrative Report" and "--- Files saved ---"
    # For now, just return the full stdout as markdown
    return jsonify({
        "session": name,
        "stdout": out,
        "stderr": err,
        "narrative_path": narrative_path,
        "score_path": score_path,
    }), 200

# ── GET /api/session/<name>/audit-report — audit-report ──
@app.route("/api/session/<name>/audit-report", methods=["GET"])
def audit_report(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)
    rc, out, err = run_trinetra(["-audit-report", name], timeout=120)
    if rc != 0:
        msg = (err.strip() or out.strip()) or "audit-report failed"
        if "not found" in msg.lower() or "no readable" in msg.lower():
            return error_response(msg, 404, {"stdout": out, "stderr": err})
        return error_response(msg, 500, {"stdout": out, "stderr": err})
    # Parse output for combined path, framework paths, aggregate, chain status
    combined_path = None
    framework_paths = []
    aggregate = None
    chain_status = None
    narrative_source = None
    in_frameworks = False
    for line in (out + "\n" + err).splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("Combined report:"):
            combined_path = line_stripped.split("Combined report:")[-1].strip()
        elif line_stripped.startswith("Per-framework reports:"):
            in_frameworks = True
            continue
        elif in_frameworks and line_stripped.startswith("- "):
            # Could be framework path
            path = line_stripped[2:].strip()
            if path.endswith(".md"):
                framework_paths.append(path)
        elif line_stripped.startswith("Derived aggregate:"):
            # e.g. Derived aggregate: 50.0% (report-builder computed)
            agg_part = line_stripped.split("Derived aggregate:")[-1].strip().split("%")[0].strip()
            try:
                aggregate = float(agg_part)
            except:
                aggregate = agg_part
            in_frameworks = False
        elif line_stripped.startswith("Chain status:"):
            chain_status = line_stripped.split("Chain status:")[-1].strip()
        elif line_stripped.startswith("Narrative source:"):
            narrative_source = line_stripped.split("Narrative source:")[-1].strip()

    # Try to read combined report content if file exists
    combined_content = None
    if combined_path and os.path.exists(combined_path):
        try:
            with open(combined_path, "r") as f:
                combined_content = f.read()
        except Exception as e:
            combined_content = f"failed to read combined report: {e}"

    return jsonify({
        "session": name,
        "combined_path": combined_path,
        "framework_paths": framework_paths,
        "derived_aggregate_pct": aggregate,
        "chain_status": chain_status,
        "narrative_source": narrative_source,
        "combined_content": combined_content,
        "stdout": out,
        "stderr": err,
    }), 200

# ── GET /api/doctor — structured doctor output ──
@app.route("/api/doctor", methods=["GET"])
def doctor():
    rc, out, err = run_trinetra(["-doctor"])
    # Doctor always exits 0, but we should still handle failures
    if rc != 0 and not out:
        return error_response(f"doctor failed: {err}", 500, {"stdout": out, "stderr": err})
    # Parse the doctor output into structured JSON
    # Sections: [1] Project Structure, [2] Compilation, [3] Test Definitions, [4] Session Validation, [5] AI Integration
    structured = {
        "raw_stdout": out,
        "raw_stderr": err,
        "sections": {},
        "project_structure": {},
        "compilation": {},
        "test_definitions": {},
        "session_validation": {},
        "ai_integration": {},
    }
    current_section = None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("[1]"):
            current_section = "project_structure"
            structured["sections"][current_section] = []
        elif stripped.startswith("[2]"):
            current_section = "compilation"
            structured["sections"][current_section] = []
        elif stripped.startswith("[3]"):
            current_section = "test_definitions"
            structured["sections"][current_section] = []
        elif stripped.startswith("[4]"):
            current_section = "session_validation"
            structured["sections"][current_section] = []
        elif stripped.startswith("[5]"):
            current_section = "ai_integration"
            structured["sections"][current_section] = []
        elif current_section:
            structured["sections"].setdefault(current_section, []).append(line)
        # Also parse specific fields
    # More structured parsing
    for line in out.splitlines():
        if "Root:" in line and "—" in line:
            structured["project_structure"]["root"] = line.strip()
        if "src/:" in line:
            structured["project_structure"]["src"] = "OK" if "OK" in line else line.strip()
        if "stat_scripts/:" in line:
            structured["project_structure"]["stat_scripts"] = "OK" if "OK" in line else line.strip()
        if "Compiled classes:" in line:
            structured["compilation"]["status"] = line.strip()
        if "Stat scripts:" in line and "definitions" in line:
            # e.g. "  Stat scripts: 124 definitions"
            m = re.search(r"Stat scripts:\s*(\d+)", line)
            if m:
                structured["test_definitions"]["count"] = int(m.group(1))
            structured["test_definitions"]["raw"] = line.strip()
        if "All sessions valid" in line:
            structured["session_validation"]["status"] = "valid"
            structured["session_validation"]["errors"] = []
        if "errors" in line and "Missing required field" in line:
            # Will be parsed below
            pass
        if "Gemini CLI:" in line:
            structured["ai_integration"]["gemini_cli"] = line.strip()
        if "GEMINI_API_KEY:" in line:
            structured["ai_integration"]["gemini_key"] = line.strip()
        if "OpenRouter" in line:
            structured["ai_integration"]["openrouter"] = line.strip()
        if "Project config.json:" in line:
            structured["ai_integration"]["config_json"] = line.strip()

    # Parse session validation errors more thoroughly
    # After [4] Session Validation, lines like "  demo: 1 errors" and "    - Missing ..."
    session_errors = {}
    in_session_validation = False
    current_sess = None
    for line in out.splitlines():
        if "[4] Session Validation" in line:
            in_session_validation = True
            continue
        if in_session_validation:
            if line.startswith("[5]"):
                break
            m = re.match(r"\s+(\S+):\s+(\d+)\s+errors", line)
            if m:
                current_sess = m.group(1)
                session_errors[current_sess] = []
            elif current_sess and "Missing required field" in line:
                session_errors[current_sess].append(line.strip())
    structured["session_validation"]["session_errors"] = session_errors
    if not session_errors and "All sessions valid" in out:
        structured["session_validation"]["status"] = "valid"
    else:
        structured["session_validation"]["status"] = "warnings" if session_errors else "unknown"

    return jsonify(structured), 200

# ── Error handlers ──
@app.errorhandler(404)
def not_found(e):
    return error_response("not found", 404)

@app.errorhandler(405)
def method_not_allowed(e):
    return error_response("method not allowed", 405)

@app.errorhandler(500)
def internal_error(e):
    return error_response("internal server error", 500)

if __name__ == "__main__":
    try:
        from bridge.config import BRIDGE_HOST, BRIDGE_PORT
    except ImportError:
        from config import BRIDGE_HOST, BRIDGE_PORT
    app.run(host=BRIDGE_HOST, port=BRIDGE_PORT, debug=False)
