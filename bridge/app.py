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

# ── POST /api/session/<name>/upload-config — config-file ingestion (PS26155) ──
@app.route("/api/session/<name>/upload-config", methods=["POST"])
def upload_config(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)

    # Accept either multipart file upload or JSON with config_content
    device_id = None
    vendor = None
    config_content = None
    filename = None

    if request.content_type and "multipart/form-data" in request.content_type:
        device_id = request.form.get("device_id") or request.form.get("deviceId")
        vendor = request.form.get("vendor") or request.form.get("vendor_hint")
        # File field can be named "config" or "file" or "config_file"
        file = request.files.get("config") or request.files.get("file") or request.files.get("config_file")
        if file and file.filename:
            filename = file.filename
            try:
                config_content = file.read().decode("utf-8", errors="replace")
            except Exception as e:
                return error_response(f"failed to read uploaded file: {e}", 400)
        else:
            # Fallback to config_content field in form
            config_content = request.form.get("config_content") or request.form.get("content")
            filename = request.form.get("filename") or (device_id + "_config.txt" if device_id else "config.txt")
        if not config_content:
            # Check if vendor provided via form and device_id
            pass
    else:
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id") or data.get("deviceId") or data.get("target")
        vendor = data.get("vendor") or data.get("vendor_hint")
        config_content = data.get("config_content") or data.get("config") or data.get("content") or data.get("file_content")
        filename = data.get("filename") or data.get("file_name") or (f"{device_id}_config.txt" if device_id else None)

    if not device_id:
        return error_response("missing device_id", 400)
    if not validate_device(device_id):
        return error_response(f"invalid device_id: {device_id!r}", 400)
    if vendor and not validate_vendor(vendor):
        return error_response(f"invalid vendor: {vendor!r}", 400)
    if not config_content or not isinstance(config_content, str) or len(config_content.strip()) == 0:
        return error_response("missing or empty config file content", 400)
    if len(config_content) > 1024 * 1024:  # 1MB limit
        return error_response("config file too large (max 1MB)", 400)
    if contains_injection(device_id) or (vendor and contains_injection(vendor)):
        return error_response("injection characters detected", 400)

    # Auto-detect vendor if not provided or "auto"
    if not vendor or vendor.lower() == "auto":
        vendor = None  # let Java auto-detect

    # Save config to temp file and call Java helper
    import tempfile
    tmp_path = None
    try:
        # Create temp file with config content
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tf:
            tf.write(config_content)
            tmp_path = tf.name

        # Call Java helper ingest-config
        args = ["ingest-config", name, device_id, vendor or "auto", tmp_path]
        rc, out, err = run_java_helper("TrinetraBridgeHelper", args, timeout=120)
        if rc != 0:
            msg = (err.strip() or out.strip()) or "config ingestion failed"
            if "not found" in msg.lower():
                return error_response(msg, 404, {"stdout": out, "stderr": err})
            return error_response(msg, 500, {"stdout": out, "stderr": err})
        try:
            data = json.loads(out.strip())
            # Include raw config save path for reference
            data["config_filename"] = filename
            return jsonify(data), 200
        except Exception as e:
            return error_response(f"failed to parse ingest output: {e}", 500, {"raw_stdout": out, "raw_stderr": err})
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except:
                pass

# ── GET /api/session/<name>/unrecognized — list unrecognized config lines ──
@app.route("/api/session/<name>/unrecognized", methods=["GET"])
def get_unrecognized(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)
    device_id = request.args.get("device_id") or request.args.get("deviceId")
    if device_id and not validate_device(device_id):
        return error_response(f"invalid device_id: {device_id!r}", 400)

    args = ["get-unrecognized", name]
    if device_id:
        args.append(device_id)
    rc, out, err = run_java_helper("TrinetraBridgeHelper", args)
    if rc != 0:
        msg = (err.strip() or out.strip()) or "failed to get unrecognized lines"
        if "not found" in msg.lower():
            return error_response(msg, 404, {"stdout": out, "stderr": err})
        return error_response(msg, 500, {"stdout": out, "stderr": err})
    try:
        data = json.loads(out.strip())
        return jsonify(data), 200
    except Exception as e:
        return error_response(f"failed to parse unrecognized output: {e}", 500, {"raw_stdout": out, "raw_stderr": err})

# ── POST /api/session/<name>/train — add training entry (no code change) ──
@app.route("/api/session/<name>/train", methods=["POST"])
def train_vendor(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)
    data = request.get_json(silent=True) or {}
    vendor = data.get("vendor")
    pattern = data.get("pattern") or data.get("config_line_pattern") or data.get("config_pattern")
    category = data.get("security_category") or data.get("category") or ""
    controls = data.get("control_mapping") or data.get("controls") or []
    remediation = data.get("remediation") or ""

    if not vendor or not pattern:
        return error_response("missing required fields: vendor and pattern", 400)
    if not validate_vendor(vendor):
        return error_response(f"invalid vendor: {vendor!r}", 400)
    if not isinstance(pattern, str) or len(pattern.strip()) == 0 or len(pattern) > 500:
        return error_response("invalid pattern", 400)
    # For pattern, allow regex chars like .*+?[]()^$ but still block shell injection
    # Block ; & | ` \n \r $() and path traversal
    if any(c in pattern for c in [';', '&', '|', '`', '\n', '\r']) or '$( ' in pattern or '$(' in pattern:
        return error_response("injection characters detected in pattern", 400)
    if contains_injection(vendor):
        return error_response("injection characters detected in vendor", 400)
    # Validate controls
    if isinstance(controls, str):
        controls = [controls]
    if not isinstance(controls, list):
        return error_response("control_mapping must be a list", 400)
    for c in controls:
        if not isinstance(c, str) or contains_injection(c):
            return error_response(f"invalid control: {c!r}", 400)
    if category and (not isinstance(category, str) or contains_injection(category)):
        return error_response(f"invalid security_category: {category!r}", 400)
    if remediation and (not isinstance(remediation, str) or len(remediation) > 1000):
        return error_response("invalid remediation", 400)

    # Directly update the JSON file via Python (no Java code change) — this is the training loop
    try:
        from pathlib import Path as _P
        import json as _json
        map_path = _P(TRINETRA_ROOT) / "config" / "vendor_training_map.json"
        # Use file lock via simple read-modify-write (single Flask worker for demo)
        content = "{}"
        if map_path.exists():
            content = map_path.read_text(encoding="utf-8")
        data_json = _json.loads(content) if content.strip() else {}
        if "entries" not in data_json or not isinstance(data_json["entries"], list):
            data_json["entries"] = []
        # Check duplicate
        for e in data_json["entries"]:
            if e.get("vendor","").lower() == vendor.lower() and e.get("pattern","") == pattern:
                return error_response("training entry already exists for this vendor+pattern", 409)
        new_entry = {
            "vendor": vendor,
            "pattern": pattern,
            "security_category": category,
            "control_mapping": controls,
            "remediation": remediation,
            "added_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "added_via": f"session:{name}"
        }
        data_json["entries"].append(new_entry)
        map_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write
        import tempfile as _tf, os as _os
        with _tf.NamedTemporaryFile(mode="w", delete=False, dir=str(map_path.parent), encoding="utf-8") as tf:
            _json.dump(data_json, tf, indent=2)
            tmp = tf.name
        _os.replace(tmp, str(map_path))
        # Invalidate Java cache by touching file (VendorTrainingMap.load checks mtime)
        return jsonify({"message": "training entry added", "entry": new_entry, "total_entries": len(data_json["entries"])}), 201
    except Exception as e:
        return error_response(f"failed to add training entry: {e}", 500)

# ── GET /api/session/<name>/audit-report/pdf — PDF export ──
@app.route("/api/session/<name>/audit-report/pdf", methods=["GET"])
def audit_report_pdf(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)
    # First ensure audit report exists (generate if needed)
    rc, out, err = run_trinetra(["-audit-report", name], timeout=120)
    if rc != 0:
        msg = (err.strip() or out.strip()) or "audit-report failed"
        if "not found" in msg.lower() or "no readable" in msg.lower():
            return error_response(msg, 404, {"stdout": out, "stderr": err})
        return error_response(msg, 500, {"stdout": out, "stderr": err})
    # Parse combined_path from output
    combined_path = None
    for line in (out + "\n" + err).splitlines():
        if line.strip().startswith("Combined report:"):
            combined_path = line.strip().split("Combined report:")[-1].strip()
            break
    if not combined_path or not os.path.exists(combined_path):
        return error_response("combined report not found after generation", 500, {"stdout": out, "stderr": err})

    # Generate PDF via ReportLab (Python) — chosen over Java PDF lib to keep Java core unchanged
    # and to keep PDF export as a bridge-layer concern (no new Java deps). ReportLab is lightweight,
    # pure Python, and already available via pip.
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        import io

        # Read session and brain state for device_id and remediation
        # Use Java helper to get status for device info
        rc2, out2, err2 = run_java_helper("TrinetraBridgeHelper", ["status", name])
        status_data = {}
        if rc2 == 0:
            try:
                status_data = json.loads(out2.strip())
            except:
                pass

        # Read combined markdown
        with open(combined_path, "r") as f:
            md_content = f.read()

        # Build PDF in memory
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=18)
        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        heading_style = styles["Heading2"]
        normal_style = styles["Normal"]
        # Custom style for evidence rows
        story = []

        # Title
        story.append(Paragraph(f"Trinetra Audit Report — {name}", title_style))
        story.append(Spacer(1, 12))

        # Session metadata table
        sess_target = status_data.get("target", "unknown")
        chain_info = status_data.get("chain", {})
        meta_data = [
            ["Session", name],
            ["Target", sess_target],
            ["Generated", __import__("datetime").datetime.utcnow().isoformat() + "Z"],
            ["Chain Status", chain_info.get("detail", "unknown") if isinstance(chain_info, dict) else str(chain_info)],
            ["Ingestion", "Config-file upload (primary) — see device table for per-device method"],
        ]
        # Add device ingestion info if available
        device_ingestion = status_data.get("device_ingestion", {})
        if device_ingestion:
            for dev, info in device_ingestion.items():
                method = info.get("method", "unknown") if isinstance(info, dict) else str(info)
                meta_data.append([f"Device {dev} ingestion", method])
        # Add device vendors
        device_vendors = status_data.get("device_vendors", {})
        if device_vendors:
            for dev, ven in device_vendors.items():
                meta_data.append([f"Device {dev} vendor", ven])

        t = Table(meta_data, colWidths=[2.5*inch, 4.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

        # Evidence rows — try to parse from markdown's evidence tables
        # Look for lines like "| Device | Vendor | Test ID | Verdict |"
        import re as _re
        evidence_rows = []
        in_evidence = False
        for line in md_content.splitlines():
            if "| Device" in line and "Vendor" in line:
                in_evidence = True
                continue
            if in_evidence and line.strip().startswith("|"):
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 4:
                    evidence_rows.append(parts[:5])  # Device, Vendor, Test ID, Verdict, Timestamp...
            elif in_evidence and not line.strip().startswith("|"):
                # End of table
                if evidence_rows:
                    break

        if evidence_rows:
            story.append(Paragraph("Evidence — Per-Device Test Results", heading_style))
            # Header + rows, ensure device_id is shown
            table_data = [["Device ID", "Vendor", "Test ID", "Verdict", "Timestamp"]]
            for row in evidence_rows[:50]:  # limit
                # Ensure 5 cols
                while len(row) < 5:
                    row.append("")
                table_data.append(row[:5])
            et = Table(table_data, repeatRows=1, colWidths=[1.2*inch, 1.0*inch, 1.0*inch, 1.0*inch, 1.8*inch])
            et.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#4472C4")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTSIZE', (0,0), (-1,-1), 7),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F2F2F2")]),
            ]))
            story.append(et)
            story.append(Spacer(1, 12))

        # Remediation section — per failed test, source from TrinetraAgr REMEDIATION map or training map
        # For demo, we extract failed tests from evidence rows where Verdict == fail
        failed_tests = [r for r in evidence_rows if len(r) >= 4 and r[3].lower() == "fail"]
        if failed_tests:
            story.append(Paragraph("Remediation — Failed Tests", heading_style))
            # Try to load remediation from Java via TrinetraAgr? For now, use static map + training map
            # We'll hardcode a few known remediations and label fallback as AI-suggested
            remediation_map = {
                "V-003": "Close unnecessary ports: `no transport input telnet` / firewall restrict. (Documented)",
                "V-006": "Disable weak TLS: `no ip http server`, enforce TLS 1.2+ with `ip ssh version 2`. (Documented)",
                "V-007": "Disable weak ciphers: `no ip ssh cipher ...` use AES-GCM/ChaCha20. (Documented)",
                "V-008": "Replace self-signed cert: `crypto ca enroll` with CA-signed. (Documented)",
                "V-013": "Enforce strong password: `enable secret <strong>` + `aaa new-model`. (Documented)",
                "V-071": "Disable insecure mgmt: `no transport input telnet`, `no ip http server`, set `exec-timeout 5 0`. (Documented)",
                "V-057": "Remove hardcoded community: `no snmp-server community public`. Use vault. (Documented)",
                "V-058": "Enable logging: `logging host <syslog>` + `service timestamps log`. (Documented)",
            }
            for row in failed_tests:
                test_id = row[2] if len(row) > 2 else "unknown"
                device = row[0] if len(row) > 0 else "unknown"
                remediation = remediation_map.get(test_id)
                is_ai = False
                if not remediation:
                    # Fallback to training map or generic
                    # Check VendorTrainingMap for this test's remediation
                    try:
                        from pathlib import Path as _P2
                        import json as _j
                        tm_path = _P(TRINETRA_ROOT) / "config" / "vendor_training_map.json"
                        if tm_path.exists():
                            tm_data = _j.loads(tm_path.read_text())
                            for e in tm_data.get("entries", []):
                                if test_id in str(e.get("control_mapping",[])):
                                    remediation = e.get("remediation", "")
                                    if remediation:
                                        break
                    except:
                        pass
                if not remediation:
                    remediation = f"Review {test_id} for device {device} and apply vendor hardening guide. (AI-suggested — verify before use)"
                    is_ai = True
                else:
                    if is_ai:
                        remediation += " (AI-suggested — verify before use)"

                p_text = f"<b>{test_id} on {device}:</b> {remediation}"
                if is_ai:
                    p_text += " <i>(AI-suggested — verify before use)</i>"
                story.append(Paragraph(p_text, normal_style))
                story.append(Spacer(1, 6))

        # Unrecognized lines section if any
        unrec = status_data.get("unrecognized_by_device", {})
        if unrec:
            story.append(Spacer(1, 12))
            story.append(Paragraph("Unrecognized Config Lines (Training Needed)", heading_style))
            for dev, lines in unrec.items():
                if lines:
                    story.append(Paragraph(f"Device {dev}: {len(lines)} unrecognized line(s)", normal_style))
                    for l in lines[:10]:
                        story.append(Paragraph(f"&nbsp;&nbsp;&bull; <font face=\"Courier\">{l[:80]}</font>", normal_style))

        # Footer — note bonus frameworks
        story.append(Spacer(1, 12))
        story.append(Paragraph("Note: PCI-DSS and SOC2 are shown as <b>bonus/additional coverage</b> only. PS-required frameworks are CIS, NIST 800-53, and ISO 27001.", normal_style))
        story.append(Spacer(1, 6))
        story.append(Paragraph("Generated by Trinetra — static config-file auditor (live SSH optional). Ingestion method per device is recorded honestly in the report.", normal_style))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        from flask import Response
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=audit_report_{name}.pdf",
                "Content-Length": str(len(pdf_bytes))
            }
        )
    except ImportError as e:
        return error_response(f"PDF generation requires reportlab: {e}", 500)
    except Exception as e:
        import traceback
        return error_response(f"PDF generation failed: {e}", 500, {"trace": traceback.format_exc()})

# ── Minimal upload GUI (plain HTML/JS via Flask) ──
@app.route("/", methods=["GET"])
@app.route("/ui", methods=["GET"])
@app.route("/upload", methods=["GET"])
def upload_gui():
    html = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Trinetra — Config Upload & Training</title>
<style>
body{font-family:system-ui,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#f9fafb;color:#111}
h1{color:#1f4a7a} h2{color:#2a5a8a;border-bottom:2px solid #e5e7eb;padding-bottom:.3rem}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:1rem;margin:1rem 0;box-shadow:0 1px 3px rgba(0,0,0,.05)}
label{display:block;margin:.5rem 0 .2rem;font-weight:600}
input,select,textarea,button{width:100%;padding:.6rem;border:1px solid #d1d5db;border-radius:6px;font-size:.95rem}
button{background:#2563eb;color:#fff;border:none;cursor:pointer;margin-top:.7rem}
button:hover{background:#1d4ed8}
button.secondary{background:#6b7280}
button.secondary:hover{background:#4b5563}
pre{background:#111;color:#0f0;padding:.8rem;overflow:auto;border-radius:6px;max-height:300px}
table{width:100%;border-collapse:collapse;margin:.5rem 0}
th,td{border:1px solid #e5e7eb;padding:.4rem;text-align:left;font-size:.85rem}
th{background:#f3f4f6}
.badge{padding:.2rem .5rem;border-radius:99px;font-size:.75rem;font-weight:600}
.pass{background:#dcfce7;color:#166534} .fail{background:#fee2e2;color:#991b1b} .review{background:#fef3c7;color:#92400e}
.small{font-size:.8rem;color:#6b7280}
</style>
</head>
<body>
<h1>Trinetra — Static Config Auditor</h1>
<p class="small">Upload a device config file → parse → score → report. No live SSH required. Live mode is secondary.</p>

<div class="card">
<h2>1. Upload Config</h2>
<form id="uploadForm" enctype="multipart/form-data">
<label>Session name (new or existing)</label>
<input type="text" id="session" placeholder="demo" required>
<label>Target (for session creation if new)</label>
<input type="text" id="target" placeholder="cisco-lab-01" value="cisco-lab-01">
<label>Device ID (hardware label/serial)</label>
<input type="text" id="device_id" placeholder="cisco-01" required>
<label>Vendor (or auto-detect)</label>
<select id="vendor"><option value="auto">Auto-detect</option><option>Cisco</option><option>Juniper</option><option>Generic</option></select>
<label>Config file (text)</label>
<input type="file" id="configFile" accept=".txt,.cfg,.conf,.config">
<label>Or paste config content</label>
<textarea id="configContent" rows="8" placeholder="hostname R1
enable secret 5 $1$...
ip ssh time-out 60
snmp-server community public RO
..."></textarea>
<button type="submit">Upload &amp; Parse</button>
</form>
<pre id="uploadResult"></pre>
</div>

<div class="card">
<h2>2. Run Checks &amp; Score</h2>
<button onclick="runChecks()">Run Compliance Checks (on uploaded config)</button>
<button class="secondary" onclick="getScore()">View Score</button>
<button class="secondary" onclick="getReport()">View Narrative Report</button>
<pre id="runResult"></pre>
<div id="scoreView"></div>
</div>

<div class="card">
<h2>3. Unrecognized Lines → Training</h2>
<p class="small">Lines the parser didn't recognize are flagged here. Label them to teach the system without code change.</p>
<button onclick="loadUnrecognized()">Load Unrecognized Lines</button>
<div id="unrecView"></div>
<pre id="trainResult"></pre>
</div>

<div class="card">
<h2>4. Audit Report &amp; PDF</h2>
<button onclick="getAuditReport()">Generate Audit Report</button>
<a id="pdfLink" href="#" style="display:none" target="_blank"><button>Download PDF Report</button></a>
<pre id="auditResult"></pre>
</div>

<script>
const $ = id => document.getElementById(id);
function getSession(){ return $('session').value.trim() || 'demo'; }

$('uploadForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const session = getSession();
  const device_id = $('device_id').value.trim();
  const vendor = $('vendor').value;
  const target = $('target').value.trim() || device_id;
  const file = $('configFile').files[0];
  let config_content = $('configContent').value;

  // Try to create session first (ignore 409)
  await fetch('/api/session', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name:session, target})});

  let res;
  if(file){
    const fd = new FormData();
    fd.append('device_id', device_id);
    fd.append('vendor', vendor);
    fd.append('config', file);
    res = await fetch(`/api/session/${encodeURIComponent(session)}/upload-config`, {method:'POST', body:fd});
  } else {
    if(!config_content){ $('uploadResult').textContent='Provide a file or paste content'; return; }
    res = await fetch(`/api/session/${encodeURIComponent(session)}/upload-config`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({device_id, vendor, config_content, filename: device_id+'_config.txt'})
    });
  }
  const j = await res.json().catch(()=>({}));
  $('uploadResult').textContent = JSON.stringify(j,null,2);
  if(res.ok) loadUnrecognized();
});

async function runChecks(){
  const session = getSession();
  // For config-file flow, checks already run on upload; this button re-triggers via run endpoint for demo
  // We use V-003 as example; but for config flow, upload already did checks. So we just show score.
  getScore();
}

async function getScore(){
  const session = getSession();
  const res = await fetch(`/api/session/${encodeURIComponent(session)}/score`);
  const j = await res.json();
  $('runResult').textContent = JSON.stringify(j,null,2);
  if(j.score && j.score.frameworks){
    let html='<table><tr><th>Framework</th><th>%</th><th>Passed/Total</th></tr>';
    for(const [fw, v] of Object.entries(j.score.frameworks)){
      const bonus = (fw==='PCI-DSS'||fw==='SOC2') ? ' <span class="small">(bonus)</span>' : '';
      html+=`<tr><td>${fw}${bonus}</td><td>${v.compliance_percentage}%</td><td>${v.tests_passed}/${v.total_tests_mapped}</td></tr>`;
    }
    html+='</table><p class="small">PCI-DSS/SOC2 are bonus/additional coverage — PS requires CIS/NIST/ISO.</p>';
    $('scoreView').innerHTML=html;
  }
}

async function getReport(){
  const session = getSession();
  const res = await fetch(`/api/session/${encodeURIComponent(session)}/report`);
  const j = await res.json();
  $('runResult').textContent = (j.stdout||'').slice(0,4000);
}

async function getAuditReport(){
  const session = getSession();
  const res = await fetch(`/api/session/${encodeURIComponent(session)}/audit-report`);
  const j = await res.json();
  $('auditResult').textContent = JSON.stringify(j,null,2);
  if(j.combined_path){
    $('pdfLink').href = `/api/session/${encodeURIComponent(session)}/audit-report/pdf`;
    $('pdfLink').style.display='inline';
  }
}

async function loadUnrecognized(){
  const session = getSession();
  const res = await fetch(`/api/session/${encodeURIComponent(session)}/unrecognized`);
  const j = await res.json();
  $('unrecView').innerHTML='';
  let lines = [];
  if(j.unrecognized_by_device){
    for(const [dev, arr] of Object.entries(j.unrecognized_by_device)){
      if(arr && arr.length) lines.push(...arr.map(l=>({device:dev, line:l})));
    }
  } else if(j.unrecognized_lines){
    lines = j.unrecognized_lines.map(l=>({device:j.device_id||'unknown', line:l}));
  }
  if(!lines.length){ $('unrecView').innerHTML='<p class="small">No unrecognized lines — all parsed via known or trained patterns.</p>'; return; }
  let html='<table><tr><th>Device</th><th>Line</th><th>Category</th><th>Controls</th><th>Action</th></tr>';
  for(const {device, line} of lines){
    const esc = line.replace(/"/g,'&quot;');
    html+=`<tr><td>${device}</td><td><code>${esc.slice(0,60)}</code></td>
      <td><input id="cat_${btoa(line).slice(0,8)}" placeholder="e.g. SSH Hardening"></td>
      <td><input id="ctrl_${btoa(line).slice(0,8)}" placeholder="e.g. CIS-IOS-XE-2.1.1.1.4"></td>
      <td><button onclick="trainLine('${device}','${esc.replace(/'/g,"\\'")}', '${btoa(line).slice(0,8)}')">Label</button></td></tr>`;
  }
  html+='</table>';
  $('unrecView').innerHTML=html;
  $('trainResult').textContent = JSON.stringify(j,null,2);
}

async function trainLine(device, line, id){
  const session = getSession();
  const cat = document.getElementById('cat_'+id).value || 'Custom Hardening';
  const ctrl = document.getElementById('ctrl_'+id).value || 'CIS-v8-4.6';
  const vendor = document.getElementById('vendor').value || 'Cisco';
  const res = await fetch(`/api/session/${encodeURIComponent(session)}/train`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({device_id: device, vendor, pattern: line, security_category: cat, control_mapping: [ctrl], remediation: 'no '+line})
  });
  const j = await res.json();
  document.getElementById('trainResult').textContent = JSON.stringify(j,null,2);
  if(res.ok){ loadUnrecognized(); }
}
</script>
</body>
</html>
    """
    return html, 200, {"Content-Type": "text/html"}

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
