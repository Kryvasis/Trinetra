import re
import subprocess
import json
import os
import shlex
import threading
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from flask import Flask, request, jsonify

try:
    from bridge import live_fetcher
    from bridge.request_boundary import install_request_boundary
    from bridge.website import bp as website_bp
    from bridge.config_validation import is_web_document, HTML_ERROR, CONFIG_SANITY_ERROR, is_plausible_config, looks_like_html
except ImportError:
    import live_fetcher
    from request_boundary import install_request_boundary
    from website import bp as website_bp
    from config_validation import is_web_document, HTML_ERROR, CONFIG_SANITY_ERROR, is_plausible_config, looks_like_html

try:
    from bridge.config import (
        TRINETRA_BIN,
        TRINETRA_ROOT,
        JAVA_OUT,
        JAVA_LIB,
        SUBPROCESS_TIMEOUT,
        FLASK_SECRET,
        MAX_REQUEST_BYTES,
    )
except ImportError:
    from config import (
        TRINETRA_BIN,
        TRINETRA_ROOT,
        JAVA_OUT,
        JAVA_LIB,
        SUBPROCESS_TIMEOUT,
        FLASK_SECRET,
        MAX_REQUEST_BYTES,
    )

app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
app.register_blueprint(website_bp)
install_request_boundary(app)

# Atomic replace protects readers from partial JSON, while this lock also
# prevents concurrent requests in one bridge process from losing an entry.
TRAINING_MAP_LOCK = threading.Lock()

# ── Validation regexes (reject before subprocess) ──
SESSION_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
TEST_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")  # e.g. V-003, T-SHARED, T_CISCO
# device_id: allow IP, hostname, simple identifiers; reject shell metachars
DEVICE_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")
VENDOR_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,254}[A-Za-z0-9])?$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")

# Strict hostname validation per RFC 1123 — used for fetch targets (ip/hostname and URL host)
# Hostname must be 3-253 chars, labels 1-63, alphanum/hyphen, not start/end hyphen.
# Single-label hostnames must be >=3 chars; multi-label TLD must be >=2 letters.
def is_valid_hostname(hostname: str) -> bool:
    if not isinstance(hostname, str):
        return False
    if len(hostname) < 3 or len(hostname) > 253:
        return False
    if hostname[0] == "." or hostname[-1] == "." or ".." in hostname:
        return False
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-" for c in hostname):
        return False
    labels = hostname.split(".")
    for label in labels:
        if not 1 <= len(label) <= 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if not label[0].isalnum() or not label[-1].isalnum():
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
    if len(labels) > 1:
        tld = labels[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False
    # Single-label hostnames must not be purely numeric (would be ambiguous with IP)
    if len(labels) == 1 and hostname.isdigit():
        return False
    return True


def is_valid_ip_or_hostname(target: str) -> bool:
    if not isinstance(target, str) or not target.strip():
        return False
    t = target.strip()
    # Try IP first (covers IPv4 and IPv6)
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        pass
    return is_valid_hostname(t)


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

def get_framework_filter():
    """Parse ?frameworks=CIS,STIG,NIST_800-53 etc. Returns list or None."""
    raw = request.args.get("frameworks") or request.args.get("framework") or request.args.get("benchmarks")
    if not raw:
        # Also accept JSON body for POST fallback (not used by GET but harmless)
        try:
            body = request.get_json(silent=True) or {}
            raw = body.get("frameworks") or body.get("framework") or body.get("benchmarks")
            if isinstance(raw, list):
                raw = ",".join(raw)
        except:
            pass
    if not raw or not isinstance(raw, str):
        return None
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    valid = []
    for p in parts:
        if not re.match(r"^[A-Za-z0-9_\-\.]+$", p):
            continue
        if contains_injection(p):
            continue
        valid.append(p)
    return valid if valid else None

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


def markdown_cells(line):
    """Preserve empty metadata columns and escaped pipes in evidence tables."""
    return [cell.strip().replace("\\|", "|") for cell in re.split(r"(?<!\\)\|", line.strip().removeprefix("|").removesuffix("|"))]

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
    if not os.path.isfile(os.path.join(TRINETRA_ROOT, "sessions", name, f"{name}.json")):
        return error_response(f"session not found: {name}", 404)
    fw_filter = get_framework_filter()
    tr_args = ["-compliance-score", name]
    if fw_filter:
        tr_args += ["--frameworks", ",".join(fw_filter)]
    rc, out, err = run_trinetra(tr_args)
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
    if not os.path.isfile(os.path.join(TRINETRA_ROOT, "sessions", name, f"{name}.json")):
        return error_response(f"session not found: {name}", 404)
    fw_filter = get_framework_filter()
    tr_args = ["-compliance-report", name]
    if fw_filter:
        tr_args += ["--frameworks", ",".join(fw_filter)]
    rc, out, err = run_trinetra(tr_args, timeout=120)
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
    fw_filter = get_framework_filter()
    tr_args = ["-audit-report", name]
    if fw_filter:
        tr_args += ["--frameworks", ",".join(fw_filter)]
    rc, out, err = run_trinetra(tr_args, timeout=120)
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
    serial_number = None
    hardware_model = None
    os_version = None

    if request.content_type and "multipart/form-data" in request.content_type:
        device_id = request.form.get("device_id") or request.form.get("deviceId")
        vendor = request.form.get("vendor") or request.form.get("vendor_hint")
        serial_number = request.form.get("serial_number") or request.form.get("serialNumber") or request.form.get("serial")
        hardware_model = request.form.get("hardware_model") or request.form.get("hardwareModel") or request.form.get("model")
        os_version = request.form.get("os_version") or request.form.get("osVersion") or request.form.get("os")
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
        serial_number = data.get("serial_number") or data.get("serialNumber") or data.get("serial")
        hardware_model = data.get("hardware_model") or data.get("hardwareModel") or data.get("model")
        os_version = data.get("os_version") or data.get("osVersion") or data.get("os")
        config_content = data.get("config_content") or data.get("config") or data.get("content") or data.get("file_content")
        filename = data.get("filename") or data.get("file_name") or (f"{device_id}_config.txt" if device_id else None)

    if not device_id:
        return error_response("missing device_id", 400)
    if not validate_device(device_id):
        return error_response(f"invalid device_id: {device_id!r}", 400)
    if vendor and not validate_vendor(vendor):
        return error_response(f"invalid vendor: {vendor!r}", 400)
    # Validate optional hardware metadata (free-text, injection-safe, max lengths)
    for field_name, field_val in [("serial_number", serial_number), ("hardware_model", hardware_model), ("os_version", os_version)]:
        if field_val is not None and field_val != "":
            if not isinstance(field_val, str) or len(field_val) > 128 or contains_injection(field_val):
                return error_response(f"invalid {field_name}: {field_val!r}", 400)
    if not config_content or not isinstance(config_content, str) or len(config_content.strip()) == 0:
        return error_response("missing or empty config file content", 400)
    if len(config_content.encode("utf-8")) > 1024 * 1024:  # 1 MiB, not characters
        return error_response("config file too large (max 1MB)", 413)
    if is_web_document(config_content) or looks_like_html(config_content):
        return error_response(HTML_ERROR, 422)
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

        # Call Java helper ingest-config — include hardware metadata (use "_" placeholder for blank to preserve positional args)
        serial_arg = serial_number.strip() if serial_number and serial_number.strip() else "_"
        hardware_arg = hardware_model.strip() if hardware_model and hardware_model.strip() else "_"
        os_arg = os_version.strip() if os_version and os_version.strip() else "_"
        args = ["ingest-config", name, device_id, vendor or "auto", tmp_path, serial_arg, hardware_arg, os_arg]
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

# ── POST /api/session/<name>/fetch-config — transient network collection ──
@app.route("/api/session/<name>/fetch-config", methods=["POST"])
def fetch_config(name):
    if not validate_session(name):
        return error_response("invalid session name", 400)
    session_path = os.path.join(TRINETRA_ROOT, "sessions", name, f"{name}.json")
    if not os.path.exists(session_path):
        return error_response("session not found", 404)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("JSON request body required", 400)

    source_type = data.get("source_type")
    target = data.get("target")
    device_id = data.get("device_id") or data.get("deviceId")
    vendor = data.get("vendor") or data.get("vendor_hint") or "auto"
    if source_type not in ("ip", "url"):
        return error_response("source_type must be 'ip' or 'url'", 400)
    if not isinstance(target, str) or not target.strip() or len(target) > 2048:
        return error_response("invalid collection target", 400)
    target = target.strip()
    if not validate_device(device_id):
        return error_response("invalid or missing device_id", 400)
    if not validate_vendor(vendor):
        return error_response("invalid vendor", 400)

    serial_number = data.get("serial_number") or data.get("serialNumber") or ""
    hardware_model = data.get("hardware_model") or data.get("hardwareModel") or ""
    os_version = data.get("os_version") or data.get("osVersion") or ""
    for field_name, field_value in (
        ("serial_number", serial_number),
        ("hardware_model", hardware_model),
        ("os_version", os_version),
    ):
        if not isinstance(field_value, str) or len(field_value) > 128 or contains_injection(field_value):
            return error_response(f"invalid {field_name}", 400)

    fetch_args = {"source_type": source_type, "target": target, "vendor": vendor}
    if source_type == "ip":
        if not is_valid_ip_or_hostname(target):
            return error_response("invalid IP address or hostname — must be a valid IPv4/IPv6 address or RFC 1123 hostname (3-253 chars, valid labels; e.g. 10.0.0.1 or edge-router.local)", 400)
        username = data.get("username")
        password = data.get("password")
        ssh_key = data.get("ssh_key")
        port = data.get("port", 22)
        if not isinstance(username, str) or not username.strip() or len(username) > 128 or any(ord(c) < 32 for c in username):
            return error_response("invalid or missing SSH username", 400)
        if not password and not ssh_key:
            return error_response("SSH password or private key is required", 400)
        if password is not None and (not isinstance(password, str) or len(password) > 1024):
            return error_response("invalid SSH password", 400)
        if ssh_key is not None and (not isinstance(ssh_key, str) or len(ssh_key) > 8192):
            return error_response("invalid SSH private key", 400)
        if isinstance(port, bool):
            return error_response("invalid SSH port", 400)
        try:
            port = int(port)
        except (TypeError, ValueError):
            return error_response("invalid SSH port", 400)
        if not 1 <= port <= 65535:
            return error_response("SSH port must be between 1 and 65535", 400)
        fetch_args.update(
            username=username.strip(), password=password, ssh_key=ssh_key, port=port,
        )
    else:
        # Strict URL validation — must start with http:// or https:// and have valid hostname
        if not re.match(r"^https?://", target, re.I):
            return error_response("URL must start with http:// or https://", 400)
        try:
            parsed = urlsplit(target)
            _ = parsed.port  # Validate malformed/out-of-range ports before collection.
        except ValueError:
            return error_response("invalid configuration URL — malformed port or URL structure", 400)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return error_response("URL must include a valid hostname (e.g. https://example.com/config)", 400)
        if not is_valid_ip_or_hostname(parsed.hostname):
            return error_response("URL must include a valid hostname (e.g. https://example.com/config)", 400)
        if parsed.username or parsed.password:
            return error_response("credentials must not be embedded in the URL", 400)
        auth_token = data.get("auth_token")
        auth_header = data.get("auth_header") or "Authorization"
        if auth_token is not None and (not isinstance(auth_token, str) or len(auth_token) > 2048):
            return error_response("invalid authentication token", 400)
        if not isinstance(auth_header, str) or not HEADER_NAME_RE.fullmatch(auth_header):
            return error_response("invalid authentication header", 400)
        if auth_header.lower() != "authorization" and not auth_header.lower().startswith("x-"):
            return error_response("authentication headers must be Authorization or an X- prefixed header", 400)
        if auth_token and parsed.scheme.lower() != "https":
            return error_response("authentication tokens require HTTPS", 400)
        fetch_args.update(auth_token=auth_token, auth_header=auth_header)

    try:
        config_content = live_fetcher.fetch_config(**fetch_args)
    except ValueError:
        return error_response("collection target rejected by security policy", 400)
    except Exception:
        return error_response(
            "Unable to collect configuration. Verify reachability, credentials, and trust settings.",
            502,
        )

    if not isinstance(config_content, str) or not config_content.strip():
        return error_response("the target returned no configuration data", 502)
    if len(config_content.encode("utf-8")) > 1024 * 1024:
        return error_response("collected configuration exceeds the 1 MB limit", 413)
    if is_web_document(config_content):
        return error_response(HTML_ERROR, 422)
    # Defense in depth: content sanity check (catches HTML/JS/error pages not at start)
    if looks_like_html(config_content):
        return error_response(CONFIG_SANITY_ERROR, 422)
    plausible, reason = is_plausible_config(config_content)
    if not plausible:
        return error_response(f"{CONFIG_SANITY_ERROR} ({reason})", 422)

    tmp_path = None
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as temp_file:
            temp_file.write(config_content)
            tmp_path = temp_file.name

        serial_arg = serial_number.strip() or "_"
        hardware_arg = hardware_model.strip() or "_"
        os_arg = os_version.strip() or "_"
        args = [
            "ingest-config", name, device_id, vendor, tmp_path,
            serial_arg, hardware_arg, os_arg, "live_fetch",
        ]
        rc, out, _ = run_java_helper("TrinetraBridgeHelper", args, timeout=120)
        if rc != 0:
            return error_response("collected configuration could not be ingested", 500)
        try:
            result = json.loads(out.strip())
        except (TypeError, json.JSONDecodeError):
            return error_response("configuration ingestion returned an invalid response", 500)
        result.update({
            "source_type": source_type,
            "target": target,
            "config_filename": f"{device_id}_live_fetch.txt",
        })
        return jsonify(result), 200
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
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

# ── GET /api/session/<name>/devices — per-device summary for multi-device dashboard ──
@app.route("/api/session/<name>/devices", methods=["GET"])
def session_devices(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)

    # Read session JSON for device metadata
    session_path = os.path.join(TRINETRA_ROOT, "sessions", name, f"{name}.json")
    if not os.path.exists(session_path):
        return error_response(f"session not found: {name}", 404)

    try:
        with open(session_path, "r") as f:
            session_data = json.load(f)
    except Exception as e:
        return error_response(f"failed to read session: {e}", 500)

    # Read brain state for normalized_results (pass/fail counts)
    brain_path = os.path.join(TRINETRA_ROOT, "sessions", name, f"brain_state_{name}.json")
    brain_data = {}
    if os.path.exists(brain_path):
        try:
            with open(brain_path, "r") as f:
                brain_data = json.load(f)
        except (OSError, ValueError):
            return error_response('Assessment evidence could not be read. Restore a valid backup before trusting results.', 500)

    device_vendors = session_data.get("device_vendors") or {}
    device_ingestion = session_data.get("device_ingestion") or {}
    device_details = session_data.get("device_details") or {}
    findings = session_data.get("findings") or []
    normalized_results = brain_data.get("normalized_results") or []

    # Build device set from findings + device_vendors
    device_ids = set(device_vendors.keys())
    for f in findings:
        did = f.get("device_id")
        if did:
            device_ids.add(did)
    for nr in normalized_results:
        did = nr.get("device_id")
        if did:
            device_ids.add(did)

    removed = session_data.get("removed_devices") or {}
    device_ids.difference_update(removed)

    # Build per-device summaries
    devices = []
    for did in sorted(device_ids):
        vendor = device_vendors.get(did, "unknown")
        ingestion = device_ingestion.get(did)
        ingestion_method = ingestion.get("method", "unknown") if ingestion else "unknown"
        ingestion_filename = ingestion.get("filename") if ingestion else None

        # Count pass/fail/manual_review from findings
        pass_count = 0
        fail_count = 0
        total = 0
        for f in findings:
            if f.get("device_id") == did:
                total += 1
                verdict = (f.get("verdict") or "").lower()
                if verdict == "pass":
                    pass_count += 1
                elif verdict == "fail":
                    fail_count += 1

        # Also count from normalized_results (more authoritative)
        nr_pass = 0
        nr_fail = 0
        nr_total = 0
        for nr in normalized_results:
            if nr.get("device_id") == did:
                nr_total += 1
                result = (nr.get("normalized_result") or "").lower()
                if result == "pass":
                    nr_pass += 1
                elif result == "fail":
                    nr_fail += 1

        # Use normalized_results counts if available, else findings
        if nr_total > 0:
            pass_count, fail_count, total = nr_pass, nr_fail, nr_total

        details = device_details.get(did) or {}
        serial_number = details.get("serial_number", "")
        hardware_model = details.get("hardware_model", "")
        os_version = details.get("os_version", "")

        devices.append({
            "device_id": did,
            "vendor": vendor,
            "ingestion_method": ingestion_method,
            "filename": ingestion_filename,
            "serial_number": serial_number,
            "hardware_model": hardware_model,
            "os_version": os_version,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "total_checks": total,
        })

    return jsonify({
        "session": name,
        "device_count": len(devices),
        "devices": devices,
        "removed_devices": sorted(removed),
    }), 200


@app.route("/api/session/<name>/devices/<device_id>", methods=["DELETE"])
@app.route("/api/session/<name>/devices/<device_id>/restore", methods=["POST"])
def device_scope(name, device_id):
    if not validate_session(name) or not validate_device(device_id):
        return error_response("invalid session or device identifier", 400)
    if not os.path.isfile(os.path.join(TRINETRA_ROOT, "sessions", name, f"{name}.json")):
        return error_response(f"session not found: {name}", 404)
    command = "remove-device" if request.method == "DELETE" else "restore-device"
    rc, out, err = run_java_helper("TrinetraBridgeHelper", [command, name, device_id])
    if rc != 0:
        return error_response("Device not found" if rc == 2 else "Could not update device scope", 404 if rc == 2 else 500)
    return jsonify({"session": name, "device_id": device_id, "removed": request.method == "DELETE", "evidence_retained": True})


# ── GET /api/session/<name>/compare — assessment comparison (review item 2) ──
# Compares the two most recent assessments per V-code for one device, using only
# the existing hash-chained normalized_results history — no new storage.
# Scope note: the data model has no explicit assessment IDs (append-only per-test
# history), so latest-two-per-V-code is the only honest comparison available.
_COMPARE_CAT1 = {"V-003", "V-006", "V-013", "V-057", "V-058", "V-071", "V-107"}
_COMPARE_CAT2 = {"V-005", "V-007", "V-008", "V-070", "V-087", "V-105", "V-106", "V-144"}

def _compare_class(test_id, verdict, assessment_kind=""):
    tid = (test_id or "").strip().upper()
    v = (verdict or "").strip().lower()
    kind = (assessment_kind or "").strip().lower()
    if tid == "UNRECOGNIZED":
        return "unsupported check"
    if v in ("error", "not_tested"):
        return "unsupported check"
    is_live = kind in ("live_probe", "stat_script")
    if tid in _COMPARE_CAT2 and not is_live:
        return "unsupported check"
    if v == "fail":
        return "confirmed risk"
    if v in ("pass", "success"):
        return "verified pass"
    return "insufficient evidence"


def _compare_transition(before_cls, after_cls):
    if before_cls == "confirmed risk" and after_cls == "verified pass":
        return "resolved"
    if before_cls == "verified pass" and after_cls == "confirmed risk":
        return "newly failing"
    if before_cls in ("insufficient evidence", "unsupported check") and after_cls in ("insufficient evidence", "unsupported check"):
        return "still unresolved"
    if before_cls == after_cls:
        return "unchanged"
    return "unchanged"


@app.route("/api/session/<name>/compare", methods=["GET"])
def compare_assessments(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)
    device_id = request.args.get("device_id") or request.args.get("deviceId")
    if not device_id or not validate_device(device_id):
        return error_response("device_id query parameter is required", 400)
    brain_path = os.path.join(TRINETRA_ROOT, "sessions", name, f"brain_state_{name}.json")
    if not os.path.exists(brain_path):
        return error_response(f"session not found: {name}", 404)
    try:
        with open(brain_path, "r") as f:
            brain_data = json.load(f)
    except (OSError, ValueError):
        return error_response("Assessment evidence could not be read. Restore a valid backup before trusting results.", 500)
    entries = [e for e in (brain_data.get("normalized_results") or [])
               if isinstance(e, dict) and e.get("device_id") == device_id]
    if not entries:
        return error_response(f"no assessments recorded for device {device_id!r}", 404)
    by_test = {}
    for e in entries:
        tid = e.get("test_id") or "?"
        by_test.setdefault(tid, []).append(e)
    comparisons = []
    for tid in sorted(by_test):
        ordered = sorted(by_test[tid], key=lambda x: str(x.get("timestamp") or ""))
        after = ordered[-1]
        before = ordered[-2] if len(ordered) >= 2 else ordered[-1]
        after_v = (after.get("normalized_result") or "").lower()
        before_v = (before.get("normalized_result") or "").lower()
        after_cls = after.get("finding_class") or _compare_class(tid, after_v, after.get("assessment_kind") or "")
        before_cls = before.get("finding_class") or _compare_class(tid, before_v, before.get("assessment_kind") or "")
        comparisons.append({
            "test_id": tid,
            "before": {"verdict": before_v, "finding_class": before_cls,
                       "timestamp": before.get("timestamp")},
            "after": {"verdict": after_v, "finding_class": after_cls,
                      "timestamp": after.get("timestamp")},
            "transition": _compare_transition(before_cls, after_cls),
            "assessments_compared": len(ordered),
        })
    summary = {"resolved": 0, "newly failing": 0, "unchanged": 0, "still unresolved": 0}
    for c in comparisons:
        summary[c["transition"]] = summary.get(c["transition"], 0) + 1
    return jsonify({
        "session": name,
        "device_id": device_id,
        "basis": ("Latest-two assessments per V-code from the hash-chained normalized_results history; "
                  "no new storage. Explicit assessment-ID selection is not supported by the current "
                  "append-only per-test data model, so this scope was chosen."),
        "comparisons": comparisons,
        "summary": summary,
    }), 200

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
    os_version_train = data.get("os_version") or data.get("osVersion") or data.get("os") or ""

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
    if os_version_train and (not isinstance(os_version_train, str) or len(os_version_train) > 128 or contains_injection(os_version_train)):
        return error_response(f"invalid os_version: {os_version_train!r}", 400)

    # Directly update the JSON file via Python (no Java code change) — this is the training loop
    try:
        from pathlib import Path as _P
        import json as _json
        map_path = _P(TRINETRA_ROOT) / "config" / "vendor_training_map.json"
        with TRAINING_MAP_LOCK:
            content = "{}"
            if map_path.exists():
                content = map_path.read_text(encoding="utf-8")
            data_json = _json.loads(content) if content.strip() else {}
            if "entries" not in data_json or not isinstance(data_json["entries"], list):
                data_json["entries"] = []
            # Duplicate detection and the write share one critical section.
            for e in data_json["entries"]:
                if e.get("vendor","").lower() == vendor.lower() and e.get("pattern","") == pattern:
                    return error_response("training entry already exists for this vendor+pattern", 409)
            new_entry = {
                "vendor": vendor,
                "pattern": pattern,
                "security_category": category,
                "control_mapping": controls,
                "remediation": remediation,
                "added_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z"),
                "added_via": f"session:{name}"
            }
            if os_version_train and os_version_train.strip():
                new_entry["os_version"] = os_version_train.strip()
            data_json["entries"].append(new_entry)
            map_path.parent.mkdir(parents=True, exist_ok=True)
            import tempfile as _tf, os as _os
            tmp = None
            try:
                with _tf.NamedTemporaryFile(mode="w", delete=False, dir=str(map_path.parent), encoding="utf-8") as tf:
                    _json.dump(data_json, tf, indent=2)
                    tmp = tf.name
                _os.replace(tmp, str(map_path))
                tmp = None
            finally:
                if tmp:
                    try:
                        _os.unlink(tmp)
                    except OSError:
                        pass
        # Invalidate Java cache by touching file (VendorTrainingMap.load checks mtime)
        # Retrain lightweight ML (TF-IDF + KNN) in parallel — never fails the training request
        try:
            import ml_knn
            ml_knn.train()
        except ImportError:
            try:
                from bridge.ml_knn import train as _ml_train
                _ml_train()
            except Exception:
                pass
        except Exception:
            pass
        return jsonify({"message": "training entry added", "entry": new_entry, "total_entries": len(data_json["entries"])}), 201
    except Exception as e:
        return error_response(f"failed to add training entry: {e}", 500)

# ── Lightweight ML advisory endpoints (KNN TF-IDF, parallel to regex) ──
@app.route("/api/ml/suggest", methods=["POST"])
def ml_suggest():
    data = request.get_json(silent=True) or {}
    line = data.get("line") or data.get("text") or ""
    if not isinstance(line, str) or not line.strip():
        return error_response("line is required", 400)
    # vendor hint optional — currently unused but kept for future per-vendor models
    vendor = data.get("vendor") or data.get("vendor_hint") or ""
    try:
        try:
            from bridge.ml_knn import predict
        except ImportError:
            from ml_knn import predict
        pred = predict(line, vendor if isinstance(vendor, str) else None)
        return jsonify({"line": line.strip(), "ml": pred, "model": "tfidf_char3-5_knn_k3_cosine", "deterministic_fallback": "regex DecisionEngine remains authoritative"}), 200
    except Exception as e:
        return jsonify({"line": line.strip(), "ml": None, "error": str(e)[:200]}), 200

@app.route("/api/ml/train", methods=["POST"])
def ml_train():
    try:
        try:
            from bridge.ml_knn import train
        except ImportError:
            from ml_knn import train
        ok = train(force=True)
        # report corpus size
        from pathlib import Path as _P2
        import json as _j2
        corp = _P2(TRINETRA_ROOT) / "config" / "ml_corpus.json"
        n = len(_j2.loads(corp.read_text())) if corp.exists() else 0
        return jsonify({"retrained": bool(ok), "corpus_size": n, "model": "tfidf_char3-5_knn_k3_cosine"}), 200
    except Exception as e:
        return error_response(f"ml train failed: {e}", 500)

@app.route("/api/ml/status", methods=["GET"])
def ml_status():
    try:
        from pathlib import Path as _P3
        import json as _j3
        has_sklearn = True
        try:
            import sklearn
        except ImportError:
            has_sklearn = False
        corp = _P3(TRINETRA_ROOT) / "config" / "ml_corpus.json"
        model = _P3(TRINETRA_ROOT) / "config" / "ml_model.pkl"
        vec = _P3(TRINETRA_ROOT) / "config" / "ml_vectorizer.pkl"
        n = len(_j3.loads(corp.read_text())) if corp.exists() else 0
        return jsonify({
            "has_sklearn": has_sklearn,
            "corpus_size": n,
            "model_exists": model.exists(),
            "vectorizer_exists": vec.exists(),
            "model_path": str(model),
            "threshold": 0.55,
            "k": 3,
            "analyzer": "char_wb 3-5 cosine",
            "fallback": "regex DecisionEngine authoritative, ML advisory only"
        }), 200
    except Exception as e:
        return error_response(f"ml status failed: {e}", 500)

# ── NLP Pattern Recognition (Gemini) — true semantic interpretation ──
@app.route("/api/nlp/suggest", methods=["POST"])
def nlp_suggest():
    data = request.get_json(silent=True) or {}
    line = data.get("line") or data.get("text") or ""
    if not isinstance(line, str) or not line.strip():
        return error_response("line is required", 400)
    vendor = data.get("vendor") or data.get("vendor_hint") or ""
    if len(line) > 500:
        return error_response("line too long (max 500)", 400)
    if any(c in line for c in [';', '&', '|', '`', '\n', '\r']):
        return error_response("injection characters detected", 400)
    try:
        rc, out, err = run_java_helper("TrinetraBridgeHelper", ["nlp-suggest", line.strip(), vendor if isinstance(vendor, str) else ""], timeout=30)
        if rc != 0 and "LLM unavailable" not in (out + err):
            # Try to parse even if non-zero, fallback to empty
            try:
                data = json.loads(out.strip())
                return jsonify(data), 200
            except:
                pass
            return jsonify({"line": line.strip(), "nlp": None, "note": "NLP unavailable"}), 200
        try:
            data = json.loads(out.strip().split("\n")[-1] if "\n" in out else out.strip())
            # Find JSON part
            j_start = out.find("{")
            j_end = out.rfind("}")
            if j_start >= 0 and j_end >= 0:
                data = json.loads(out[j_start:j_end+1])
            return jsonify(data), 200
        except Exception as je:
            return jsonify({"line": line.strip(), "nlp": None, "error": f"parse failed: {je}", "raw": out[:500]}), 200
    except Exception as e:
        return jsonify({"line": line.strip(), "nlp": None, "error": str(e)[:200]}), 200

# ── Vendor Auto-Discovery (Iskabon + Trinetra) — zero-code new vendor learning ──
@app.route("/api/vendor/discovery", methods=["GET"])
def vendor_discovery():
    try:
        p = Path(TRINETRA_ROOT) / "config" / "vendor_discovery_map.json"
        if not p.exists():
            return jsonify({"oids": {}, "os_families": {}, "pending_oids": {}, "banner_learned": {}}), 200
        data = json.loads(p.read_text(encoding="utf-8"))
        return jsonify(data), 200
    except Exception as e:
        return error_response(f"discovery map read failed: {e}", 500)

@app.route("/api/vendor/discovery/report", methods=["POST"])
def vendor_discovery_report():
    """Report an unknown vendor/OID/banner — auto-promotes after 3 sightings (clustering)."""
    data = request.get_json(silent=True) or {}
    oid = (data.get("oid") or data.get("sysObjectID") or "").strip()
    banner = (data.get("banner") or data.get("raw_banner") or "").strip()
    vendor_guess = (data.get("vendor_guess") or data.get("vendor") or "").strip()
    if not oid and not banner and not vendor_guess:
        return error_response("oid or banner or vendor_guess required", 400)
    if oid and not re.match(r"^1\.3\.6\.1\.4\.1\.\d+(\.\d+)*$", oid):
        return error_response("invalid OID format", 400)
    if vendor_guess and (len(vendor_guess) > 32 or contains_injection(vendor_guess)):
        return error_response("invalid vendor_guess", 400)
    try:
        p = Path(TRINETRA_ROOT) / "config" / "vendor_discovery_map.json"
        raw = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"oids": {}, "os_families": {}, "pending_oids": {}, "banner_learned": {}}
        # Banner learning: if banner contains SSH vendor, auto-extract
        if banner and not vendor_guess:
            m = re.search(r"SSH-\d+\.\d+-([A-Za-z0-9-]+)[_\- ]", banner)
            if m:
                vendor_guess = m.group(1).strip()
        if oid and vendor_guess:
            # Direct promotion if vendor_guess provided
            enterprise = ".".join(oid.split(".")[:7])  # 1.3.6.1.4.1.<num>
            if enterprise not in raw.get("oids", {}):
                raw.setdefault("oids", {})[enterprise] = vendor_guess
                # Also ensure OS family table has it
                raw.setdefault("os_families", {})[vendor_guess.lower()] = vendor_guess
                p.write_text(json.dumps(raw, indent=2), encoding="utf-8")
                return jsonify({"learned": True, "enterprise": enterprise, "vendor": vendor_guess, "method": "direct"}), 200
        if oid:
            enterprise = ".".join(oid.split(".")[:7])
            pending = raw.setdefault("pending_oids", {})
            entry = pending.get(enterprise, {"count": 0, "raw_oids": [], "banner_samples": []})
            entry["count"] = int(entry.get("count", 0)) + 1
            if oid not in entry.get("raw_oids", []):
                entry.setdefault("raw_oids", []).append(oid)
            if banner and banner not in entry.get("banner_samples", []):
                entry.setdefault("banner_samples", []).append(banner[:200])
            if vendor_guess and "vendor_guess" not in entry:
                entry["vendor_guess"] = vendor_guess
            pending[enterprise] = entry
            # Auto-promote after 3 sightings with consistent banner vendor
            if entry["count"] >= 3 and entry.get("vendor_guess"):
                raw.setdefault("oids", {})[enterprise] = entry["vendor_guess"]
                raw.setdefault("os_families", {})[entry["vendor_guess"].lower()] = entry["vendor_guess"]
                # Move to learned
                raw.setdefault("banner_learned", {})[entry["vendor_guess"]] = f"auto-learned from {enterprise} after 3 sightings"
                del pending[enterprise]
                p.write_text(json.dumps(raw, indent=2), encoding="utf-8")
                return jsonify({"learned": True, "enterprise": enterprise, "vendor": entry["vendor_guess"], "method": "auto-promote-3x"}), 200
            p.write_text(json.dumps(raw, indent=2), encoding="utf-8")
            return jsonify({"learned": False, "pending": entry, "need": 3 - entry["count"]}), 200
        if vendor_guess and banner:
            raw.setdefault("banner_learned", {})[vendor_guess] = banner[:200]
            raw.setdefault("os_families", {})[vendor_guess.lower()] = vendor_guess
            p.write_text(json.dumps(raw, indent=2), encoding="utf-8")
            return jsonify({"learned": True, "vendor": vendor_guess, "method": "banner"}), 200
        return jsonify({"learned": False}), 200
    except Exception as e:
        return error_response(f"discovery report failed: {e}", 500)

@app.route("/api/vendor/discovery/learn", methods=["POST"])
def vendor_discovery_learn():
    """Manual teaching: directly add OID or vendor mapping (low-code, no redeploy)."""
    data = request.get_json(silent=True) or {}
    oid = (data.get("oid") or "").strip()
    vendor = (data.get("vendor") or "").strip()
    os_family = (data.get("os_family") or "").strip()
    if not vendor or not validate_vendor(vendor):
        return error_response("valid vendor required", 400)
    if oid and not re.match(r"^1\.3\.6\.1\.4\.1\.\d+(\.\d+)*$", oid):
        return error_response("invalid OID", 400)
    if os_family and (len(os_family) > 32 or contains_injection(os_family)):
        return error_response("invalid os_family", 400)
    try:
        p = Path(TRINETRA_ROOT) / "config" / "vendor_discovery_map.json"
        raw = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"oids": {}, "os_families": {}, "pending_oids": {}, "banner_learned": {}}
        if oid:
            enterprise = ".".join(oid.split(".")[:7])
            raw.setdefault("oids", {})[enterprise] = vendor
        if os_family:
            raw.setdefault("os_families", {})[os_family.lower()] = vendor
        else:
            raw.setdefault("os_families", {})[vendor.lower()] = vendor
        raw.setdefault("banner_learned", {})[vendor] = f"manual learn {oid or vendor}"
        p.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        return jsonify({"learned": True, "vendor": vendor, "oid": oid, "os_family": os_family or vendor.lower()}), 200
    except Exception as e:
        return error_response(f"learn failed: {e}", 500)

# ── GET /api/session/<name>/audit-report/pdf — PDF export ──
@app.route("/api/session/<name>/audit-report/pdf", methods=["GET"])
def audit_report_pdf(name):
    if not validate_session(name):
        return error_response(f"invalid session name: {name!r}", 400)
    # First ensure audit report exists (generate if needed) — honor framework filter
    fw_filter = get_framework_filter()
    tr_args = ["-audit-report", name]
    if fw_filter:
        tr_args += ["--frameworks", ",".join(fw_filter)]
    rc, out, err = run_trinetra(tr_args, timeout=120)
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
        from xml.sax.saxutils import escape as xml_escape
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

        # Build PDF in memory — landscape for 9-col evidence table (Device+Serial+Hardware+OS+Test+Verdict+Severity+Timestamp)
        buffer = io.BytesIO()
        from reportlab.lib.pagesizes import landscape
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), rightMargin=24, leftMargin=24, topMargin=24, bottomMargin=16)
        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        heading_style = styles["Heading2"]
        normal_style = styles["Normal"]
        small_style = ParagraphStyle('small', parent=normal_style, fontSize=7, leading=9)
        header_cell_style = ParagraphStyle('headerCell', parent=normal_style, fontSize=6, leading=7, textColor=colors.whitesmoke, alignment=1)
        # Custom style for evidence rows
        story = []

        # Title
        story.append(Paragraph(f"Cortex Audit Report — {name}", title_style))
        story.append(Paragraph("Configuration evidence assessment, not a compliance certification. Manual review, errors, and untested checks are unresolved evidence, not confirmed failures. Review scope and applicability before acting.", normal_style))
        story.append(Spacer(1, 12))

        # Session metadata table
        sess_target = status_data.get("target", "unknown")
        chain_info = status_data.get("chain", {})
        meta_data = [
            ["Session", name],
            ["Target", sess_target],
            ["Generated", __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z")],
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
        # Add distinct hardware metadata (PS Deliverable 4) + OS version (item 8 metadata-level)
        device_details = status_data.get("device_details", {})
        if device_details:
            for dev, det in device_details.items():
                if not isinstance(det, dict):
                    continue
                sn = det.get("serial_number", "")
                hw = det.get("hardware_model", "")
                osv = det.get("os_version", "")
                if sn:
                    meta_data.append([f"Device {dev} serial", sn])
                if hw:
                    meta_data.append([f"Device {dev} hardware", hw])
                if osv:
                    meta_data.append([f"Device {dev} OS version", osv])
                if not sn and not hw and not osv:
                    meta_data.append([f"Device {dev} details", "no serial/hardware/OS provided (optional)"])

        t = Table(meta_data, colWidths=[2.5*inch, 8*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

        # Evidence rows — parse markdown's evidence tables dynamically (supports old 5-col + new 9-col with Serial/Hardware/OS/Severity)
        import re as _re
        header_row = None
        evidence_rows = []
        # Include each selected framework's score summary in the export.
        story.append(Paragraph("Mapped-check outcomes", heading_style))
        current_framework = ""
        for line in md_content.splitlines():
            if line.startswith("### "):
                current_framework = line[4:].strip()
            elif line.startswith("- Mapped-check pass rate:"):
                story.append(Paragraph(xml_escape(current_framework + ": " + line[2:].replace("**", "")), normal_style))
            elif line.startswith(("- Passed/failed/total mapped:", "- Manual review/errors/not tested:")):
                story.append(Paragraph(xml_escape(line[2:]), normal_style))
        story.append(Spacer(1, 12))
        in_evidence = False
        seen_evidence = set()
        col_index = {}
        for line in md_content.splitlines():
            if "| Device" in line and "Vendor" in line:
                # Header line — capture column names for dynamic indexing
                header_cells = markdown_cells(line)
                header_row = header_cells
                # Build case-insensitive index map
                col_index = {c.lower(): i for i, c in enumerate(header_cells)}
                in_evidence = True
                continue
            if in_evidence and line.strip().startswith("|"):
                # Skip separator line like |--------| etc
                stripped = line.strip()
                if set(stripped.replace("|","").replace("-","").replace(":","").strip()) == set() or stripped.replace("|","").replace("-","").strip() == "":
                    continue
                if stripped.startswith("|--------") or stripped.startswith("|---"):
                    continue
                parts = markdown_cells(line)
                # Ignore header repeated
                if parts and parts[0].lower() == "device" and "vendor" in " ".join(parts).lower():
                    continue
                if len(parts) >= 2 and tuple(parts) not in seen_evidence:
                    evidence_rows.append(parts)
                    seen_evidence.add(tuple(parts))
            elif in_evidence and not line.strip().startswith("|"):
                in_evidence = False

        if evidence_rows and header_row:
            story.append(Paragraph("Evidence — Per-Device Test Results", heading_style))
            # Use header from markdown directly for PDF header; fallback to old 5-col if header missing new fields
            # Build PDF header cells as Paragraphs for wrapping
            pdf_header = [Paragraph(f"<b>{xml_escape(h)}</b>", header_cell_style) for h in header_row[:10]]
            table_data = [pdf_header]
            # Determine indices for verdict/severity/device for remediation extraction
            verdict_idx = col_index.get("verdict", 3)
            # Severity may be present at different index
            for row in evidence_rows[:60]:  # limit
                # Ensure row length matches header
                while len(row) < len(header_row):
                    row.append("")
                # Truncate to header length
                pdf_row = [Paragraph(xml_escape(p.replace("_", " ") if i == verdict_idx else p), small_style) for i, p in enumerate(row[:len(header_row)])]
                table_data.append(pdf_row)
            # Column widths: distribute landscape width (~10.5 inch usable) across columns
            ncols = len(header_row)
            # Heuristic widths: Device 1.1, Vendor 0.9, Serial 0.9, Hardware 1.0, OS 1.0, Test 0.8, Verdict 0.7, Severity 0.8, Timestamp 1.2, Controls 1.3
            width_map = {"device":1.0, "vendor":0.9, "serial":0.9, "hardware":1.0, "os version":1.0, "os":1.0, "test id":0.8, "verdict":1.1, "severity":0.8, "timestamp":1.4, "controls":1.4}
            col_widths = []
            for h in header_row:
                w = width_map.get(h.lower(), 0.9) * inch
                col_widths.append(w)
            # Normalize to fit ~10.5 inch
            total_w = sum(col_widths)
            if total_w > 10.5*inch:
                scale = (10.5*inch)/total_w
                col_widths = [w*scale for w in col_widths]
            et = Table(table_data, repeatRows=1, colWidths=col_widths)
            et.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#4472C4")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTSIZE', (0,0), (-1,-1), 6),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F2F2F2")]),
                ('LEFTPADDING', (0,0), (-1,-1), 3),
                ('RIGHTPADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(et)
            if len(evidence_rows) > 60:
                story.append(Paragraph(f"Showing 60 of {len(evidence_rows)} evidence rows. The generated Markdown audit report contains the complete table.", normal_style))
            story.append(Spacer(1, 12))
        elif evidence_rows:
            # Fallback old 5-col
            story.append(Paragraph("Evidence — Per-Device Test Results", heading_style))
            table_data = [["Device ID", "Vendor", "Test ID", "Verdict", "Timestamp"]]
            for row in evidence_rows[:50]:
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

        # Advice must not invent platform-specific commands or claim AI provenance.
        # Finding classes use the same four terms as UI + markdown: confirmed risk /
        # verified pass / insufficient evidence / unsupported check.
        fc_idx = col_index.get("finding class", -1)
        v_idx = col_index.get("verdict", -1)
        def _row_class(r):
            if 0 <= fc_idx < len(r) and r[fc_idx].strip().lower() in (
                    "confirmed risk", "verified pass", "insufficient evidence", "unsupported check"):
                return r[fc_idx].strip().lower()
            if 0 <= v_idx < len(r):
                vv = r[v_idx].strip().lower()
                if vv == "fail":
                    return "confirmed risk"
                if vv == "pass":
                    return "verified pass"
                if vv == "manual_review":
                    return "insufficient evidence"
            return "unsupported check"
        failed_rows = [r for r in evidence_rows if _row_class(r) == "confirmed risk"]
        if failed_rows:
            story.append(Paragraph("Review plan for confirmed risks", heading_style))
            story.append(Paragraph("Each item below cites its triggering source lines from the session evidence bundle. Curated Cisco IOS steps are shown only here (Documented — review before use; backup, confirm OS version, rollback plan, post-change verify). All other finding classes use generic guidance. Cortex does not validate or execute remediation commands.", normal_style))
            for row in failed_rows[:60]:
                tid = row[col_index.get("test id", 2)] if col_index.get("test id", 2) < len(row) else "?"
                device = row[col_index.get("device", 0)] if col_index.get("device", 0) < len(row) else "?"
                story.append(Paragraph(xml_escape(f"{tid} on {device}: confirmed risk — operator review required."), normal_style))
        # Traceable remediation lines from the markdown (curated steps for confirmed risks only).
        remediation_lines = [line for line in md_content.splitlines()
                             if line.startswith("Remediation:")]
        if remediation_lines:
            story.append(Paragraph("Traceable remediation (confirmed risks only)", heading_style))
            for line in remediation_lines[:60]:
                story.append(Paragraph(xml_escape(line), normal_style))
            story.append(Spacer(1, 6))
            curated = [line for line in md_content.splitlines()
                       if line.startswith("Curated Cisco IOS steps")]
            for line in curated[:60]:
                story.append(Paragraph(xml_escape(line), small_style))
            story.append(Spacer(1, 12))

        config_lines = [line for line in md_content.splitlines()
                        if line.startswith(("Config review:", "Config observation:", "Config limitation:"))]
        if config_lines:
            story.append(Paragraph("Configuration observations — separate from benchmark scores", heading_style))
            for line in config_lines:
                story.append(Paragraph(xml_escape(line), normal_style))
            story.append(Spacer(1, 12))

        # Script-output evidence bundle (per-session JSON + MD, cited by the report)
        script_lines = [line for line in md_content.splitlines()
                        if line.startswith("Script evidence:")]
        evidence_count = status_data.get("evidence_count", 0)
        if script_lines or evidence_count:
            story.append(Paragraph("Script output evidence", heading_style))
            story.append(Paragraph(xml_escape(
                f"{evidence_count or len(script_lines)} script execution(s) recorded in "
                f"evidence_{name}.json / evidence_{name}.md (sessions/{name}/). "
                "Each verdict in this PDF traces to one raw stdout/stderr entry in that bundle."
            ), normal_style))
            for line in script_lines[:60]:
                story.append(Paragraph(xml_escape(line), normal_style))
            if len(script_lines) > 60:
                story.append(Paragraph(xml_escape(
                    f"Showing 60 of {len(script_lines)} script-evidence lines. See evidence_{name}.json for the full bundle."
                ), normal_style))
            story.append(Spacer(1, 12))

        # Unrecognized lines section if any
        unrec = status_data.get("unrecognized_by_device", {})
        if unrec:
            story.append(Spacer(1, 12))
            story.append(Paragraph("Unrecognized Config Lines (Training Needed)", heading_style))
            for dev, lines in unrec.items():
                if lines:
                    story.append(Paragraph(f"Device {xml_escape(str(dev))}: {len(lines)} unrecognized line(s)", normal_style))
                    story.append(Paragraph('Raw configuration lines are omitted from this export because they may contain credentials. Review them locally in Training.', normal_style))

        # Footer — note bonus frameworks (now includes STIG as PS-required)
        story.append(Spacer(1, 12))
        story.append(Paragraph("Note: PCI-DSS and SOC2 are shown as <b>bonus/additional coverage</b> only. PS-required frameworks are CIS, NIST 800-53, ISO 27001, and STIG (STIG controls: CISC-ND/JUSX-ND via DISA STIG Viewer).", normal_style))
        story.append(Spacer(1, 6))
        story.append(Paragraph("Generated by Cortex — configuration evidence assessment (live SSH optional). Collection method is recorded per device. Review findings before remediation.", normal_style))

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

# ── GET /api/session/<name>/devices/<device_id>/pdf — Per-device PDF (PS single PDF per device) ──
@app.route("/api/session/<name>/devices/<device_id>/pdf", methods=["GET"])
@app.route("/api/session/<name>/devices/<device_id>/audit-report/pdf", methods=["GET"])
@app.route("/api/session/<name>/audit-report/device/<device_id>/pdf", methods=["GET"])
def device_audit_pdf(name, device_id):
    if not validate_session(name) or not validate_device(device_id):
        return error_response("invalid session or device identifier", 400)
    fw_filter = get_framework_filter()
    fw_arg = ",".join(fw_filter) if fw_filter else "_"
    rc, out, err = run_java_helper("TrinetraBridgeHelper", ["device-audit-report", name, device_id, fw_arg], timeout=120)
    if rc != 0:
        msg = (err.strip() or out.strip()) or "device report failed"
        if "not found" in msg.lower():
            return error_response(msg, 404, {"stdout": out, "stderr": err})
        return error_response(msg, 500, {"stdout": out, "stderr": err})
    try:
        data = json.loads(out.strip())
        device_path = data.get("device_path") or data.get("combined_path")
        if not device_path or not os.path.exists(device_path):
            return error_response("device report not found after generation", 500, {"stdout": out, "stderr": err})
        with open(device_path, "r") as f:
            md_content = f.read()
        rc2, out2, _ = run_java_helper("TrinetraBridgeHelper", ["status", name])
        status_data = {}
        if rc2 == 0:
            try: status_data = json.loads(out2.strip())
            except: pass
        # Reuse PDF logic but title is device-specific
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from xml.sax.saxutils import escape as xml_escape
        import io
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), rightMargin=24, leftMargin=24, topMargin=24, bottomMargin=16)
        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]; heading_style = styles["Heading2"]; normal_style = styles["Normal"]
        small_style = ParagraphStyle('small', parent=normal_style, fontSize=7, leading=9)
        header_cell_style = ParagraphStyle('headerCell', parent=normal_style, fontSize=6, leading=7, textColor=colors.whitesmoke, alignment=1)
        story = []
        det = status_data.get("device_details", {}).get(device_id, {}) if isinstance(status_data.get("device_details"), dict) else {}
        vendor = status_data.get("device_vendors", {}).get(device_id, det.get("vendor", "unknown")) if isinstance(status_data.get("device_vendors"), dict) else det.get("vendor", "unknown")
        story.append(Paragraph(f"Device Audit Report — {xml_escape(device_id)} ({xml_escape(str(vendor))})", title_style))
        story.append(Paragraph(f"Session {xml_escape(name)} — single device report. Configuration evidence assessment, not a compliance certification.", normal_style))
        story.append(Spacer(1, 12))
        meta = [
            ["Session", name],
            ["Device ID", device_id],
            ["Vendor", str(vendor)],
            ["Serial", str(det.get("serial_number", ""))],
            ["Hardware", str(det.get("hardware_model", ""))],
            ["OS Version", str(det.get("os_version", ""))],
            ["Generated", __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00","Z")],
            ["Chain", (status_data.get("chain", {}).get("detail", "unknown") if isinstance(status_data.get("chain"), dict) else "unknown")],
        ]
        t = Table(meta, colWidths=[2*__import__("reportlab.lib.units").lib.units.inch, 8*__import__("reportlab.lib.units").lib.units.inch])
        t.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.5,colors.grey),('FONTSIZE',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
        story.append(t); story.append(Spacer(1,12))
        # Evidence table from device markdown
        import re as _re
        header_row = None; evidence_rows = []; col_index = {}; in_evidence=False; seen=set()
        for line in md_content.splitlines():
            if "| Test ID" in line or ("| Device" in line and "Vendor" in line):
                header_row = markdown_cells(line); col_index={c.lower():i for i,c in enumerate(header_row)}; in_evidence=True; continue
            if in_evidence and line.strip().startswith("|"):
                if set(line.strip().replace("|","").replace("-","").replace(":","").strip())==set() or line.strip().startswith("|---") or line.strip().startswith("|--------"):
                    continue
                parts = markdown_cells(line)
                if parts and parts[0].lower()=="device" and "vendor" in " ".join(parts).lower():
                    continue
                if len(parts)>=2 and tuple(parts) not in seen:
                    evidence_rows.append(parts); seen.add(tuple(parts))
            elif in_evidence and not line.strip().startswith("|"):
                in_evidence=False
        if evidence_rows and header_row:
            story.append(Paragraph("Evidence — This Device Only", heading_style))
            pdf_header=[Paragraph(f"<b>{xml_escape(h)}</b>", header_cell_style) for h in header_row[:10]]
            table_data=[pdf_header]
            for row in evidence_rows[:80]:
                while len(row)<len(header_row): row.append("")
                pdf_row=[Paragraph(xml_escape(p), small_style) for p in row[:len(header_row)]]
                table_data.append(pdf_row)
            ncols=len(header_row); width_map={"device":1.0,"vendor":0.9,"serial":0.9,"hardware":1.0,"os version":1.0,"test id":0.8,"verdict":0.9,"finding class":1.1,"severity":0.8,"controls":1.4}
            col_widths=[width_map.get(h.lower(),0.9)*__import__("reportlab.lib.units").lib.units.inch for h in header_row]
            total_w=sum(col_widths)
            if total_w>10.5*__import__("reportlab.lib.units").lib.units.inch:
                scale=(10.5*__import__("reportlab.lib.units").lib.units.inch)/total_w
                col_widths=[w*scale for w in col_widths]
            et=Table(table_data, repeatRows=1, colWidths=col_widths)
            et.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor("#4472C4")),('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),('ALIGN',(0,0),(-1,-1),'CENTER'),('FONTSIZE',(0,0),(-1,-1),6),('GRID',(0,0),(-1,-1),0.5,colors.grey),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, colors.HexColor("#F2F2F2")])]))
            story.append(et); story.append(Spacer(1,12))
        # Remediation
        rem_lines=[l for l in md_content.splitlines() if l.startswith("Remediation:") or l.startswith("Curated Cisco")]
        if rem_lines:
            story.append(Paragraph("Traceable remediation (confirmed risks only)", heading_style))
            for l in rem_lines[:60]:
                story.append(Paragraph(xml_escape(l), small_style))
        # Baseline section
        if "## Baseline" in md_content:
            story.append(Spacer(1,12)); story.append(Paragraph("Baseline (vendor-neutral)", heading_style))
            in_baseline=False; baseline_text=[]
            for l in md_content.splitlines():
                if l.startswith("## Baseline"): in_baseline=True; continue
                if in_baseline:
                    if l.startswith("```"): continue
                    if l.startswith("#"): break
                    if l.strip(): baseline_text.append(l)
                    if len(baseline_text)>40: break
            for l in baseline_text[:40]:
                story.append(Paragraph(xml_escape(l[:200]), small_style))
        doc.build(story)
        pdf_bytes=buffer.getvalue(); buffer.close()
        from flask import Response
        return Response(pdf_bytes, mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=audit_report_{device_id}_{name}.pdf", "Content-Length": str(len(pdf_bytes))})
    except Exception as e:
        import traceback
        return error_response(f"Device PDF generation failed: {e}", 500, {"trace": traceback.format_exc()})

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
function escapeHtml(value){
  return String(value).replace(/[&<>"']/g, ch => ({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
  })[ch]);
}
let currentUnrecognizedLines = [];

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
      html+=`<tr><td>${escapeHtml(fw)}${bonus}</td><td>${escapeHtml(v.compliance_percentage)}%</td><td>${escapeHtml(v.tests_passed)}/${escapeHtml(v.total_tests_mapped)}</td></tr>`;
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
  currentUnrecognizedLines = lines;
  if(!lines.length){ $('unrecView').innerHTML='<p class="small">No unrecognized lines — all parsed via known or trained patterns.</p>'; return; }
  let html='<table><tr><th>Device</th><th>Line</th><th>Category</th><th>Controls</th><th>Action</th></tr>';
  for(let index=0; index<lines.length; index++){
    const {device, line} = lines[index];
    html+=`<tr><td>${escapeHtml(device)}</td><td><code>${escapeHtml(line.slice(0,60))}</code></td>
      <td><input id="cat_${index}" placeholder="e.g. SSH Hardening"></td>
      <td><input id="ctrl_${index}" placeholder="e.g. CIS-IOS-XE-2.1.1.1.4"></td>
      <td><button onclick="trainLine(${index})">Label</button></td></tr>`;
  }
  html+='</table>';
  $('unrecView').innerHTML=html;
  $('trainResult').textContent = JSON.stringify(j,null,2);
}

async function trainLine(index){
  const item = currentUnrecognizedLines[index];
  if(!item) return;
  const {device, line} = item;
  const session = getSession();
  const cat = document.getElementById('cat_'+index).value || 'Custom Hardening';
  const ctrl = document.getElementById('ctrl_'+index).value || 'CIS-v8-4.6';
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
            elif current_sess and line.strip().startswith("-"):
                session_errors[current_sess].append(line.strip())
    structured["session_validation"]["session_errors"] = session_errors
    # Session inventory is not the diagnostic error list.
    sessions_root = Path(TRINETRA_ROOT) / "sessions"
    all_sessions = sorted(
        folder.name for folder in sessions_root.iterdir()
        if folder.is_dir() and not folder.is_symlink() and validate_session(folder.name) and (folder / f"{folder.name}.json").is_file()
    ) if sessions_root.is_dir() else []
    structured["archived_sessions"] = [name for name in all_sessions if (sessions_root / name / '.cortex-archived').is_file()]
    structured["sessions"] = [name for name in all_sessions if name not in structured["archived_sessions"]]
    if not session_errors and "All sessions valid" in out:
        structured["session_validation"]["status"] = "valid"
    else:
        structured["session_validation"]["status"] = "warnings" if session_errors else "unknown"

    return jsonify(structured), 200

@app.route('/api/session/<name>/archive', methods=['POST', 'DELETE'])
def archive_session(name):
    """Recoverable list removal only; never rewrite or delete assessment evidence."""
    if not validate_session(name):
        return error_response('invalid session name', 400)
    root = Path(TRINETRA_ROOT) / 'sessions'
    folder = root / name
    if folder.is_symlink() or folder.resolve().parent != root.resolve():
        return error_response('invalid session path', 400)
    if not (folder / f'{name}.json').is_file():
        return error_response('session not found', 404)
    marker = folder / '.cortex-archived'
    if marker.is_symlink():
        return error_response('invalid archive marker', 400)
    archived = request.method == 'POST'
    try:
        if archived:
            # Exclusive create is atomic and leaves an existing marker untouched.
            try:
                fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                if not marker.is_file():
                    return error_response('invalid archive marker', 409)
            else:
                os.close(fd)
        else:
            marker.unlink(missing_ok=True)
    except OSError:
        app.logger.exception('Could not update session archive marker')
        return error_response('Could not update session. Refresh the list and retry.', 500)
    return jsonify(session=name, archived=archived, evidence_retained=True)


# ── Error handlers ──
@app.errorhandler(404)
def not_found(e):
    return error_response("not found", 404)

@app.errorhandler(405)
def method_not_allowed(e):
    return error_response("method not allowed", 405)

@app.errorhandler(413)
def request_too_large(e):
    return error_response(f"request too large (max {MAX_REQUEST_BYTES} bytes)", 413)

@app.errorhandler(500)
def internal_error(e):
    return error_response("internal server error", 500)

if __name__ == "__main__":
    try:
        from bridge.config import BRIDGE_HOST, BRIDGE_PORT
    except ImportError:
        from config import BRIDGE_HOST, BRIDGE_PORT
    app.run(host=BRIDGE_HOST, port=BRIDGE_PORT, debug=False)
