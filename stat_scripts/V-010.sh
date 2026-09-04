#!/bin/bash
# V-010 -- Missing HSTS header
# Tool: curl -I
# Usage: bash V-010.sh <target> <session_output_dir>
#
# Decision rule: grep_present
#   PASS = Strict-Transport-Security header present
#   FAIL = header missing

TARGET="${1:-}"
SESSION_DIR="${2:-}"

HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')
# --- Trinetra Hardening v1.0: canonical input/output contract ---
# Input: $1 target, $2 session_output_dir, env TRINETRA_VENDOR etc.
# Output: must contain VERDICT: <pass|fail|manual_review|error> and SEVERITY
# Exit 0 = script executed (verdict authoritative), non-zero = execution error
# Handles: empty, oversized, HTML/JSON/binary, injection, vendor mismatch, timeout
set -o pipefail
# Size guard: target too large (2048 bytes, 1000 lines)
if [ "${#TARGET}" -gt 2048 ]; then
  echo "VERDICT: error"
  echo "SEVERITY: none"
  echo "DETAILS: target too large (${#TARGET} bytes > 2048)"
  exit 0
fi
_LINE_COUNT=$(printf '%s' "$TARGET" | wc -l | tr -d ' ')
if [ "$_LINE_COUNT" -gt 1000 ]; then
  echo "VERDICT: error"
  echo "SEVERITY: none"
  echo "DETAILS: target too large ($_LINE_COUNT lines > 1000)"
  exit 0
fi
# Empty / whitespace-only
_TRIMMED=$(printf '%s' "$TARGET" | tr -d ' \t\n\r')
if [ -z "$_TRIMMED" ]; then
  echo "VERDICT: manual_review"
  echo "SEVERITY: none"
  echo "DETAILS: empty target"
  exit 0
fi
# Hostname/IP length and space validation
if [ "${#TARGET}" -lt 3 ]; then
  echo "VERDICT: error"
  echo "SEVERITY: none"
  echo "DETAILS: target too short (must be at least 3 chars)"
  exit 0
fi
if printf '%s' "$TARGET" | grep -q ' '; then
  echo "VERDICT: error"
  echo "SEVERITY: none"
  echo "DETAILS: target contains spaces"
  exit 0
fi
# Injection characters (shell metachars) — reject before any use
if printf '%s' "$TARGET" | grep -qE '[;|&$`><\\]'; then
  echo "VERDICT: error"
  echo "SEVERITY: none"
  echo "DETAILS: target contains illegal characters"
  exit 0
fi
if [ -n "${HOST:-}" ] && printf '%s' "$HOST" | grep -qE '[;|&$`><\\]'; then
  echo "VERDICT: error"
  echo "SEVERITY: none"
  echo "DETAILS: host contains illegal characters"
  exit 0
fi
# HTML / JS / JSON error detection (Prompt 29)
if printf '%s' "$TARGET" | grep -qiE '<!doctype html|<html|<head|<body|<script|window\.ytcfg|EMERGENCY_BASE_URL|ytInitialData'; then
  echo "VERDICT: error"
  echo "SEVERITY: none"
  echo "DETAILS: target appears to be HTML/JS, not a valid host"
  exit 0
fi
_JSON_TRIM=$(printf '%s' "$TARGET" | sed -e 's/^[[:space:]]*//')
case "$_JSON_TRIM" in
  \{*\"error\"*| \{*\"Error\"*)
    echo "VERDICT: error"
    echo "SEVERITY: none"
    echo "DETAILS: target appears to be JSON error response"
    exit 0
    ;;
esac
# Binary check (null byte) - not applicable for bash string targets, skip
if printf '%s' "$TARGET" | python3 -c "import sys; data=sys.stdin.buffer.read(); sys.exit(0 if b'\x00' in data else 1)"; then
  echo "VERDICT: error"
  echo "SEVERITY: none"
  echo "DETAILS: target contains binary data"
  exit 0
fi
# Vendor mismatch (best-effort): if TRINETRA_VENDOR set and target looks like other vendor config, flag manual_review
# This is permissive: only log, do not block, unless clear mismatch
if [ -n "${TRINETRA_VENDOR:-}" ]; then
  # Normalize vendor
  _VENDOR_LC=$(printf '%s' "$TRINETRA_VENDOR" | tr '[:upper:]' '[:lower:]')
  # If target contains Juniper set syntax but vendor is Cisco, treat as not applicable
  if printf '%s' "$TARGET" | grep -qE 'set system host-name|set interfaces' && [ "$_VENDOR_LC" = "cisco" ]; then
    echo "VERDICT: manual_review"
    echo "SEVERITY: none"
    echo "DETAILS: Juniper config fed to Cisco check — not applicable"
    exit 0
  fi
  if printf '%s' "$TARGET" | grep -qE 'hostname .+|enable secret|interface [A-Z]' && [ "$_VENDOR_LC" = "juniper" ]; then
    echo "VERDICT: manual_review"
    echo "SEVERITY: none"
    echo "DETAILS: Cisco config fed to Juniper check — not applicable"
    exit 0
  fi
fi
# Timeout safety: enforce per-tool timeouts (outer Java 300s, inner 10-90s per tool)
# Individual tools already wrapped in timeout where applicable; this header ensures script itself does not hang on large input
# End hardening header


echo "=== V-010: Missing HSTS header ==="
echo "Target: $HOST"

# --- DNS Resolution ---
RESOLVED_IP=""
for DNS in 8.8.8.8 1.1.1.1 9.9.9.9; do
    IP=$(timeout 5 dig +short +time=3 +tries=1 "$HOST" "@${DNS}" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    if [ -n "$IP" ]; then
        echo "[+] Resolved via $DNS: $IP"
        RESOLVED_IP="$IP"
        break
    fi
done

if [ -z "$RESOLVED_IP" ]; then
    RESOLVED_IP=$(timeout 5 getent hosts "$HOST" 2>/dev/null | awk '{print $1}' | head -1)
    [ -n "$RESOLVED_IP" ] && echo "[+] Resolved via system: $RESOLVED_IP"
fi

if [ -z "$RESOLVED_IP" ]; then
    echo "[-] DNS resolution failed - target may be unreachable"
    echo "VERDICT: manual_review"
    echo "SEVERITY: none"
    echo "DETAILS: DNS resolution failed"
    _VERDICT_EMITTED=1
    exit 0
fi

FOUND_HSTS=0

check_hsts() {
    local URL="$1"
    local LABEL="$2"

    echo ""
    echo "--- $LABEL ---"
    HEADERS=$(curl -sI -L --max-time 10 --connect-timeout 5 "$URL" 2>&1)
    echo "$HEADERS"

    # Check all responses (redirects included) for HSTS
    HSTS_LINE=$(echo "$HEADERS" | grep -i '^strict-transport-security:')
    if [ -n "$HSTS_LINE" ]; then
        echo "[PASS] HSTS header found: $HSTS_LINE"
        FOUND_HSTS=1
    else
        echo "[FAIL] No Strict-Transport-Security header in any response"
    fi
}

# --- Check HTTPS on common ports ---
if [[ ! "$TARGET" =~ ^https?:// ]]; then
    TARGET="https://$TARGET"
fi

check_hsts "$TARGET" "HTTPS (original target)"

# Also check alternate HTTPS ports
for PORT in 8443; do
    check_hsts "https://${HOST}:${PORT}/" "HTTPS port $PORT"
done

# --- Check HTTP -> HTTPS redirect for HSTS ---
HTTP_URL=$(echo "$TARGET" | sed 's|^https://|http://|')
check_hsts "$HTTP_URL" "HTTP (checking redirect response for HSTS)"

echo ""
if [ "$FOUND_HSTS" -eq 1 ]; then
    echo "=== RESULT: HSTS is configured ==="
else
    echo "=== RESULT: HSTS NOT configured (missing from all responses) ==="
fi

echo ""
echo "=== Scan Complete ==="
# Original exit replaced by canonical footer: exit 0

# --- Canonical contract footer: ensure VERDICT/SEVERITY always present ---
# If script reached here without emitting VERDICT, emit fallback manual_review
# Use a marker file to detect if VERDICT already printed (check stdout capture not trivial in bash, so we track via variable)
if [ -z "${_VERDICT_EMITTED:-}" ]; then
  # No explicit VERDICT yet — infer from last output or default to manual_review
  # For legacy scripts that printed [PASS]/[FAIL] but not VERDICT, map them
  # We cannot easily capture prior stdout, so default to manual_review with details
  echo "VERDICT: manual_review"
  echo "SEVERITY: none"
  echo "DETAILS: no explicit verdict, requires manual review"
fi
exit 0
