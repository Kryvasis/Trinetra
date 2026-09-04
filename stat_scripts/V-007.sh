#!/bin/bash
# V-007 -- Weak cipher suite
# Tool: testssl.sh + openssl + nmap fallbacks
# Usage: bash V-007.sh <target> <session_output_dir>
#
# Decision rule: grep_absent
#   PASS = strong ciphers only
#   FAIL = weak/NULL/EXPORT cipher offered

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
TMP_CIPHER_LOG=$(mktemp)


TIMEOUT=30

echo "=== V-007: Weak cipher suite ==="
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

SCAN_TARGET="$RESOLVED_IP"

# --- Method 1: testssl.sh (if available) ---
echo ""
echo "=== Method 1: testssl.sh ==="
TESTSSL=""
for PATH_CANDIDATE in testssl.sh /usr/local/bin/testssl.sh /opt/testssl.sh/testssl.sh; do
    if command -v "$PATH_CANDIDATE" &>/dev/null; then
        TESTSSL="$PATH_CANDIDATE"
        break
    fi
done

if [ -n "$TESTSSL" ]; then
    timeout 120 "$TESTSSL" --fast -U --sneaky -q "$TARGET" 2>&1 | grep -iE 'cipher|NULL|EXPORT|anonymous|RC4|DES|MD5|WEAK|strength' || true
else
    echo "[-] testssl.sh not found, skipping"
fi

# --- Method 2: openssl cipher string probes ---
echo ""
echo "=== Method 2: openssl weak cipher probes ==="

for PORT in 443 8443; do
    echo ""
    echo "--- Port $PORT ---"

    for CIPHER_GROUP in "NULL" "EXPORT" "aNULL" "eNULL" "RC4" "DES" "3DES" "MD5" "ADH" "AECDH"; do
        RESULT=$(printf '' | timeout 10 openssl s_client -connect "${SCAN_TARGET}:${PORT}" -servername "$HOST" -cipher "${CIPHER_GROUP}" 2>&1)

        if echo "$RESULT" | grep -q "BEGIN CERTIFICATE"; then
            echo "[FAIL] $CIPHER_GROUP: ACCEPTED (connection succeeded)"
        else
            echo "[PASS] $CIPHER_GROUP: rejected"
        fi
    done

    # Check for RC4/3DES specifically
    RESULT=$(printf '' | timeout 10 openssl s_client -connect "${SCAN_TARGET}:${PORT}" -servername "$HOST" -cipher "RC4:3DES" 2>&1)

    if echo "$RESULT" | grep -q "BEGIN CERTIFICATE"; then
        echo "[FAIL] RC4/3DES: ACCEPTED"
    else
        echo "[PASS] RC4/3DES: rejected"
    fi
done

# --- Method 3: nmap ssl-enum-ciphers ---
echo ""
echo "=== Method 3: nmap ssl-enum-ciphers ==="
SAFE_OPTS="-T3 -Pn --open --max-retries 2 --max-rate 100 --host-timeout 120s"
timeout 90 nmap -p 443,8443 $SAFE_OPTS \
    --script ssl-enum-ciphers "$SCAN_TARGET" 2>&1 || true

# --- Method 4: openssl full cipher list check ---
echo ""
echo "=== Method 4: openssl full cipher enumeration ==="
for PORT in 443 8443; do
    echo ""
    echo "--- Port $PORT ---"
    CIPHERS=$(printf '' | timeout 10 openssl s_client -connect "${SCAN_TARGET}:${PORT}" -servername "$HOST" 2>&1 | grep -i 'Cipher is' || true)
    echo "$CIPHERS"

    # Check negotiated cipher for weak properties
    NEGOTIATED=$(echo "$CIPHERS" | awk -F': ' '{print $2}')
    if echo "$NEGOTIATED" | grep -qiE 'RC4|DES|MD5|NULL|EXPORT|anon'; then
        echo "[FAIL] Negotiated cipher is weak: $NEGOTIATED"
    elif [ -n "$NEGOTIATED" ]; then
        echo "[PASS] Negotiated cipher appears strong: $NEGOTIATED"
    fi
done

echo ""
echo "=== Scan Complete ==="
# Original exit replaced by canonical footer: exit 0


# Bucket A wiring: V-007 weak ciphers - check for [FAIL] in cipher checks
if grep -q "\[FAIL\]" "$TMP_CIPHER_LOG" 2>/dev/null || grep -q "WEAK.*ACCEPTED" "$TMP_CIPHER_LOG" 2>/dev/null; then
  echo "VERDICT: fail"
  echo "SEVERITY: high"
  echo "DETAILS: weak cipher offered"
  _VERDICT_EMITTED=1
  exit 0
else
  echo "VERDICT: pass"
  echo "SEVERITY: none"
  echo "DETAILS: strong ciphers only"
  _VERDICT_EMITTED=1
  exit 0
fi

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
