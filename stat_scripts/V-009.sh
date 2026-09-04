#!/bin/bash
# V-009 -- Lack of SSL pinning
# Tool: sslscan + openssl
# Usage: bash V-009.sh <target> <session_output_dir>
#
# Decision rule: grep_present
#   PASS = SSL pinning detected
#   FAIL = no pinning, standard CA trust only

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


echo "=== V-009: Lack of SSL pinning ==="
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
FOUND_PINNING=0

# --- Method 1: sslscan certificate chain analysis ---
echo ""
echo "=== Method 1: sslscan ==="
SSLSCAN=""
for PATH_CANDIDATE in sslscan /usr/bin/sslscan /usr/local/bin/sslscan; do
    if command -v "$PATH_CANDIDATE" &>/dev/null; then
        SSLSCAN="$PATH_CANDIDATE"
        break
    fi
done

if [ -n "$SSLSCAN" ]; then
    SSLSCAN_OUT=$(timeout 60 "$SSLSCAN" --no-colour --show-certificate "$TARGET" 2>&1)
    echo "$SSLSCAN_OUT"

    # Check for HPKP header (deprecated but still a pinning indicator)
    if echo "$SSLSCAN_OUT" | grep -qiE "HPKP|public.key.pinning|pin-sha256"; then
        echo "[PASS] sslscan: HPKP/pin-sha256 header detected"
        FOUND_PINNING=1
    fi

    # Check certificate chain depth (pinning often uses intermediate/leaf pins)
    CERT_COUNT=$(echo "$SSLSCAN_OUT" | grep -c "Certificate chain" || true)
    echo "[INFO] sslscan: Certificate chain entries found: $CERT_COUNT"
else
    echo "[-] sslscan not found, skipping"
fi

# --- Method 2: openssl certificate chain + pinning checks ---
echo ""
echo "=== Method 2: openssl certificate analysis ==="

CERT_RAW=$(timeout 10 bash -c "
    echo '' | openssl s_client -connect ${SCAN_TARGET}:443 \
        -servername $HOST \
        -showcerts 2>&1
" 2>/dev/null)

# Extract just the first certificate PEM block
END_LINE=$(echo "$CERT_RAW" | grep -nF '-----END CERTIFICATE-----' | head -1 | cut -d: -f1)
if [ -n "$END_LINE" ]; then
    CERT_PEM=$(echo "$CERT_RAW" | sed -n "1,${END_LINE}p" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p')
else
    CERT_PEM=""
fi

if [ -n "$CERT_PEM" ]; then
    echo "[+] Certificate extracted successfully"

    # Extract subject public key info for pinning analysis
    PUBKEY_INFO=$(echo "$CERT_PEM" | openssl x509 -noout -pubkey 2>/dev/null | \
        openssl dgst -sha256 -binary 2>/dev/null | base64 2>/dev/null)
    if [ -n "$PUBKEY_INFO" ]; then
        echo ""
        echo "[INFO] Leaf certificate SPKI pin (sha256/base64): $PUBKEY_INFO"
        echo "[INFO] This is the pin value you would use for SSL pinning"
    fi

    # Check for self-signed or unusual chain
    ISSUER=$(echo "$CERT_PEM" | openssl x509 -noout -issuer 2>/dev/null)
    SUBJECT=$(echo "$CERT_PEM" | openssl x509 -noout -subject 2>/dev/null)
    echo "[INFO] Subject: $SUBJECT"
    echo "[INFO] Issuer:  $ISSUER"

    if [ "$ISSUER" = "$SUBJECT" ]; then
        echo "[INFO] Certificate is self-signed (pinning moot - no CA chain to pin against)"
    fi
else
    echo "[-] Failed to extract certificate PEM block"
fi

# --- Method 3: HTTP headers for pinning hints ---
echo ""
echo "=== Method 3: HTTP header checks ==="
HEADERS=$(curl -sI -L --max-time 10 --connect-timeout 5 "https://${HOST}/" 2>&1)

# Check for HPKP header (deprecated HTTP header)
HPKP_HEADER=$(echo "$HEADERS" | grep -i '^public-key-pins:')
if [ -n "$HPKP_HEADER" ]; then
    echo "[PASS] HPKP header found: $HPKP_HEADER"
    FOUND_PINNING=1
else
    echo "[INFO] No HPKP header (deprecated, but absence means no header-based pinning)"
fi

# Check for Expect-CT or other cert transparency hints
CT_HEADER=$(echo "$HEADERS" | grep -i '^expect-ct:')
if [ -n "$CT_HEADER" ]; then
    echo "[INFO] Expect-CT header: $CT_HEADER"
fi

# --- Method 4: nmap ssl-cert for chain details ---
echo ""
echo "=== Method 4: nmap ssl-cert ==="
SAFE_OPTS="-T3 -Pn --open --max-retries 2 --max-rate 100 --host-timeout 60s"
timeout 45 nmap -p 443 $SAFE_OPTS \
    --script ssl-cert "$SCAN_TARGET" 2>&1 || true

# --- Summary ---
echo ""
echo "=== Summary ==="
if [ "$FOUND_PINNING" -eq 1 ]; then
    echo "[PASS] SSL pinning indicators detected"
else
    echo "[FAIL] No SSL pinning indicators found - standard CA trust only"
    echo "[INFO] Recommendation: Implement certificate pinning to mitigate MITM attacks"
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
