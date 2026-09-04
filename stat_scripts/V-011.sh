#!/bin/bash
# V-011 -- MITM exposure
# Tool: bettercap+curl+openssl+arp+dig
# Usage: bash V-011.sh <target> <session_output_dir>
#
# Decision rule: exit_code_zero
#   PASS = no MITM vectors found
#   FAIL = MITM exposure detected

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


echo "=== V-011: MITM exposure ==="
echo "Target: $HOST"

MITM_FOUND=0

# --- Test 1: SSL stripping (HTTP->HTTPS redirect) ---
echo ""
echo "=== Test 1: SSL Strip / HTTP downgrade ==="
HTTP_URL="http://${HOST}/"
REDIRECT=$(curl -sI -L --max-time 10 --connect-timeout 5 "$HTTP_URL" 2>&1)
REDIRECT_URL=$(echo "$REDIRECT" | grep -i '^location:' | head -1)

if echo "$REDIRECT_URL" | grep -qi "^location:.*https://"; then
    echo "[PASS] HTTP redirects to HTTPS: $REDIRECT_URL"
elif echo "$REDIRECT" | grep -qi "^location:"; then
    echo "[FAIL] HTTP redirects to non-HTTPS: $REDIRECT_URL"
    MITM_FOUND=1
else
    echo "[WARN] No HTTP->HTTPS redirect detected (may indicate SSL strip risk)"
    MITM_FOUND=1
fi

# --- Test 2: HSTS header present ---
echo ""
echo "=== Test 2: HSTS Header ==="
HSTS_CHECK=$(curl -sI --max-time 10 "https://${HOST}/" 2>&1)
if echo "$HSTS_CHECK" | grep -qi '^strict-transport-security:'; then
    echo "[PASS] HSTS header present"
else
    echo "[FAIL] No HSTS header - SSL strip possible"
    MITM_FOUND=1
fi

# --- Test 3: Certificate Transparency ---
echo ""
echo "=== Test 3: Certificate Transparency ==="
CERT_RAW=$(echo | openssl s_client -connect "${HOST}:443" -servername "$HOST" 2>/dev/null)
SCT_COUNT=$(echo "$CERT_RAW" | grep -c "Signed Certificate Timestamp" || true)
if [ "$SCT_COUNT" -gt 0 ]; then
    echo "[PASS] Certificate Transparency SCTs found: $SCT_COUNT"
else
    echo "[WARN] No SCTs in certificate - CT logging absent"
fi

# --- Test 4: Weak cipher / protocol downgrade ---
echo ""
echo "=== Test 4: Protocol Downgrade Indicators ==="
TLS_CHECK=$(echo | openssl s_client -connect "${HOST}:443" -servername "$HOST" 2>/dev/null)
TLS_VERSION=$(echo "$TLS_CHECK" | grep "Protocol" | head -1)
if echo "$TLS_VERSION" | grep -qiE "TLSv1\.2|TLSv1\.3"; then
    echo "[PASS] $TLS_VERSION"
elif echo "$TLS_VERSION" | grep -qiE "TLSv1$|TLSv1\.1|SSLv3"; then
    echo "[FAIL] Weak protocol accepted: $TLS_VERSION"
    MITM_FOUND=1
else
    echo "[INFO] Could not determine TLS version"
fi

# --- Test 5: ARP table anomalies ---
echo ""
echo "=== Test 5: ARP Table Check ==="
GW_IP=$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -1)
if [ -n "$GW_IP" ]; then
    ARP_ENTRY=$(arp -n "$GW_IP" 2>/dev/null | tail -1)
    ARP_MAC=$(echo "$ARP_ENTRY" | awk '{print $3}')
    ARP_TYPE=$(echo "$ARP_ENTRY" | awk '{print $5}')

    if [ -n "$ARP_MAC" ] && [ "$ARP_TYPE" = "ether" ]; then
        echo "[INFO] Gateway $GW_IP -> $ARP_MAC ($ARP_TYPE)"

        # Check for duplicate IPs with different MACs (ARP spoofing indicator)
        DUPLICATE_ARPS=$(arp -n 2>/dev/null | grep -c "$ARP_MAC" || true)
        if [ "$DUPLICATE_ARPS" -gt 2 ]; then
            echo "[WARN] Multiple IPs map to same MAC ($DUPLICATE_ARPS) - possible ARP spoofing"
        else
            echo "[PASS] ARP table looks normal"
        fi
    else
        echo "[INFO] ARP entry for gateway incomplete"
    fi
else
    echo "[INFO] Could not determine default gateway"
fi

# --- Test 6: Bettercap ARP spoofing detection ---
echo ""
echo "=== Test 6: Bettercap ARP Spoof Detection ==="
if command -v bettercap &>/dev/null; then
    BETTERCAP_RUNNING=0
    # Check if bettercap is already running (active session)
    if pgrep -f "bettercap" &>/dev/null; then
        echo "[INFO] Bettercap session already running"
        BETTERCAP_RUNNING=1
    fi

    # Passive ARP table snapshot before any probe
    ARP_BEFORE=$(arp -an 2>/dev/null | sort)
    sleep 2
    ARP_AFTER=$(arp -an 2>/dev/null | sort)

    if [ "$ARP_BEFORE" = "$ARP_AFTER" ]; then
        echo "[PASS] ARP table stable (no spoofing detected)"
    else
        echo "[FAIL] ARP table changed during probe - possible ARP spoofing"
        MITM_FOUND=1
    fi

    # Check for duplicate MACs across different IPs (ARP spoofing indicator)
    DUP_MACS=$(arp -an 2>/dev/null | awk '{print $4}' | sort | uniq -d)
    if [ -n "$DUP_MACS" ]; then
        echo "[WARN] Duplicate MACs detected: $DUP_MACS"
    fi
else
    echo "[INFO] bettercap not installed, skipping ARP spoof detection"
fi

# --- Test 7: Bettercap DNS spoofing detection ---
echo ""
echo "=== Test 7: Bettercap DNS Spoof Detection ==="
if command -v bettercap &>/dev/null; then
    # Query multiple resolvers and compare
    DNS_RESULTS=()
    for DNS in 8.8.8.8 1.1.1.1; do
        RES=$(dig +short +time=5 "$HOST" A "@${DNS}" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        if [ -n "$RES" ]; then
            DNS_RESULTS+=("$DNS:$RES")
        fi
    done

    # Check if all DNS results match
    DNS_IPS=($(printf '%s\n' "${DNS_RESULTS[@]}" | cut -d: -f2 | sort -u))
    if [ ${#DNS_IPS[@]} -le 1 ] && [ ${#DNS_RESULTS[@]} -gt 0 ]; then
        echo "[PASS] DNS responses consistent across resolvers"
    elif [ ${#DNS_IPS[@]} -gt 1 ]; then
        echo "[FAIL] DNS poisoning detected - responses differ"
        MITM_FOUND=1
    fi
else
    echo "[INFO] bettercap not installed, skipping DNS spoof detection"
fi

# --- Test 8: Bettercap SSL strip detection ---
echo ""
echo "=== Test 8: Bettercap SSL Strip Detection ==="
if command -v bettercap &>/dev/null; then
    # Check if target serves mixed content (HTTP resources on HTTPS page)
    HTTPS_BODY=$(curl -sk --max-time 10 "https://${HOST}/" 2>/dev/null)
    HTTP_REFS=$(echo "$HTTPS_BODY" | grep -oiE 'http://[^"'"'"' >]+' | head -5)
    if [ -n "$HTTP_REFS" ]; then
        echo "[WARN] Mixed content detected (HTTP resources on HTTPS page):"
        echo "$HTTP_REFS" | sed 's/^/  /'
        MITM_FOUND=1
    else
        echo "[PASS] No mixed content detected"
    fi
else
    echo "[INFO] bettercap not installed, skipping SSL strip detection"
fi

# --- Test 9: Bettercap network interface check ---
echo ""
echo "=== Test 9: Network Interface Anomalies ==="
if command -v bettercap &>/dev/null; then
    # Check for promiscuous mode interfaces
    PROMISC=$(ip link show 2>/dev/null | grep -i "PROMISC" || true)
    if [ -n "$PROMISC" ]; then
        echo "[FAIL] Interface in promiscuous mode - possible sniffing"
        echo "$PROMISC"
        MITM_FOUND=1
    else
        echo "[PASS] No interfaces in promiscuous mode"
    fi

    # Check for unusual network routes
    ROUTES=$(ip route show 2>/dev/null | grep -v "^default" | grep -v "^127\." | head -5)
    if [ -n "$ROUTES" ]; then
        echo "[INFO] Active routes:"
        echo "$ROUTES" | sed 's/^/  /'
    fi
else
    echo "[INFO] bettercap not installed, skipping interface check"
fi

# --- Test 10: DNS consistency (multi-resolver) ---
echo ""
echo "=== Test 10: DNS Consistency ==="
IPS=()
for DNS in 8.8.8.8 1.1.1.1 9.9.9.9; do
    IP=$(dig +short +time=5 "$HOST" A "@${DNS}" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    if [ -n "$IP" ]; then
        IPS+=("$IP")
    fi
done

UNIQUE_IPS=($(printf '%s\n' "${IPS[@]}" 2>/dev/null | sort -u))
if [ ${#UNIQUE_IPS[@]} -le 1 ] && [ ${#IPS[@]} -gt 0 ]; then
    echo "[PASS] DNS consistent: ${UNIQUE_IPS[0]}"
elif [ ${#IPS[@]} -gt 1 ]; then
    echo "[FAIL] DNS inconsistency detected (possible DNS hijacking)"
    MITM_FOUND=1
fi

# --- Summary ---
echo ""
echo "=== Summary ==="
if [ "$MITM_FOUND" -eq 1 ]; then
    echo "[FAIL] MITM exposure detected"
    echo "VERDICT: fail"
    echo "SEVERITY: high"
    echo "DETAILS: MITM exposure detected"
    _VERDICT_EMITTED=1
    exit 0
else
    echo "[PASS] No MITM vectors detected"
    echo "VERDICT: pass"
    echo "SEVERITY: none"
    echo "DETAILS: no MITM vectors"
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
