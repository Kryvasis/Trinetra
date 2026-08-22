#!/bin/bash
# V-011 -- MITM exposure
# Tool: bettercap+curl+openssl+arp+dig
# Usage: bash V-011.sh <target> <session_output_dir>
#
# Decision rule: exit_code_zero
#   PASS = no MITM vectors found
#   FAIL = MITM exposure detected

TARGET="${1:?Usage: V-011.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

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
    exit 1
else
    echo "[PASS] No MITM vectors detected"
    exit 0
fi
