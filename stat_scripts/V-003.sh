#!/bin/bash
# V-003 -- Open port/unnecessary service
# Tool: nmap (multi-phase, network-safe)
# Usage: bash V-003.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-003.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

echo "=== V-003: Open port scan ==="
echo "Target: $HOST"

# --- DNS Resolution ---
echo "=== DNS Resolution ==="
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
    exit 1
fi

SCAN_TARGET="$RESOLVED_IP"

# --- Network-safe nmap options ---
# -sS: SYN stealth scan (half-open, no full TCP handshake -- low impact)
# -T3: Normal timing (avoids flooding the network)
# -Pn: Skip host discovery (treat all hosts as online, avoids ICMP flood)
# --max-rate 300: Cap packets/sec to prevent network saturation
# --max-retries 2: Retry lost probes without hammering
# --open: Show only open ports
BASE_OPTS="-sS -T3 -Pn --open --max-retries 2 --max-rate 300 --min-rate 10 --host-timeout 120s"

# --- Phase 1: Quick TCP SYN on top 100 fast ports ---
echo ""
echo "=== Phase 1: TCP quick scan (top 100 ports) ==="
timeout 90 nmap $BASE_OPTS --top-ports 100 --reason "$SCAN_TARGET" 2>&1 || true

# --- Phase 2: Full TCP 1-1024 (well-known ports) ---
echo ""
echo "=== Phase 2: TCP well-known ports (1-1024) ==="
timeout 120 nmap $BASE_OPTS -p 1-1024 -sV --version-intensity 4 "$SCAN_TARGET" 2>&1 || true

# --- Phase 3: Extended TCP 1025-10000 (registered ports) ---
echo ""
echo "=== Phase 3: TCP registered ports (1025-10000) ==="
timeout 180 nmap $BASE_OPTS -p 1025-10000 -sV --version-intensity 2 "$SCAN_TARGET" 2>&1 || true

# --- Phase 4: Default scripts on discovered open ports ---
echo ""
echo "=== Phase 4: Default scripts on open ports ==="
timeout 120 nmap $BASE_OPTS -sC -sV --version-intensity 4 "$SCAN_TARGET" 2>&1 || true

# --- Phase 5: UDP top 20 only (UDP is inherently slow & noisy) ---
echo ""
echo "=== Phase 5: UDP top 20 ports ==="
timeout 90 nmap -sU -T2 -Pn --open --max-retries 1 --max-rate 50 --top-ports 20 "$SCAN_TARGET" 2>&1 || true

echo ""
echo "=== Scan Complete ==="
exit 0
