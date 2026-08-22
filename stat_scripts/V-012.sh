#!/bin/bash
# V-012 -- Default credentials
# Tool: hydra + curl
# Usage: bash V-012.sh <target> <session_output_dir>
#
# Decision rule: grep_absent
#   PASS = no valid login with default creds
#   FAIL = valid login with default creds

TARGET="${1:?Usage: V-012.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

echo "=== V-012: Default credentials ==="
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
    echo "[-] DNS resolution failed"
    exit 1
fi

SCAN_TARGET="$RESOLVED_IP"
FOUND_CREDS=0

# --- Small targeted default credential lists ---
CREDS=(
    "admin:admin"
    "admin:password"
    "admin:123456"
    "admin:admin123"
    "admin:"
    "root:root"
    "root:toor"
    "root:password"
    "root:123456"
    "root:admin"
    "root:"
    "test:test"
    "test:password"
    "guest:guest"
    "guest:password"
    "user:user"
    "user:password"
    "oracle:oracle"
    "mysql:mysql"
    "postgres:postgres"
    "postgres:password"
    "postgres:admin"
    "sa:sa"
    "sa:password"
    "mssql:mssql"
    "ftp:ftp"
    "ftp:password"
    "anonymous:"
    "administrator:administrator"
    "administrator:password"
    "admin:Passw0rd"
    "admin:P@ssw0rd"
    "root:P@ssw0rd"
    "changeme:changeme"
)

# --- Phase 1: Detect open services ---
echo ""
echo "=== Phase 1: Service detection ==="
SAFE_OPTS="-T3 -Pn --open --max-retries 1 --max-rate 100 --host-timeout 30s"
SERVICES=$(timeout 45 nmap -sV $SAFE_OPTS -p 21,22,23,25,110,143,443,3306,5432,6379,27017,8080,8443 "$SCAN_TARGET" 2>&1 || true)
echo "$SERVICES" | grep -E "^[0-9]+/.*open" || echo "(nmap: no open services detected)"

# Curl-based fallback service detection (nmap may be filtered)
echo ""
echo "=== Phase 1b: curl-based service detection ==="
WEB_PORTS=()
for PORT in 80 443 8080 8443 8000 8888 3000 5000 9090; do
    for PROTO in https http; do
        RESP=$(timeout 5 curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 3 "${PROTO}://${HOST}:${PORT}/" 2>/dev/null)
        if [ "$RESP" != "000" ]; then
            echo "[+] ${PROTO}://${HOST}:${PORT}/ -> HTTP $RESP"
            WEB_PORTS+=("${PROTO}:${PORT}")
        fi
    done
done 2>/dev/null

if [ ${#WEB_PORTS[@]} -eq 0 ]; then
    echo "[-] No web services detected via curl"
fi

# Also detect non-web services via nmap SYN scan (no version detection, faster)
SYN_SERVICES=$(timeout 30 nmap -sS -T3 -Pn --open -p 21,22,25,110,143,3306,5432,6379,27017 "$SCAN_TARGET" 2>&1 || true)
echo "$SYN_SERVICES" | grep -E "^[0-9]+/.*open" || true

# --- Phase 2: SSH default creds (if port 22 open) ---
if echo "$SERVICES" | grep -q "22/tcp.*open" || echo "$SYN_SERVICES" | grep -q "22/tcp.*open"; then
    echo ""
    echo "=== Phase 2: SSH default credentials ==="
    for CREDS_PAIR in "${CREDS[@]}"; do
        USER=$(echo "$CREDS_PAIR" | cut -d: -f1)
        PASS=$(echo "$CREDS_PAIR" | cut -d: -f2)
        RESULT=$(timeout 10 hydra -l "$USER" -p "$PASS" -s 22 -t 1 -f -o /dev/null -q "$SCAN_TARGET" ssh 2>&1)
        if echo "$RESULT" | grep -q "\[22\]\[ssh\]"; then
            echo "[FAIL] SSH login succeeded: $USER:$PASS"
            FOUND_CREDS=1
            break
        fi
    done
    if [ "$FOUND_CREDS" -eq 0 ]; then
        echo "[PASS] No SSH default creds found"
    fi
fi

# --- Phase 3: FTP default creds (if port 21 open) ---
if echo "$SERVICES" | grep -q "21/tcp.*open" || echo "$SYN_SERVICES" | grep -q "21/tcp.*open"; then
    echo ""
    echo "=== Phase 3: FTP default credentials ==="
    for CREDS_PAIR in "${CREDS[@]}"; do
        USER=$(echo "$CREDS_PAIR" | cut -d: -f1)
        PASS=$(echo "$CREDS_PAIR" | cut -d: -f2)
        RESULT=$(timeout 10 hydra -l "$USER" -p "$PASS" -s 21 -t 1 -f -o /dev/null -q "$SCAN_TARGET" ftp 2>&1)
        if echo "$RESULT" | grep -q "\[21\]\[ftp\]"; then
            echo "[FAIL] FTP login succeeded: $USER:$PASS"
            FOUND_CREDS=1
            break
        fi
    done
    if [ "$FOUND_CREDS" -eq 0 ]; then
        echo "[PASS] No FTP default creds found"
    fi
fi

# --- Phase 4: MySQL default creds (if port 3306 open) ---
if echo "$SERVICES" | grep -q "3306/tcp.*open" || echo "$SYN_SERVICES" | grep -q "3306/tcp.*open"; then
    echo ""
    echo "=== Phase 4: MySQL default credentials ==="
    for CREDS_PAIR in "root:" "root:root" "root:password" "mysql:mysql" "admin:admin"; do
        USER=$(echo "$CREDS_PAIR" | cut -d: -f1)
        PASS=$(echo "$CREDS_PAIR" | cut -d: -f2)
        RESULT=$(timeout 10 hydra -l "$USER" -p "$PASS" -s 3306 -t 1 -f -o /dev/null -q "$SCAN_TARGET" mysql 2>&1)
        if echo "$RESULT" | grep -q "\[3306\]\[mysql\]"; then
            echo "[FAIL] MySQL login succeeded: $USER:$PASS"
            FOUND_CREDS=1
            break
        fi
    done
    if [ "$FOUND_CREDS" -eq 0 ]; then
        echo "[PASS] No MySQL default creds found"
    fi
fi

# --- Phase 5: Redis no-auth check (if port 6379 open) ---
if echo "$SERVICES" | grep -q "6379/tcp.*open" || echo "$SYN_SERVICES" | grep -q "6379/tcp.*open"; then
    echo ""
    echo "=== Phase 5: Redis no-auth check ==="
    REDIS_RESULT=$(timeout 5 bash -c "echo 'INFO server' | nc -w3 $SCAN_TARGET 6379 2>/dev/null" | head -5)
    if [ -n "$REDIS_RESULT" ] && echo "$REDIS_RESULT" | grep -qi "redis_version"; then
        echo "[FAIL] Redis accessible without authentication"
        echo "$REDIS_RESULT"
        FOUND_CREDS=1
    else
        echo "[PASS] Redis requires authentication"
    fi
fi

# --- Phase 6: HTTP basic auth / form login check ---
echo ""
echo "=== Phase 6: HTTP login pages ==="

# Login paths to check
LOGIN_PATHS=(
    "/" "/login" "/admin" "/admin/login" "/wp-login.php"
    "/signin" "/sign-in" "/auth" "/authentication"
    "/api/login" "/api/auth" "/api/v1/login"
    "/user/login" "/users/login" "/account/login"
    "/manager/html" "/console" "/dashboard"
    "/phpmyadmin" "/pma" "/adminer"
    "/.env" "/config" "/setup" "/install"
)

# Use detected web ports, fallback to defaults
if [ ${#WEB_PORTS[@]} -eq 0 ]; then
    WEB_PORTS=("https:443" "http:80" "http:8080" "https:8443")
fi

for ENTRY in "${WEB_PORTS[@]}"; do
    PROTO="${ENTRY%%:*}"
    PORT="${ENTRY##*:}"
    echo ""
    echo "--- ${PROTO} port ${PORT} ---"

    # Check each login path
    for LP in "${LOGIN_PATHS[@]}"; do
        FULL_URL="${PROTO}://${HOST}:${PORT}${LP}"
        STATUS=$(timeout 6 curl -sk -o /tmp/v012_resp -w "%{http_code}" "${FULL_URL}" 2>/dev/null)
        if [ "$STATUS" = "000" ]; then continue; fi

        # Detect login forms and auth prompts
        BODY=$(cat /tmp/v012_resp 2>/dev/null | head -c 50000)
        HINTS=""

        # Check for form-based login indicators
        if echo "$BODY" | grep -qiE '<form[^>]*(login|signin|auth|password)'; then
            HINTS="LOGIN-FORM"
        fi
        # Check for basic auth challenge
        if echo "$BODY" | grep -qiE 'WWW-Authenticate|401 Unauthorized'; then
            HINTS="${HINTS:+$HINTS, }BASIC-AUTH"
        fi
        # Check for default admin panels
        if echo "$BODY" | grep -qiE 'admin|dashboard|console|管理'; then
            HINTS="${HINTS:+$HINTS, }ADMIN-PANEL"
        fi

        if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
            echo "  [!] ${LP} -> HTTP ${STATUS} (auth required) ${HINTS}"
        elif [ "$STATUS" = "200" ] && [ -n "$HINTS" ]; then
            echo "  [!] ${LP} -> HTTP ${STATUS} ${HINTS}"
        elif [ "$STATUS" = "200" ]; then
            # Check if it's a real page or redirect
            TITLE=$(echo "$BODY" | grep -oP '(?<=<title>)[^<]+' | head -1)
            echo "  [i] ${LP} -> HTTP ${STATUS} ${TITLE:+($TITLE)}"
        fi
    done
done
rm -f /tmp/v012_resp

echo ""
if [ "$FOUND_CREDS" -eq 1 ]; then
    echo "=== RESULT: Default credentials found ==="
else
    echo "=== RESULT: No default credentials found ==="
fi

echo ""
echo "=== Scan Complete ==="
exit 0
