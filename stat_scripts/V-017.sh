#!/bin/bash
# V-017 -- Insecure password reset flow
# Tool: curl + hydra (passive analysis + active token testing)
# Usage: bash V-017.sh <target> <session_output_dir>
#
# Decision rule: exit_code_zero
#   PASS = secure password reset flow
#   FAIL = insecure password reset flow detected

TARGET="${1:?Usage: V-017.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

echo "=== V-017: Insecure password reset flow ==="
echo "Target: $HOST"

VULN_FOUND=0

# --- Helper functions ---
check_url() {
    curl -sI -o /dev/null -w "%{http_code}" --max-time 3 --connect-timeout 2 "$1" 2>/dev/null
}

fetch_page() {
    curl -sL --max-time 5 "$1" 2>/dev/null
}

fetch_headers() {
    curl -sI --max-time 5 "$1" 2>/dev/null
}

# Calculate Shannon entropy of a string
calc_entropy() {
    local str="$1"
    local len=${#str}
    if [ "$len" -eq 0 ]; then
        echo "0"
        return
    fi

    python3 -c "
import math, collections
s = '$str'
length = len(s)
if length == 0:
    print(0)
else:
    freq = collections.Counter(s)
    entropy = -sum((c/length) * math.log2(c/length) for c in freq.values())
    print(round(entropy * length, 2))
" 2>/dev/null || echo "0"
}

# --- Test 1: Discover password reset page ---
echo ""
echo "=== Test 1: Password Reset Page Discovery ==="
RESET_PATHS=(
    # Core paths (most common)
    "/forgot-password" "/reset-password" "/recover-password"
    "/forgot_password" "/password-reset" "/password_reset"
    # Auth paths
    "/auth/forgot-password" "/auth/reset-password" "/auth/forgot"
    # Account paths
    "/account/forgot-password" "/account/reset-password"
    # User paths
    "/user/forgot-password" "/user/reset-password" "/user/password"
    # API paths
    "/api/v1/forgot-password" "/api/v1/reset-password"
    "/api/forgot-password" "/api/reset-password"
    "/api/auth/forgot-password" "/api/auth/reset-password"
    # Indian gov portals
    "/employeeportal/forgot-password" "/employeeportal/reset-password"
    "/citizenportal/forgot-password" "/portal/forgot-password"
    # WordPress/CMS
    "/wp-login.php?action=lostpassword"
)

RESET_PAGE=""
RESET_URL=""

for PATH_CANDIDATE in "${RESET_PATHS[@]}"; do
    TEST_URL="https://${HOST}${PATH_CANDIDATE}"
    HTTP_CODE=$(check_url "$TEST_URL")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "303" ] || [ "$HTTP_CODE" = "307" ]; then
        RESET_PAGE=$(fetch_page "$TEST_URL")
        RESET_URL="$TEST_URL"
        echo "[+] Password reset page found: $RESET_URL"
        break
    fi
done

# Method 1b: Check main page for reset links
if [ -z "$RESET_PAGE" ]; then
    echo "[*] Scanning main page for reset links..."
    MAIN_PAGE=$(fetch_page "https://${HOST}/" 2>/dev/null)
    RESET_LINK=$(echo "$MAIN_PAGE" | grep -oiE 'href=["'"'"'][^"'"'"']*["'"'"']' | grep -iE 'forgot|reset|recover|change.*pass' | head -3)
    if [ -n "$RESET_LINK" ]; then
        echo "[+] Reset-related links found on homepage:"
        echo "$RESET_LINK" | sed 's/^/  /'
        RESET_URL_FOUND=$(echo "$RESET_LINK" | head -1 | grep -oiE 'href=["'"'"'][^"'"'"']*["'"'"']' | sed "s/href=['\"]//;s/['\"]$//")
        if [ -n "$RESET_URL_FOUND" ]; then
            if [[ "$RESET_URL_FOUND" == /* ]]; then
                RESET_URL="https://${HOST}${RESET_URL_FOUND}"
            elif [[ "$RESET_URL_FOUND" != http* ]]; then
                RESET_URL="https://${HOST}/${RESET_URL_FOUND}"
            else
                RESET_URL="$RESET_URL_FOUND"
            fi
            RESET_PAGE=$(fetch_page "$RESET_URL")
        fi
    fi
fi

# Method 1c: Check login page for reset links
if [ -z "$RESET_PAGE" ]; then
    echo "[*] Checking login pages for reset links..."
    LOGIN_PATHS=("/login" "/signin" "/auth/login" "/employeeportal/login")
    for LOGIN_PATH in "${LOGIN_PATHS[@]}"; do
        LOGIN_URL="https://${HOST}${LOGIN_PATH}"
        LOGIN_PAGE=$(fetch_page "$LOGIN_URL" 2>/dev/null) || continue
        RESET_LINK=$(echo "$LOGIN_PAGE" | grep -oiE 'href=["'"'"'][^"'"'"']*["'"'"']' | grep -iE 'forgot|reset|recover' | head -1)
        if [ -n "$RESET_LINK" ]; then
            echo "[+] Reset link found on login page: $LOGIN_PATH"
            RESET_URL_FOUND=$(echo "$RESET_LINK" | grep -oiE 'href=["'"'"'][^"'"'"']*["'"'"']' | sed "s/href=['\"]//;s/['\"]$//")
            if [[ "$RESET_URL_FOUND" == /* ]]; then
                RESET_URL="https://${HOST}${RESET_URL_FOUND}"
            elif [[ "$RESET_URL_FOUND" != http* ]]; then
                RESET_URL="https://${HOST}/${RESET_URL_FOUND}"
            else
                RESET_URL="$RESET_URL_FOUND"
            fi
            RESET_PAGE=$(fetch_page "$RESET_URL")
            break
        fi
    done
fi

# Method 1d: Check robots.txt and sitemap
if [ -z "$RESET_PAGE" ]; then
    echo "[*] Checking robots.txt and sitemap..."
    ROBOTS=$(fetch_page "https://${HOST}/robots.txt" 2>/dev/null)
    REG_IN_ROBOTS=$(echo "$ROBOTS" | grep -iE 'forgot|reset|recover|password' | head -3)
    if [ -n "$REG_IN_ROBOTS" ]; then
        echo "[+] Password-related paths in robots.txt:"
        echo "$REG_IN_ROBOTS" | sed 's/^/  /'
        ROBOT_PATH=$(echo "$REG_IN_ROBOTS" | grep -oiE '/[a-zA-Z0-9/_-]*' | head -1)
        if [ -n "$ROBOT_PATH" ]; then
            TEST_URL="https://${HOST}${ROBOT_PATH}"
            HTTP_CODE=$(check_url "$TEST_URL")
            if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
                RESET_PAGE=$(fetch_page "$TEST_URL")
                RESET_URL="$TEST_URL"
            fi
        fi
    fi
fi

# Method 1e: Check API documentation
if [ -z "$RESET_PAGE" ]; then
    echo "[*] Checking API documentation..."
    API_PATHS=("/swagger-ui.html" "/api-docs" "/openapi.json")
    for API_PATH in "${API_PATHS[@]}"; do
        API_URL="https://${HOST}${API_PATH}"
        HTTP_CODE=$(check_url "$API_URL")
        if [ "$HTTP_CODE" = "200" ]; then
            API_PAGE=$(fetch_page "$API_URL")
            RESET_ENDPOINT=$(echo "$API_PAGE" | grep -oiE '[^"]*forgot[^"]*|[^"]*reset[^"]*|[^"]*recover[^"]*' | head -3)
            if [ -n "$RESET_ENDPOINT" ]; then
                echo "[+] Password reset endpoints in API docs:"
                echo "$RESET_ENDPOINT" | sed 's/^/  /'
            fi
            break
        fi
    done
fi

if [ -z "$RESET_PAGE" ]; then
    echo "[-] No password reset page found"
    echo "[INFO] Password reset flow test skipped"
    exit 0
fi

# --- Test 2: Token entropy analysis ---
echo ""
echo "=== Test 2: Token Entropy Analysis ==="

# Check if reset page mentions tokens
TOKEN_INDICATORS=("token" "code" "key" "hash" "reset_id" "verification" "otp")
TOKEN_FOUND=0

for INDICATOR in "${TOKEN_INDICATORS[@]}"; do
    if echo "$RESET_PAGE" | grep -qiE "$INDICATOR"; then
        echo "[+] Token indicator found in page: $INDICATOR"
        TOKEN_FOUND=1
        break
    fi
done

# Check URL parameters for tokens
URL_TOKEN=$(echo "$RESET_URL" | grep -oiE '[?&](token|code|key|hash|reset_id)=[^&]*' | head -1)
if [ -n "$URL_TOKEN" ]; then
    TOKEN_VALUE=$(echo "$URL_TOKEN" | cut -d= -f2)
    TOKEN_LEN=${#TOKEN_VALUE}
    ENTROPY=$(calc_entropy "$TOKEN_VALUE")

    echo "[INFO] Token in URL: $URL_TOKEN"
    echo "[INFO] Token length: $TOKEN_LEN characters"
    echo "[INFO] Shannon entropy: $ENTROPY bits"

    if [ "$TOKEN_LEN" -lt 16 ]; then
        echo "[FAIL] Token too short ($TOKEN_LEN < 16 characters)"
        VULN_FOUND=1
    elif [ "$(echo "$ENTROPY < 50" | bc -l 2>/dev/null || echo 1)" -eq 1 ]; then
        echo "[FAIL] Token entropy too low ($ENTROPY bits)"
        VULN_FOUND=1
    else
        echo "[PASS] Token entropy acceptable"
    fi
fi

# --- Test 3: Token predictability check ---
echo ""
echo "=== Test 3: Token Predictability ==="

if [ -n "$URL_TOKEN" ]; then
    TOKEN_VALUE=$(echo "$URL_TOKEN" | cut -d= -f2)
    # Check for common predictable token patterns
    PREDICT_PATTERNS=("^[0-9]+$" "^[0-9a-f]{8}$" "^[0-9a-f]{16}$" "^[A-Za-z0-9+/]+=*$")
    for PATTERN in "${PREDICT_PATTERNS[@]}"; do
        if echo "$TOKEN_VALUE" | grep -qE "$PATTERN"; then
            echo "[WARN] Token matches predictable pattern: $PATTERN"
        fi
    done

    # Check if token is sequential or timestamp-based
    if echo "$TOKEN_VALUE" | grep -qE "^[0-9]{10,13}$"; then
        echo "[FAIL] Token appears to be timestamp-based"
        VULN_FOUND=1
    elif echo "$TOKEN_VALUE" | grep -qE "^[0-9]+$"; then
        echo "[WARN] Token is numeric only (lower entropy)"
    else
        echo "[PASS] Token appears non-sequential"
    fi
else
    # Form-based reset - check for predictable patterns in page
    echo "[INFO] Form-based reset (no token in URL)"
    if echo "$RESET_PAGE" | grep -qiE "reset.*token|token.*reset|key.*reset"; then
        echo "[INFO] Token generation appears server-side"
    else
        echo "[INFO] No visible token in reset flow"
    fi
fi

# --- Test 4: Reset link exposure in response ---
echo ""
echo "=== Test 4: Reset Link Exposure ==="

HEADERS=$(fetch_headers "$RESET_URL")
RESP_BODY=$(fetch_page "$RESET_URL")

# Check for email in response (link poisoning indicator)
if echo "$RESP_BODY" | grep -qiE "email.*sent|check.*inbox|reset.*link.*sent|link.*sent.*email"; then
    echo "[INFO] Reset link sent via email (standard flow)"
fi

# Check for token in response body
if echo "$RESP_BODY" | grep -qiE "token.*=|reset.*=|code.*="; then
    echo "[WARN] Token may be exposed in response body"
fi

# Check response headers for sensitive data
if echo "$HEADERS" | grep -qiE "x-reset-token|x-token|x-api-key"; then
    echo "[WARN] Sensitive token in response headers"
fi

# Check for verbose error messages
if echo "$RESP_BODY" | grep -qiE "user.*not.*found|email.*not.*found|account.*not.*exist"; then
    echo "[WARN] Username enumeration via error message"
fi

# Check for CORS misconfiguration
if echo "$HEADERS" | grep -qiE "access-control-allow-origin: \*"; then
    echo "[WARN] CORS misconfiguration on reset endpoint"
fi

echo "[INFO] Reset endpoint response analysis complete"

# --- Test 5: Rate limiting on reset endpoint ---
echo ""
echo "=== Test 5: Rate Limiting on Reset ==="
RATE_HEADERS=$(echo "$HEADERS" | grep -iE "rate|x-rate|retry-after|throttle|limit")
if [ -n "$RATE_HEADERS" ]; then
    echo "[PASS] Rate limiting headers on reset endpoint"
    echo "$RATE_HEADERS" | sed 's/^/  /'
else
    echo "[WARN] No rate limiting headers on reset endpoint"
fi

# --- Test 6: Check for reset token reuse ---
echo ""
echo "=== Test 6: Token Reuse Protection ==="

# Check if reset page mentions single-use tokens
REUSE_KEYWORDS=("single.use" "one.time" "expires.*after" "valid.*for" "token.*expire" "link.*expire")
REUSE_FOUND=0

for KEYWORD in "${REUSE_KEYWORDS[@]}"; do
    if echo "$RESET_PAGE" | grep -qiE "$KEYWORD"; then
        echo "[+] Token reuse protection: $KEYWORD"
        REUSE_FOUND=1
        break
    fi
done

if [ "$REUSE_FOUND" -eq 0 ]; then
    echo "[WARN] No token reuse protection indicators"
else
    echo "[PASS] Token reuse protection present"
fi

# --- Test 7: Check for password requirements on reset ---
echo ""
echo "=== Test 7: Password Requirements on Reset ==="
REQ_KEYWORDS=("must contain" "at least" "uppercase" "lowercase" "number" "special" "minimum" "complexity")
REQ_FOUND=0

for KEYWORD in "${REQ_KEYWORDS[@]}"; do
    if echo "$RESET_PAGE" | grep -qiE "$KEYWORD"; then
        echo "[+] Password requirement: $KEYWORD"
        REQ_FOUND=1
        break
    fi
done

if [ "$REQ_FOUND" -eq 0 ]; then
    echo "[WARN] No password requirements on reset page"
else
    echo "[PASS] Password requirements present"
fi

# --- Test 8: Hydra - password reset token brute-force ---
echo ""
echo "=== Test 8: Hydra Token Brute-Force Test ==="
if command -v hydra &>/dev/null; then
    # Check if reset endpoint accepts token parameter
    if [ -n "$URL_TOKEN" ]; then
        TOKEN_PARAM=$(echo "$URL_TOKEN" | cut -d= -f1 | sed 's/^[?&]//')
        echo "[INFO] Token parameter: $TOKEN_PARAM"

        # Generate small list of common token patterns for testing
        TOKEN_LIST=$(mktemp)
        cat > "$TOKEN_LIST" <<'EOF'
000000
123456
admin
test
password
token
reset
changeme
12345678
00000000
EOF

        echo "[INFO] Testing common token patterns..."

        # Extract base URL without token
        BASE_URL=$(echo "$RESET_URL" | sed -E "s/[?&]${TOKEN_PARAM}=[^&]*//")

        # Test each token
        TOKEN_VULN=0
        while IFS= read -r TEST_TOKEN; do
            TEST_URL="${BASE_URL}&${TOKEN_PARAM}=${TEST_TOKEN}"
            RESP_CODE=$(check_url "$TEST_URL")
            if [ "$RESP_CODE" = "200" ] || [ "$RESP_CODE" = "302" ]; then
                echo "[WARN] Token '$TEST_TOKEN' returned HTTP $RESP_CODE"
                TOKEN_VULN=1
            fi
        done < "$TOKEN_LIST"

        rm -f "$TOKEN_LIST"

        if [ "$TOKEN_VULN" -eq 1 ]; then
            echo "[FAIL] Common tokens accepted by reset endpoint"
            VULN_FOUND=1
        else
            echo "[PASS] Common tokens rejected"
        fi
    else
        echo "[INFO] No token parameter in URL - testing form-based reset"

        # Try to find reset form and test with hydra
        FORM_ACTION=$(echo "$RESET_PAGE" | grep -oiE 'action=["'"'"'][^"'"'"']*["'"'"']' | head -1 | sed "s/action=['\"]//;s/['\"]$//")
        EMAIL_FIELD=$(echo "$RESET_PAGE" | grep -oiE '<input[^>]*name=["'"'"'][^"'"'"']*["'"'"'][^>]*>' | grep -iE 'email|user|login' | head -1 | grep -oiE 'name=["'"'"'][^"'"'"']*["'"'"']' | sed "s/name=['\"]//;s/['\"]$//")

        if [ -n "$FORM_ACTION" ] && [ -n "$EMAIL_FIELD" ]; then
            if [[ "$FORM_ACTION" == /* ]]; then
                POST_URL="https://${HOST}${FORM_ACTION}"
            elif [[ "$FORM_ACTION" != http* ]]; then
                POST_URL="https://${HOST}/${FORM_ACTION}"
            else
                POST_URL="$FORM_ACTION"
            fi

            echo "[INFO] Reset form: POST $POST_URL ($EMAIL_FIELD)"

            # Test with common email patterns
            EMAIL_LIST=$(mktemp)
            cat > "$EMAIL_LIST" <<'EOF'
admin@target.com
test@target.com
user@target.com
info@target.com
support@target.com
EOF

            echo "[INFO] Testing common email addresses..."
            HYDRA_OUTPUT=$(timeout 60 hydra -L "$EMAIL_LIST" -p "test" \
                -t 4 -f -v \
                "$HOST" http-post-form "$POST_URL:${EMAIL_FIELD}=^USER^:F=invalid|error|not.found" \
                2>&1 | tail -10)

            echo "$HYDRA_OUTPUT"
            rm -f "$EMAIL_LIST"
        fi
    fi
else
    echo "[INFO] hydra not installed, skipping token brute-force"
fi

# --- Test 9: Check for host header injection ---
echo ""
echo "=== Test 9: Host Header Injection Test ==="

# Send reset request with manipulated Host header
MANIPULATED_RESPONSE=$(curl -s --max-time 10 -H "Host: evil.com" "https://${HOST}/forgot-password" 2>/dev/null)
if echo "$MANIPULATED_RESPONSE" | grep -qiE "evil\.com|reset.*link.*sent|token"; then
    echo "[FAIL] Host header injection possible - reset link may be poisoned"
    VULN_FOUND=1
else
    echo "[PASS] Host header injection not detected"
fi

# --- Test 10: Check for timing attack on token validation ---
echo ""
echo "=== Test 10: Timing Analysis ==="

# Measure response time for invalid vs potentially valid tokens
TIMES=()
for TEST_TOKEN in "invalid_token_xyz" "000000" "admin"; do
    START=$(date +%s%3N)
    if [ -n "$URL_TOKEN" ]; then
        TOKEN_PARAM=$(echo "$URL_TOKEN" | cut -d= -f1 | sed 's/^[?&]//')
        BASE_URL=$(echo "$RESET_URL" | sed -E "s/[?&]${TOKEN_PARAM}=[^&]*//")
        curl -s --max-time 5 "${BASE_URL}&${TOKEN_PARAM}=${TEST_TOKEN}" -o /dev/null 2>/dev/null
    else
        curl -s --max-time 5 "${RESET_URL}" -o /dev/null 2>/dev/null
    fi
    END=$(date +%s%3N)
    ELAPSED=$((END - START))
    TIMES+=("$ELAPSED")
    echo "  Token '$TEST_TOKEN': ${ELAPSED}ms"
done

# Check for significant timing differences
if [ ${#TIMES[@]} -ge 2 ]; then
    MIN_TIME=$(printf '%s\n' "${TIMES[@]}" | sort -n | head -1)
    MAX_TIME=$(printf '%s\n' "${TIMES[@]}" | sort -n | tail -1)
    DIFF=$((MAX_TIME - MIN_TIME))

    if [ "$DIFF" -gt 1000 ]; then
        echo "[FAIL] Significant timing difference (${DIFF}ms) - timing attack possible"
        VULN_FOUND=1
    elif [ "$DIFF" -gt 500 ]; then
        echo "[WARN] Moderate timing difference (${DIFF}ms) - may indicate timing leak"
    else
        echo "[PASS] Response times consistent (diff: ${DIFF}ms)"
    fi
fi

# --- Test 11: Nuclei-style checks (if available) ---
echo ""
echo "=== Test 11: Vulnerability Pattern Check ==="
if command -v nuclei &>/dev/null; then
    echo "[*] Running nuclei password reset checks..."
    NUCLEI_OUTPUT=$(timeout 60 nuclei -u "https://${HOST}" \
        -t ~/nuclei-templates/vulnerabilities/generic/password-reset-*.yaml \
        -silent 2>/dev/null || true)

    if [ -n "$NUCLEI_OUTPUT" ]; then
        echo "$NUCLEI_OUTPUT"
        VULN_FOUND=1
    else
        echo "[PASS] No nuclei templates matched"
    fi
else
    echo "[INFO] nuclei not installed, skipping template scan"

    # Manual pattern checks
    RESET_POISON_KEYWORDS=("host.header" "password.reset.poison" "reset.link" "email.poison")
    for KEYWORD in "${RESET_POISON_KEYWORDS[@]}"; do
        if echo "$RESET_PAGE" | grep -qiE "$KEYWORD"; then
            echo "[WARN] Reset poisoning indicator: $KEYWORD"
        fi
    done
fi

# --- Summary ---
echo ""
echo "=== Summary ==="
echo "Reset endpoint: $RESET_URL"
if [ "$VULN_FOUND" -eq 1 ]; then
    echo "[FAIL] Insecure password reset flow detected"
    exit 1
else
    echo "[PASS] Password reset flow appears secure"
    exit 0
fi
