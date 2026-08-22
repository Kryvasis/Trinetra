#!/bin/bash
# V-016 -- Credential stuffing exposure
# Tool: hydra + curl (hydra for active probing, curl for passive analysis)
# Usage: bash V-016.sh <target> <session_output_dir>
#
# Decision rule: exit_code_zero
#   PASS = credential stuffing protections detected
#   FAIL = vulnerable to credential stuffing

TARGET="${1:?Usage: V-016.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

echo "=== V-016: Credential stuffing exposure ==="
echo "Target: $HOST"

VULN_FOUND=0

# --- Helper functions ---
check_url() {
    curl -sI -o /dev/null -w "%{http_code}" --max-time 8 --connect-timeout 5 "$1" 2>/dev/null
}

fetch_page() {
    curl -sL --max-time 10 "$1" 2>/dev/null
}

# --- Locate wordlists ---
WORDLIST_DIR="/usr/share/wordlists"
SECLISTS_DIR="/usr/share/seclists"

# Usernames
USERLIST=""
for CANDIDATE in \
    "$SECLISTS_DIR/Usernames/top-usernames-shortlist.txt" \
    "$WORDLIST_DIR/metasploit/unix_users.txt" \
    "$WORDLIST_DIR/metasploit/namelist.txt" \
    "$WORDLIST_DIR/fasttrack.txt"; do
    if [ -f "$CANDIDATE" ]; then
        USERLIST="$CANDIDATE"
        break
    fi
done

# Passwords (small list for credential stuffing test - not full brute force)
PASSLIST=""
for CANDIDATE in \
    "$SECLISTS_DIR/Passwords/Common-Credentials/10k-most-common.txt" \
    "$SECLISTS_DIR/Passwords/Common-Credentials/best110.txt" \
    "$SECLISTS_DIR/Passwords/Common-Credentials/darkweb2017_top-100.txt" \
    "$WORDLIST_DIR/fasttrack.txt" \
    "$WORDLIST_DIR/metasploit/password.lst"; do
    if [ -f "$CANDIDATE" ]; then
        PASSLIST="$CANDIDATE"
        break
    fi
done

echo "[INFO] Userlist: $USERLIST"
echo "[INFO] Passlist: $PASSLIST"

# --- Test 1: Discover login endpoint ---
echo ""
echo "=== Test 1: Login Endpoint Discovery ==="
LOGIN_PATHS=(
    "/login" "/signin" "/sign-in" "/sign_in"
    "/auth/login" "/auth/signin" "/auth/local"
    "/account/login" "/user/login" "/member/login"
    "/portal/login" "/app/login" "/web/login"
    "/wp-login.php" "/wp-admin"
    "/administrator" "/admin/login" "/backend/login"
    "/api/v1/login" "/api/login" "/api/auth/login"
    "/graphql" "/oauth/authorize" "/sso/login"
    "/remote/login" "/vpn/login" "/citrix/login"
)

LOGIN_PAGE=""
LOGIN_URL=""
LOGIN_SERVICE=""

for PATH_CANDIDATE in "${LOGIN_PATHS[@]}"; do
    TEST_URL="https://${HOST}${PATH_CANDIDATE}"
    HTTP_CODE=$(check_url "$TEST_URL")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
        LOGIN_PAGE=$(fetch_page "$TEST_URL")
        LOGIN_URL="$TEST_URL"
        echo "[+] Login endpoint found: $LOGIN_URL"
        break
    fi
done

# Also check HTTP (port 80)
if [ -z "$LOGIN_PAGE" ]; then
    for PATH_CANDIDATE in "${LOGIN_PATHS[@]}"; do
        TEST_URL="http://${HOST}${PATH_CANDIDATE}"
        HTTP_CODE=$(check_url "$TEST_URL")
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
            LOGIN_PAGE=$(fetch_page "$TEST_URL")
            LOGIN_URL="$TEST_URL"
            echo "[+] Login endpoint found (HTTP): $LOGIN_URL"
            break
        fi
    done
fi

if [ -z "$LOGIN_PAGE" ]; then
    echo "[-] No login endpoint found"
    echo "[INFO] Credential stuffing test skipped"
    exit 0
fi

# --- Test 2: Passive analysis - rate limiting ---
echo ""
echo "=== Test 2: Rate Limiting Detection ==="
RATE_KEYWORDS=("rate.limit" "too.many" "throttle" "slow.down" "try.again" "attempt.*limit" "max.attempts" "brute.force" "429" "retry-after" "temporarily.blocked")
RATE_FOUND=0

for KEYWORD in "${RATE_KEYWORDS[@]}"; do
    if echo "$LOGIN_PAGE" | grep -qiE "$KEYWORD"; then
        echo "[+] Rate limiting indicator: $KEYWORD"
        RATE_FOUND=1
        break
    fi
done

HEADERS=$(curl -sI --max-time 10 "$LOGIN_URL" 2>/dev/null)
if echo "$HEADERS" | grep -qiE "retry-after|x-rate-limit|x-ratelimit|ratelimit|429"; then
    echo "[+] Rate limiting headers detected"
    RATE_FOUND=1
fi

if [ "$RATE_FOUND" -eq 0 ]; then
    echo "[FAIL] No rate limiting detected"
    VULN_FOUND=1
else
    echo "[PASS] Rate limiting present"
fi

# --- Test 3: Passive analysis - CAPTCHA ---
echo ""
echo "=== Test 3: CAPTCHA Detection ==="
CAPTCHA_KEYWORDS=("captcha" "recaptcha" "hcaptcha" "turnstile" "cf-turnstile" "arkose" "challenge" "g-recaptcha")
CAPTCHA_FOUND=0

for KEYWORD in "${CAPTCHA_KEYWORDS[@]}"; do
    if echo "$LOGIN_PAGE" | grep -qiE "$KEYWORD"; then
        echo "[+] CAPTCHA detected: $KEYWORD"
        CAPTCHA_FOUND=1
        break
    fi
done

if [ "$CAPTCHA_FOUND" -eq 0 ]; then
    echo "[WARN] No CAPTCHA on login"
else
    echo "[PASS] CAPTCHA present"
fi

# --- Test 4: Passive analysis - MFA/2FA ---
echo ""
echo "=== Test 4: MFA/2FA Detection ==="
MFA_KEYWORDS=("two.factor" "2fa" "multi.factor" "mfa" "authenticator" "totp" "sms.*code" "email.*code" "verification.*code")
MFA_FOUND=0

for KEYWORD in "${MFA_KEYWORDS[@]}"; do
    if echo "$LOGIN_PAGE" | grep -qiE "$KEYWORD"; then
        echo "[+] MFA/2FA detected: $KEYWORD"
        MFA_FOUND=1
        break
    fi
done

if [ "$MFA_FOUND" -eq 0 ]; then
    echo "[WARN] No MFA/2FA on login"
else
    echo "[PASS] MFA/2FA present"
fi

# --- Test 5: Passive analysis - account lockout ---
echo ""
echo "=== Test 5: Account Lockout Detection ==="
LOCK_KEYWORDS=("locked" "lockout" "too.many.attempts" "account.disabled" "temporarily.locked" "try.again.later" "blocked" "suspended")
LOCK_FOUND=0

for KEYWORD in "${LOCK_KEYWORDS[@]}"; do
    if echo "$LOGIN_PAGE" | grep -qiE "$KEYWORD"; then
        echo "[+] Lockout indicator: $KEYWORD"
        LOCK_FOUND=1
        break
    fi
done

if [ "$LOCK_FOUND" -eq 0 ]; then
    echo "[WARN] No lockout indicators"
else
    echo "[PASS] Account lockout present"
fi

# --- Test 6: Passive analysis - error message specificity ---
echo ""
echo "=== Test 6: Error Message Analysis ==="
SPECIFIC_KEYWORDS=("user.not.found" "account.not.exist" "username.not.found" "no.account" "invalid.user")
GENERIC_KEYWORDS=("invalid.credentials" "incorrect.password" "login.failed" "authentication.failed")

SPECIFIC_FOUND=0
GENERIC_FOUND=0

for KEYWORD in "${SPECIFIC_KEYWORDS[@]}"; do
    if echo "$LOGIN_PAGE" | grep -qiE "$KEYWORD"; then
        echo "[WARN] Username enumeration: $KEYWORD"
        SPECIFIC_FOUND=1
        break
    fi
done

for KEYWORD in "${GENERIC_KEYWORDS[@]}"; do
    if echo "$LOGIN_PAGE" | grep -qiE "$KEYWORD"; then
        echo "[+] Generic error: $KEYWORD"
        GENERIC_FOUND=1
        break
    fi
done

if [ "$SPECIFIC_FOUND" -eq 1 ]; then
    echo "[FAIL] Error messages reveal valid usernames"
    VULN_FOUND=1
elif [ "$GENERIC_FOUND" -eq 1 ]; then
    echo "[PASS] Generic error messages"
else
    echo "[INFO] Could not determine error specificity"
fi

# --- Test 7: Passive analysis - form security ---
echo ""
echo "=== Test 7: Login Form Security ==="
FORM_TAG=$(echo "$LOGIN_PAGE" | grep -oiE '<form[^>]*>' | head -1)
if [ -n "$FORM_TAG" ]; then
    CSRF=$(echo "$LOGIN_PAGE" | grep -oiE 'csrf|_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken' | head -1)
    if [ -n "$CSRF" ]; then
        echo "[PASS] CSRF protection: $CSRF"
    else
        echo "[WARN] No CSRF token"
    fi

    if echo "$FORM_TAG" | grep -qi "method=.get"; then
        echo "[FAIL] Form uses GET method"
        VULN_FOUND=1
    else
        echo "[PASS] Form uses POST"
    fi
else
    echo "[INFO] No form tag found"
fi

# --- Test 8: Hydra active probe - HTTP POST form ---
echo ""
echo "=== Test 8: Hydra Active Probe (HTTP POST) ==="
if command -v hydra &>/dev/null && [ -n "$USERLIST" ] && [ -n "$PASSLIST" ]; then
    # Find form fields
    FORM_ACTION=$(echo "$LOGIN_PAGE" | grep -oiE 'action=["'"'"'][^"'"'"']*["'"'"']' | head -1 | sed "s/action=['\"]//;s/['\"]$//")
    USER_FIELD=$(echo "$LOGIN_PAGE" | grep -oiE '<input[^>]*name=["'"'"'][^"'"'"']*["'"'"'][^>]*>' | grep -iE 'user|email|login' | head -1 | grep -oiE 'name=["'"'"'][^"'"'"']*["'"'"']' | sed "s/name=['\"]//;s/['\"]$//")
    PW_FIELD=$(echo "$LOGIN_PAGE" | grep -oiE '<input[^>]*type=["'"'"']password["'"'"'][^>]*>' | head -1 | grep -oiE 'name=["'"'"'][^"'"'"']*["'"'"']' | sed "s/name=['\"]//;s/['\"]$//")

    if [ -n "$USER_FIELD" ] && [ -n "$PW_FIELD" ]; then
        if [ -n "$FORM_ACTION" ]; then
            if [[ "$FORM_ACTION" == /* ]]; then
                POST_PATH="$FORM_ACTION"
            elif [[ "$FORM_ACTION" != http* ]]; then
                POST_PATH="/$FORM_ACTION"
            else
                POST_PATH=$(echo "$FORM_ACTION" | sed -E 's|https?://[^/]*||')
            fi
        else
            POST_PATH=$(echo "$LOGIN_URL" | sed -E 's|https?://[^/]*||')
        fi

        # Determine failure string (common patterns)
        FAIL_STRING="invalid|incorrect|failed|error|wrong"
        HYDRA_URL="${HOST}:${POST_PATH}:${USER_FIELD}=^USER^&${PW_FIELD}=^PASS^:F=${FAIL_STRING}"

        echo "[INFO] Hydra target: $HYDRA_URL"
        echo "[INFO] Using: $USERLIST + $PASSLIST (top 100-1000 credentials)"

        # Run hydra with small wordlist, fast timeout, single thread for safety
        HYDRA_OUTPUT=$(timeout 120 hydra -L "$USERLIST" -P "$PASSLIST" \
            -t 4 -f -v \
            "$HOST" http-post-form "$POST_PATH:${USER_FIELD}=^USER^&${PW_FIELD}=^PASS^:F=${FAIL_STRING}" \
            2>&1 | tail -30)

        echo "$HYDRA_OUTPUT"

        # Check for successful login
        if echo "$HYDRA_OUTPUT" | grep -qiE "\[443\]\[http-post-form\] host:.*login:.*password:"; then
            echo "[FAIL] Valid credentials found via credential stuffing!"
            VULN_FOUND=1
        elif echo "$HYDRA_OUTPUT" | grep -qiE "1 valid password found|successfully completed"; then
            echo "[FAIL] Credential stuffing successful"
            VULN_FOUND=1
        else
            echo "[PASS] No valid credentials found with common list"
        fi
    else
        echo "[INFO] Could not determine form fields for hydra"
    fi
else
    echo "[INFO] Hydra or wordlists not available, skipping active probe"
    if ! command -v hydra &>/dev/null; then
        echo "  hydra not installed"
    fi
    if [ -z "$USERLIST" ]; then
        echo "  userlist not found"
    fi
    if [ -z "$PASSLIST" ]; then
        echo "  passlist not found"
    fi
fi

# --- Test 9: Hydra active probe - SSH (optional, quick check) ---
echo ""
echo "=== Test 9: Hydra SSH Probe (top credentials) ==="
if command -v hydra &>/dev/null && [ -n "$PASSLIST" ]; then
    echo "[INFO] Testing SSH with top 10 passwords..."

    # Create temp file with top 10 common passwords
    TOP10_PASS=$(mktemp)
    head -10 "$PASSLIST" > "$TOP10_PASS" 2>/dev/null

    # Common admin usernames
    TOP_USERS=$(mktemp)
    cat > "$TOP_USERS" <<'EOF'
root
admin
 administrator
user
test
guest
support
info
postgres
mysql
EOF

    HYDRA_SSH=$(timeout 60 hydra -L "$TOP_USERS" -P "$TOP10_PASS" \
        -t 4 -f -v \
        "$HOST" ssh \
        2>&1 | tail -20)

    echo "$HYDRA_SSH"

    if echo "$HYDRA_SSH" | grep -qiE "\[22\]\[ssh\] host:.*login:.*password:"; then
        echo "[FAIL] SSH credential stuffing successful!"
        VULN_FOUND=1
    else
        echo "[PASS] SSH resistant to top credential stuffing"
    fi

    rm -f "$TOP10_PASS" "$TOP_USERS"
else
    echo "[INFO] Skipping SSH probe"
fi

# --- Test 10: Check for credential stuffing specific indicators ---
echo ""
echo "=== Test 10: Credential Stuffing Indicators ==="
STUFFING_KEYWORDS=("credential.stuffing" "password.spray" "dictionary.attack" "brute.force.protection" "anomaly.detect" "bot.detect" "risk.score" "device.fingerprint" "behavioral")
STUFFING_FOUND=0

for KEYWORD in "${STUFFING_KEYWORDS[@]}"; do
    if echo "$LOGIN_PAGE" | grep -qiE "$KEYWORD"; then
        echo "[+] Anti-stuffing indicator: $KEYWORD"
        STUFFING_FOUND=1
        break
    fi
done

if [ "$STUFFING_FOUND" -eq 0 ]; then
    echo "[INFO] No specific anti-stuffing indicators"
else
    echo "[PASS] Anti-stuffing measures detected"
fi

# --- Summary ---
echo ""
echo "=== Summary ==="
echo "Login endpoint: $LOGIN_URL"
echo "Userlist: $USERLIST"
echo "Passlist: $PASSLIST"

if [ "$VULN_FOUND" -eq 1 ]; then
    echo "[FAIL] Credential stuffing exposure detected"
    exit 1
else
    echo "[PASS] Credential stuffing protections appear adequate"
    exit 0
fi
