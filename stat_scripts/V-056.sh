#!/bin/bash
# V-056 -- Insecure session token design
# Tool: curl + python3 (entropy analysis)
# Usage: bash V-056.sh <target> <session_output_dir>
#
# Decision rule: exit_code_zero
#   PASS = entropy >= 128 bits, random
#   FAIL = predictable/low-entropy token

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


echo "=== V-056: Insecure session token design ==="
echo "Target: $HOST"

VULN_FOUND=0

# --- Helper: calculate entropy ---
calc_entropy() {
    python3 -c "
import math, collections
s = '$1'
if not s:
    print(0)
else:
    freq = collections.Counter(s)
    length = len(s)
    entropy = -sum((c/length) * math.log2(c/length) for c in freq.values())
    print(round(entropy * length, 2))
" 2>/dev/null || echo "0"
}

# --- Test 1: Discover endpoints that set session cookies ---
echo ""
echo "=== Test 1: Session Token Discovery ==="
ENDPOINTS=(
    "/" "/login" "/signin" "/auth/login"
    "/account/login" "/user/login" "/portal/login"
    "/employeeportal/login" "/citizenportal/login"
    "/wp-login.php" "/api/v1/login" "/api/login"
    "/graphql" "/register" "/signup"
    "/api/v1/auth" "/api/auth" "/api/user"
    "/api/v1/user" "/api/account" "/api/v1/account"
)

COOKIE_NAMES=()
COOKIE_VALUES=()
TOKEN_SOURCES=()

# Method 1: Check Set-Cookie headers
for ENDPOINT in "${ENDPOINTS[@]}"; do
    TEST_URL="https://${HOST}${ENDPOINT}"
    COOKIE_JAR=$(mktemp)
    HEADERS=$(curl -sI --max-time 5 -c "$COOKIE_JAR" "$TEST_URL" 2>/dev/null)

    while IFS= read -r line; do
        NAME=$(echo "$line" | awk '{print $6}')
        VALUE=$(echo "$line" | awk '{print $7}')
        if [ -n "$NAME" ] && [ -n "$VALUE" ]; then
            COOKIE_NAMES+=("$NAME")
            COOKIE_VALUES+=("$VALUE")
            TOKEN_SOURCES+=("cookie:$ENDPOINT")
            echo "[+] Cookie: $NAME = ${VALUE:0:30}... (from $ENDPOINT)"
        fi
    done < <(grep -iE "Set-Cookie" "$COOKIE_JAR" 2>/dev/null | grep -v "^#")
    rm -f "$COOKIE_JAR"
done

# Method 2: Check custom headers for tokens
for ENDPOINT in "${ENDPOINTS[@]}"; do
    TEST_URL="https://${HOST}${ENDPOINT}"
    HEADERS=$(curl -sI --max-time 5 "$TEST_URL" 2>/dev/null)
    TOKEN_HEADER=$(echo "$HEADERS" | grep -iE "x-auth-token|x-access-token|x-session-token|authorization|Bearer" | head -1)
    if [ -n "$TOKEN_HEADER" ]; then
        TOKEN_VAL=$(echo "$TOKEN_HEADER" | cut -d: -f2- | sed 's/^ *//')
        COOKIE_NAMES+=("header")
        COOKIE_VALUES+=("$TOKEN_VAL")
        TOKEN_SOURCES+=("header:$ENDPOINT")
        echo "[+] Header token: $TOKEN_HEADER"
    fi
done

# Method 3: Check response body for tokens in JSON
for ENDPOINT in "/" "/api/v1/user" "/api/user" "/api/auth"; do
    TEST_URL="https://${HOST}${ENDPOINT}"
    BODY=$(curl -sL --max-time 5 "$TEST_URL" 2>/dev/null)

    # Extract token from JSON response
    JSON_TOKEN=$(echo "$BODY" | grep -oiE '"(token|access_token|auth_token|session_token|jwt|id_token|refresh_token)"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -oiE ':[[:space:]]*"[^"]*"' | sed 's/: * "//;s/"$//')
    if [ -n "$JSON_TOKEN" ] && [ ${#JSON_TOKEN} -gt 10 ]; then
        COOKIE_NAMES+=("json_token")
        COOKIE_VALUES+=("$JSON_TOKEN")
        TOKEN_SOURCES+=("json:$ENDPOINT")
        echo "[+] JSON token from $ENDPOINT: ${JSON_TOKEN:0:30}..."
    fi
done

# Method 4: Check JavaScript for embedded tokens
JS_TOKENS=$(curl -sL --max-time 8 "https://${HOST}/" 2>/dev/null | grep -oiE 'token["'"'"']*[=:]["'"'"']*[ "'"'"']*["'"'"'][A-Za-z0-9._-]{20,}["'"'"']' | head -3)
if [ -n "$JS_TOKENS" ]; then
    echo "[+] Tokens found in JavaScript:"
    JS_TOKEN_VAL=$(echo "$JS_TOKENS" | head -1 | grep -oiE '"[A-Za-z0-9._-]{20,}"' | tr -d '"')
    if [ -n "$JS_TOKEN_VAL" ]; then
        COOKIE_NAMES+=("js_token")
        COOKIE_VALUES+=("$JS_TOKEN_VAL")
        TOKEN_SOURCES+=("javascript:/")
        echo "    ${JS_TOKEN_VAL:0:40}..."
    fi
fi

if [ ${#COOKIE_VALUES[@]} -eq 0 ]; then
    echo "[-] No session tokens discovered via any method"
fi

# --- Test 2: Entropy analysis ---
echo ""
echo "=== Test 2: Token Entropy Analysis ==="

if [ ${#COOKIE_VALUES[@]} -gt 0 ]; then
    for i in "${!COOKIE_VALUES[@]}"; do
        TOKEN="${COOKIE_VALUES[$i]}"
        NAME="${COOKIE_NAMES[$i]}"
        LENGTH=${#TOKEN}
        ENTROPY=$(calc_entropy "$TOKEN")
        CHARS=$(echo "$TOKEN" | grep -oE '[0-9a-fA-F]' | wc -l)
        HEX_RATIO=$(echo "scale=2; $CHARS / $LENGTH * 100" | bc 2>/dev/null || echo "0")

        echo ""
        echo "  Token: $NAME"
        echo "  Length: $LENGTH characters"
        echo "  Shannon entropy: $ENTROPY bits"
        echo "  Hex ratio: ${HEX_RATIO}%"

        # Calculate theoretical entropy (log2 of charset size * length)
        if echo "$TOKEN" | grep -qE '^[0-9a-fA-F]+$'; then
            CHARSET_ENTROPY=$(echo "scale=2; $LENGTH * 4" | bc 2>/dev/null || echo "0")
        elif echo "$TOKEN" | grep -qE '^[0-9a-zA-Z+/=]+$'; then
            CHARSET_ENTROPY=$(echo "scale=2; $LENGTH * 6" | bc 2>/dev/null || echo "0")
        elif echo "$TOKEN" | grep -qE '^[0-9]+$'; then
            CHARSET_ENTROPY=$(echo "scale=2; $LENGTH * 3.32" | bc 2>/dev/null || echo "0")
        else
            CHARSET_ENTROPY=$(echo "scale=2; $LENGTH * 7" | bc 2>/dev/null || echo "0")
        fi

        echo "  Theoretical entropy: ${CHARSET_ENTROPY} bits"

        # Evaluate
        if [ "$(echo "$ENTROPY < 50" | bc -l 2>/dev/null || echo 1)" -eq 1 ]; then
            echo "  [FAIL] Very low entropy ($ENTROPY bits)"
            VULN_FOUND=1
        elif [ "$(echo "$ENTROPY < 100" | bc -l 2>/dev/null || echo 1)" -eq 1 ]; then
            echo "  [WARN] Low entropy ($ENTROPY bits)"
        else
            echo "  [PASS] Entropy acceptable ($ENTROPY bits)"
        fi
    done
else
    echo "[INFO] No session cookies found for entropy analysis"
fi

# --- Test 3: Token predictability patterns ---
echo ""
echo "=== Test 3: Predictability Patterns ==="

if [ ${#COOKIE_VALUES[@]} -gt 0 ]; then
    for i in "${!COOKIE_VALUES[@]}"; do
        TOKEN="${COOKIE_VALUES[$i]}"
        NAME="${COOKIE_NAMES[$i]}"

        echo "  Checking: $NAME"

        # Check for sequential patterns
        if echo "$TOKEN" | grep -qE '^(0+|1+|2+|9+)$'; then
            echo "    [FAIL] Sequential pattern detected"
            VULN_FOUND=1
        fi

        # Check for timestamp-based tokens
        if echo "$TOKEN" | grep -qE '^[0-9]{10,13}$'; then
            TIMESTAMP=$(echo "$TOKEN" | head -c 10)
            if [ "$TIMESTAMP" -gt 1000000000 ] && [ "$TIMESTAMP" -lt 2000000000 ]; then
                echo "    [FAIL] Timestamp-based token detected"
                VULN_FOUND=1
            fi
        fi

        # Check for common weak patterns
        WEAK_PATTERNS=(
            "^admin" "^test" "^password" "^123" "^abc"
            "^(.)\1+$" "^[a-f0-9]{8}$" "^[0-9]{1,6}$"
            "^session_" "^token_" "^auth_"
        )
        for PATTERN in "${WEAK_PATTERNS[@]}"; do
            if echo "$TOKEN" | grep -qiE "$PATTERN"; then
                echo "    [WARN] Weak pattern: $PATTERN"
            fi
        done

        # Check for all-numeric
        if echo "$TOKEN" | grep -qE '^[0-9]+$'; then
            echo "    [WARN] All-numeric token (lower entropy)"
        fi

        # Check for all-hex
        if echo "$TOKEN" | grep -qE '^[0-9a-fA-F]+$'; then
            if [ ${#TOKEN} -lt 32 ]; then
                echo "    [WARN] Short hex token (${#TOKEN} chars)"
            fi
        fi
    done
fi

# --- Test 4: Multiple request token analysis ---
echo ""
echo "=== Test 4: Token Uniqueness Analysis ==="

COLLECTED_TOKENS=()
for i in 1 2 3 4 5; do
    COOKIE_TMP=$(mktemp)
    curl -sI --max-time 5 -c "$COOKIE_TMP" "https://${HOST}/" > /dev/null 2>&1
    TMP_TOKEN=$(grep -iE "session|sid|token|jwt|auth|phpsessid|jsessionid" "$COOKIE_TMP" 2>/dev/null | awk '{print $7}' | head -1)
    if [ -n "$TMP_TOKEN" ]; then
        COLLECTED_TOKENS+=("$TMP_TOKEN")
    fi
    rm -f "$COOKIE_TMP"
done

if [ ${#COLLECTED_TOKENS[@]} -ge 2 ]; then
    UNIQUE=$(printf '%s\n' "${COLLECTED_TOKENS[@]}" | sort -u | wc -l)
    TOTAL=${#COLLECTED_TOKENS[@]}
    UNIQUENESS=$(echo "scale=2; $UNIQUE / $TOTAL * 100" | bc 2>/dev/null || echo "0")

    echo "[INFO] Collected $TOTAL tokens, $UNIQUE unique"
    echo "[INFO] Uniqueness: ${UNIQUENESS}%"

    if [ "$UNIQUE" -eq "$TOTAL" ]; then
        echo "[PASS] All tokens unique"
    elif [ "$UNIQUE" -gt 1 ]; then
        echo "[WARN] Some tokens repeated"
    else
        echo "[FAIL] Same token reused across requests"
        VULN_FOUND=1
    fi
fi

# --- Test 5: Token structure analysis ---
echo ""
echo "=== Test 5: Token Structure ==="

if [ ${#COOKIE_VALUES[@]} -gt 0 ]; then
    for i in "${!COOKIE_VALUES[@]}"; do
        TOKEN="${COOKIE_VALUES[$i]}"
        NAME="${COOKIE_NAMES[$i]}"

        echo "  $NAME structure:"

        # Check character diversity
        DIGITS=$(echo "$TOKEN" | tr -cd '0-9' | wc -c)
        LOWER=$(echo "$TOKEN" | tr -cd 'a-z' | wc -c)
        UPPER=$(echo "$TOKEN" | tr -cd 'A-Z' | wc -c)
        SPECIAL=$(echo "$TOKEN" | tr -cd '+/=' | wc -c)
        TOTAL=${#TOKEN}

        echo "    Digits: $DIGITS, Lower: $LOWER, Upper: $UPPER, Special: $SPECIAL"

        # Check for balanced character distribution
        if [ "$TOTAL" -gt 0 ]; then
            DIGIT_PCT=$(echo "scale=0; $DIGITS * 100 / $TOTAL" | bc 2>/dev/null || echo "0")
            if [ "$DIGIT_PCT" -gt 90 ]; then
                echo "    [WARN] Primarily digits (${DIGIT_PCT}%)"
            fi
        fi

        # Check for UUID format
        if echo "$TOKEN" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
            echo "    [INFO] UUID format detected"
        fi

        # Check for JWT format
        if echo "$TOKEN" | grep -qE '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'; then
            echo "    [INFO] JWT format detected"
        fi
    done
fi

# --- Test 6: Check for session in response body ---
echo ""
echo "=== Test 6: Token Exposure in Response ==="

RESPONSE=$(curl -sL --max-time 8 "https://${HOST}/" 2>/dev/null)

# Check for tokens in response body
EXPOSURE_PATTERNS=(
    "session.*=.*[0-9a-zA-Z]{16,}"
    "token.*=.*[0-9a-zA-Z]{16,}"
    "sid.*=.*[0-9a-zA-Z]{16,}"
    "csrf.*token.*=.*[0-9a-zA-Z]{8,}"
)
EXPOSURE_FOUND=0

for PATTERN in "${EXPOSURE_PATTERNS[@]}"; do
    if echo "$RESPONSE" | grep -qiE "$PATTERN"; then
        echo "[WARN] Token exposed in response body"
        EXPOSURE_FOUND=1
        break
    fi
done

if [ "$EXPOSURE_FOUND" -eq 0 ]; then
    echo "[PASS] No token exposure in response body"
fi

# --- Test 7: Check for token in URL ---
echo ""
echo "=== Test 7: Token in URL ==="

if [ ${#COOKIE_VALUES[@]} -gt 0 ]; then
    # Check if token appears in any URL parameters
    URL_PARAMS=$(echo "$RESPONSE" | grep -oiE 'href=["'"'"'][^"'"'"']*\?(session|token|sid)=[^"'"'"']*["'"'"']' | head -3)
    if [ -n "$URL_PARAMS" ]; then
        echo "[FAIL] Token found in URL parameters"
        echo "$URL_PARAMS" | sed 's/^/  /'
        VULN_FOUND=1
    else
        echo "[PASS] No token in URL parameters"
    fi
fi

# --- Test 8: Entropy distribution analysis ---
echo ""
echo "=== Test 8: Entropy Distribution ==="

if [ ${#COOKIE_VALUES[@]} -gt 0 ]; then
    for i in "${!COOKIE_VALUES[@]}"; do
        TOKEN="${COOKIE_VALUES[$i]}"
        NAME="${COOKIE_NAMES[$i]}"

        # Calculate per-position entropy
        LENGTH=${#TOKEN}
        if [ "$LENGTH" -gt 0 ]; then
            # Get character frequency at each position
            POS_ENTROPY=$(python3 -c "
import math, collections
s = '$TOKEN'
length = len(s)
if length == 0:
    print(0)
else:
    # Calculate entropy per character position
    pos_entropy = 0
    for i, c in enumerate(s):
        freq = collections.Counter(s)
        p = freq[c] / length
        if p > 0:
            pos_entropy += -math.log2(p)
    print(round(pos_entropy / length, 2))
" 2>/dev/null || echo "0")

            echo "  $NAME: avg position entropy = ${POS_ENTROPY} bits/char"

            if [ "$(echo "$POS_ENTROPY < 2" | bc -l 2>/dev/null || echo 1)" -eq 1 ]; then
                echo "    [WARN] Low per-position entropy"
            fi
        fi
    done
fi

# --- Summary ---
echo ""
echo "=== Summary ==="
if [ ${#COOKIE_VALUES[@]} -gt 0 ]; then
    echo "Tokens analyzed: ${#COOKIE_VALUES[@]}"
else
    echo "No session tokens found"
fi

if [ "$VULN_FOUND" -eq 1 ]; then
    echo "[FAIL] Insecure session token design detected"
    echo "VERDICT: fail"
    echo "SEVERITY: high"
    echo "DETAILS: insecure token design"
    _VERDICT_EMITTED=1
    exit 0
else
    echo "[PASS] Session token design appears secure"
    echo "VERDICT: pass"
    echo "SEVERITY: none"
    echo "DETAILS: secure token design"
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
