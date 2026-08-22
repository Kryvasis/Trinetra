#!/bin/bash
# V-021 -- SAML bypass/sig wrapping
# Tool: xmlsec1
# Usage: bash V-021.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-021.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-021: SAML signature wrapping ==="; echo "Tool: xmlsec1"; echo "Target: $TARGET"
which xmlsec1 2>/dev/null && echo "xmlsec1 found" || echo "xmlsec1 not found"
# Fetch SAML metadata
METADATA=$(curl -sL --max-time 10 "$TARGET/saml/metadata" 2>&1)
echo "$METADATA" | head -30
# Check for XML signature
if echo "$METADATA" | grep -qi "Signature\|ds:Signature"; then
    echo "SAML metadata contains signature — potential wrapping vector"
else
    echo "No SAML signature detected in metadata"
fi
exit $?
