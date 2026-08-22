#!/bin/bash
# V-103 -- ADCS abuse
# Tool: certipy
# Usage: bash V-103.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-103.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

echo "ADCS test"; certipy find -dc-ip "$HOST" 2>&1 | head -30
exit $?
