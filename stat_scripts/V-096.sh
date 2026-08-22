#!/bin/bash
# V-096 -- Pass-the-Hash
# Tool: netexec
# Usage: bash V-096.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-096.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')
netexec smb "$HOST" --shares 2>&1 | head -20
exit $?
