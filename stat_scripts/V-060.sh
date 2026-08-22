#!/bin/bash
# V-060 -- GPP password exposure
# Tool: impacket_gpp
# Usage: bash V-060.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-060.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

echo "GPP check"; smbclient -N "//$HOST/SYSVOL" -c "ls" 2>&1 | head -20
exit $?
