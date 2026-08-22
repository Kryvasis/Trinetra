#!/bin/bash
# V-033 -- CMDi/OSCi
# Tool: commix
# Usage: bash V-033.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-033.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="http://$TARGET"; fi
commix -u "$TARGET" --batch 2>&1 | tail -30
exit $?
