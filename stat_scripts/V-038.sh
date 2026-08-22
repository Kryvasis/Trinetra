#!/bin/bash
# V-038 -- SSTI
# Tool: tplmap
# Usage: bash V-038.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-038.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="http://$TARGET"; fi
tplmap -u "$TARGET" --batch 2>&1 | tail -30
exit $?
