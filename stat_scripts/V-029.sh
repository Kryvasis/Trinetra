#!/bin/bash
# V-029 -- SQLi
# Tool: sqlmap
# Usage: bash V-029.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-029.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="http://$TARGET"; fi
sqlmap -u "$TARGET" --batch --level=1 --risk=1 --timeout=10 2>&1 | tail -30
exit $?
