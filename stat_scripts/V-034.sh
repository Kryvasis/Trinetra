#!/bin/bash
# V-034 -- Reflected XSS
# Tool: xsstrike
# Usage: bash V-034.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-034.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="http://$TARGET"; fi
xsstrike -u "$TARGET" --crawl --batch 2>&1 | tail -30
exit $?
