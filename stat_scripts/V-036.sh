#!/bin/bash
# V-036 -- DOM-based XSS
# Tool: dalfox
# Usage: bash V-036.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-036.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="http://$TARGET"; fi
echo "=== V-036: DOM-based XSS ==="; echo "Tool: dalfox"; echo "Target: $TARGET"
dalfox url "$TARGET" --mass-worker 10 --only-custom-payload --no-spinner 2>&1
exit $?
