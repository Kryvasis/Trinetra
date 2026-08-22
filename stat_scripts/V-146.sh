#!/bin/bash
# V-146 -- PaX/grsecurity bypass testing
# Tool: paxtest
# Usage: bash V-146.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-146.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-146: PaX/grsecurity bypass testing ==="; echo "Tool: paxtest"; echo "Target: $TARGET"; which paxtest 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
