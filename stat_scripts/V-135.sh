#!/bin/bash
# V-135 -- KASAN crash triage
# Tool: kasan
# Usage: bash V-135.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-135.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-135: KASAN crash triage ==="; echo "Tool: kasan"; echo "Target: $TARGET"; which kasan 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
