#!/bin/bash
# V-136 -- UBSAN detection
# Tool: ubsan
# Usage: bash V-136.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-136.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-136: UBSAN detection ==="; echo "Tool: ubsan"; echo "Target: $TARGET"; which ubsan 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
