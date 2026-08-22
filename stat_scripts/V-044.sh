#!/bin/bash
# V-044 -- HPP
# Tool: dup_param_probe
# Usage: bash V-044.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-044.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-044: HPP ==="; echo "Tool: dup_param_probe"; echo "Target: $TARGET"; which dup_param_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
