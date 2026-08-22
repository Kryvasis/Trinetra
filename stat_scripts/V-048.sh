#!/bin/bash
# V-048 -- Open redirect
# Tool: redirect_param_probe
# Usage: bash V-048.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-048.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-048: Open redirect ==="; echo "Tool: redirect_param_probe"; echo "Target: $TARGET"; which redirect_param_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
