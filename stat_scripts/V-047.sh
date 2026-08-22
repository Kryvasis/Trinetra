#!/bin/bash
# V-047 -- SSRF
# Tool: ssrf_callback_probe
# Usage: bash V-047.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-047.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-047: SSRF ==="; echo "Tool: ssrf_callback_probe"; echo "Target: $TARGET"; which ssrf_callback_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
