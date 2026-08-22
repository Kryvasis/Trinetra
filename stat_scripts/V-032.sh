#!/bin/bash
# V-032 -- XPATHi
# Tool: xpath_payload_probe
# Usage: bash V-032.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-032.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-032: XPATHi ==="; echo "Tool: xpath_payload_probe"; echo "Target: $TARGET"; which xpath_payload_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
