#!/bin/bash
# V-052 -- ReDoS
# Tool: regex_input_probe
# Usage: bash V-052.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-052.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-052: ReDoS ==="; echo "Tool: regex_input_probe"; echo "Target: $TARGET"; which regex_input_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
