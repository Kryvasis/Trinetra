#!/bin/bash
# V-037 -- XXE
# Tool: xxe_payload_probe
# Usage: bash V-037.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-037.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-037: XXE ==="; echo "Tool: xxe_payload_probe"; echo "Target: $TARGET"; which xxe_payload_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
