#!/bin/bash
# V-041 -- ESI
# Tool: esi_payload_probe
# Usage: bash V-041.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-041.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-041: ESI ==="; echo "Tool: esi_payload_probe"; echo "Target: $TARGET"; which esi_payload_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
