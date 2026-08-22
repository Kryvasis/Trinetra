#!/bin/bash
# V-063 -- RFI
# Tool: rfi_payload_probe
# Usage: bash V-063.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-063.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-063: RFI ==="; echo "Tool: rfi_payload_probe"; echo "Target: $TARGET"; which rfi_payload_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
