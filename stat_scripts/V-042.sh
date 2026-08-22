#!/bin/bash
# V-042 -- XSLT injection
# Tool: xslt_payload_probe
# Usage: bash V-042.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-042.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-042: XSLT injection ==="; echo "Tool: xslt_payload_probe"; echo "Target: $TARGET"; which xslt_payload_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
