#!/bin/bash
# V-064 -- Unrestricted file upload
# Tool: upload_bypass_probe
# Usage: bash V-064.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-064.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-064: Unrestricted file upload ==="; echo "Tool: upload_bypass_probe"; echo "Target: $TARGET"; which upload_bypass_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
