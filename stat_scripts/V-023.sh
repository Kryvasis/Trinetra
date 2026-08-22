#!/bin/bash
# V-023 -- IDOR
# Tool: id_enum_diff
# Usage: bash V-023.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-023.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-023: IDOR ==="; echo "Tool: id_enum_diff"; echo "Target: $TARGET"; which id_enum_diff 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
