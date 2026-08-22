#!/bin/bash
# V-043 -- HHI (Host Header Injection)
# Tool: host_header_probe
# Usage: bash V-043.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-043.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-043: HHI (Host Header Injection) ==="; echo "Tool: host_header_probe"; echo "Target: $TARGET"; which host_header_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
