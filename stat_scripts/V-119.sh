#!/bin/bash
# V-119 -- Insecure IPC/exported component
# Tool: drozer
# Usage: bash V-119.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-119.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "Android IPC check"; drozer console connect -c "list" 2>&1 | head -20
exit $?
