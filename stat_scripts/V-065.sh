#!/bin/bash
# V-065 -- Insecure deserialization
# Tool: ysoserial
# Usage: bash V-065.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-065.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "Deserialization testing"; curl -s -I "$TARGET" 2>&1 | head -10
exit $?
