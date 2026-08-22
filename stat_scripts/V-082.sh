#!/bin/bash
# V-082 -- Memory leak
# Tool: valgrind
# Usage: bash V-082.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-082.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

if [ -f "$TARGET" ]; then valgrind --leak-check=full "$TARGET" 2>&1 | tail -30; else echo "No binary at $TARGET"; fi
exit $?
