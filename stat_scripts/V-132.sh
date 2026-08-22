#!/bin/bash
# V-132 -- Coverage-guided fuzzing
# Tool: syzkaller
# Usage: bash V-132.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-132.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== kernel crash ==="; dmesg 2>/dev/null | grep -i "panic\|oops\|BUG\|crash\|syzkaller" | head -20
exit $?
