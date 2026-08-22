#!/bin/bash
# V-133 -- Structure-aware syscall fuzzing
# Tool: syzkaller
# Usage: bash V-133.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-133.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== kernel crash ==="; dmesg 2>/dev/null | grep -i "panic\|oops\|BUG\|crash\|syzkaller" | head -20
exit $?
