#!/bin/bash
# V-153 -- io_uring subsystem abuse
# Tool: syzkaller_iouring
# Usage: bash V-153.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-153.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== io_uring ==="; dmesg 2>/dev/null | grep -i "io_uring\|iouring" | head -20
exit $?
