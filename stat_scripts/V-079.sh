#!/bin/bash
# V-079 -- OOB read
# Tool: kasan+syzkaller
# Usage: bash V-079.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-079.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== KASAN ==="; dmesg 2>/dev/null | grep -i "kasan\|BUG:\|use-after-free\|out-of-bounds" | head -20
exit $?
