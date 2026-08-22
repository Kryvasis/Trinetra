#!/bin/bash
# V-080 -- OOB write
# Tool: kasan+syzkaller
# Usage: bash V-080.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-080.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== KASAN ==="; dmesg 2>/dev/null | grep -i "kasan\|BUG:\|use-after-free\|out-of-bounds" | head -20
exit $?
