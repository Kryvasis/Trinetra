#!/bin/bash
# V-137 -- Concurrency/data-race detection
# Tool: kcsan+lockdep
# Usage: bash V-137.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-137.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== KCSAN ==="; dmesg 2>/dev/null | grep -i "kcsan\|data race" | head -20; echo "=== lockdep ==="; dmesg 2>/dev/null | grep -i "lockdep\|deadlock" | head -20
exit $?
