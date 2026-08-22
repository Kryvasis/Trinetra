#!/bin/bash
# V-084 -- Race condition
# Tool: kcsan
# Usage: bash V-084.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-084.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

dmesg 2>/dev/null | grep -i "kcsan\|data race" | head -20
exit $?
