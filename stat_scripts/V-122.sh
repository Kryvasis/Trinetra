#!/bin/bash
# V-122 -- Insecure local storage in client app
# Tool: objection
# Usage: bash V-122.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-122.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "Mobile security"; objection -g "$TARGET" explore 2>&1 | head -20
exit $?
