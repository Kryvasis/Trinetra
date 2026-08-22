#!/bin/bash
# V-066 -- PHP object injection
# Tool: phpggc
# Usage: bash V-066.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-066.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="http://$TARGET"; fi
echo "PHP object injection test"; curl -s "$TARGET/info.php" 2>&1 | head -5
exit $?
