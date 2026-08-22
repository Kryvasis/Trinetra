#!/bin/bash
# V-019 -- Weak JWT validation/sig bypass
# Tool: jwt_tool
# Usage: bash V-019.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-019.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "JWT tool requires captured token"; curl -s "$TARGET/.well-known/openid-configuration" 2>&1 | head -20
exit $?
