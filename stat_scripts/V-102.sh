#!/bin/bash
# V-102 -- Golden ticket forgery
# Tool: impacket_ticketer
# Usage: bash V-102.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-102.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "Golden ticket test"; echo "Requires krbtgt hash"
exit $?
