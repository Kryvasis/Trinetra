#!/bin/bash
# V-101 -- PAC tampering/silver ticket
# Tool: impacket_ticketer
# Usage: bash V-101.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-101.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "Silver ticket test"; echo "Requires domain credentials"
exit $?
