#!/bin/bash
# V-104 -- VLAN hopping
# Tool: yersinia
# Usage: bash V-104.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-104.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "VLAN hopping test"; yersinia dtp -attack 1 2>&1 | head -20
exit $?
