#!/bin/bash
# V-092 -- WPAD spoofing
# Tool: responder
# Usage: bash V-092.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-092.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

echo "LLMNR/NBT-NS check"; nmap -sU -p 5353,137,138,139,3702 "$HOST" 2>&1 | head -20
exit $?
