#!/bin/bash
# V-093 -- SMB relay
# Tool: netexec+ntlmrelayx
# Usage: bash V-093.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-093.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')
nmap -p 445,139 --script smb-security-mode "$HOST" 2>&1 | head -20
exit $?
