#!/bin/bash
# V-049 -- HRS/desync
# Tool: smuggler
# Usage: bash V-049.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-049.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | sed 's|:.*$||')
PORT=$(echo "$TARGET" | grep -oP ":\K[0-9]+" || echo "80")
python3 -c "import socket; s=socket.socket(); s.settimeout(10); s.connect(("" + "$HOST" + "", int("" + "$PORT" + ""))); print(s.recv(4096).decode(errors="replace"))" 2>&1 | head -20
exit $?
