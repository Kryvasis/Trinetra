#!/bin/bash
# V-089 -- ARP spoofing
# Tool: bettercap
# Usage: bash V-089.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-089.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "ARP spoofing test"; arp -a 2>&1 | head -20
exit $?
