#!/bin/bash
# V-031 -- LDAPi
# Tool: ldap_payload_probe
# Usage: bash V-031.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-031.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "=== V-031: LDAPi ==="; echo "Tool: ldap_payload_probe"; echo "Target: $TARGET"; which ldap_payload_probe 2>/dev/null && echo "Tool found" || echo "Tool not found"
exit $?
