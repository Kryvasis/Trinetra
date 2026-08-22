#!/bin/bash
# V-158 -- Regression testing vs known CVEs
# Tool: kernjc
# Usage: bash V-158.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-158.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

PROJECT_ROOT="/home/kali/Desktop/Trinetra_v"
KERNJC_DIR="$PROJECT_ROOT/KernJC"
KJC="$KERNJC_DIR/kjc"

echo "=== V-158: Regression testing vs known CVEs ==="; echo "Tool: kernjc"; echo "Target: $TARGET"

if [ ! -f "$KJC" ]; then
    echo "ERROR: kernjc not found at $KJC"
    exit 1
fi

if [ ! -f "$KERNJC_DIR/config.yaml" ]; then
    cp "$KERNJC_DIR/config.yaml.tmpl" "$KERNJC_DIR/config.yaml" 2>/dev/null
fi

cd "$KERNJC_DIR"

case "$TARGET" in
    CVE-*|cve-*)
        echo "Building environment for $TARGET..."
        python3 "$KJC" build "$TARGET" 2>&1
        python3 "$KJC" ps 2>&1
        ;;
    list|status)
        python3 "$KJC" ps 2>&1
        ;;
    update)
        python3 "$KJC" update 2>&1
        ;;
    *)
        if [ -n "$SESSION_DIR" ]; then
            LOGFILE="$SESSION_DIR/kernjc_scan.log"
            python3 "$KJC" query "$TARGET" 2>&1 | tee "$LOGFILE"
        else
            python3 "$KJC" -h 2>&1
        fi
        ;;
esac

exit $?
