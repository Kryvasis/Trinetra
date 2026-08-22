#!/bin/bash
# PEN_REQ: delegates to trinetra_pen.java -- no static decision rule exists for this test
# Test: V-053 -- Business logic flaws
# Tool/Method: workflow_abuse
# Usage: bash V-053.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-053.sh <target> <session_output_dir>}"
SESSION_DIR="${2:?Usage: V-053.sh <target> <session_output_dir>}"
SESSION_NAME=$(basename "$SESSION_DIR")

PROJECT_ROOT="/home/kali/Desktop/Trinetra_v"
java -Dtrinetra.root="$PROJECT_ROOT" -cp "$PROJECT_ROOT/out" Trinetra -pen -hex run V-053 "$SESSION_NAME" "$TARGET" 2>&1

exit $?
