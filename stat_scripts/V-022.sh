#!/bin/bash
# PEN_REQ: delegates to trinetra_pen.java -- no static decision rule exists for this test
# Test: V-022 -- Broken access control (BAC)
# Tool/Method: role_matrix_test
# Usage: bash V-022.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-022.sh <target> <session_output_dir>}"
SESSION_DIR="${2:?Usage: V-022.sh <target> <session_output_dir>}"
SESSION_NAME=$(basename "$SESSION_DIR")

PROJECT_ROOT="/home/kali/Desktop/Trinetra_v"
java -Dtrinetra.root="$PROJECT_ROOT" -cp "$PROJECT_ROOT/out" Trinetra -pen -hex run V-022 "$SESSION_NAME" "$TARGET" 2>&1

exit $?
