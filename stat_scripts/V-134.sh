#!/bin/bash
# V-134 -- Driver-targeted fuzzing
# Tool: difuze (MangoFuzz)
# Usage: bash V-134.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-134.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

PROJECT_ROOT="/home/kali/Desktop/Trinetra_v"
DIFUZE_DIR="$PROJECT_ROOT/difuze"
RUNNER="$DIFUZE_DIR/MangoFuzz/runner.py"

echo "=== V-134: Driver-targeted fuzzing ==="; echo "Tool: difuze (MangoFuzz)"; echo "Target: $TARGET"

if [ ! -f "$RUNNER" ]; then
    echo "ERROR: difuze runner not found at $RUNNER"
    exit 1
fi

pip install -q -r "$DIFUZE_DIR/requirements.txt" 2>/dev/null

TARGET_ADDR=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*$||' | cut -d: -f1)
TARGET_PORT=$(echo "$TARGET" | cut -d: -f2)
TARGET_PORT=${TARGET_PORT:-2022}

DRIVERS_DIR="$DIFUZE_DIR/MangoFuzz/fuzzer/mango_types"
if [ ! -d "$DRIVERS_DIR" ]; then
    echo "WARNING: No driver definitions found, using basic fuzz mode"
    python3 "$RUNNER" -a "$TARGET_ADDR" -port "$TARGET_PORT" -seed $$ 2>&1
else
    python3 "$RUNNER" -f "$DRIVERS_DIR" -a "$TARGET_ADDR" -port "$TARGET_PORT" -seed $$ -num 100 2>&1
fi

exit $?
