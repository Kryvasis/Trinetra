#!/bin/bash
# V-130 -- Sensitive data exposure via model output
# Tool: garak
# Usage: bash V-130.sh <target> <session_output_dir>

TARGET="${1:?Usage: V-130.sh <target> <session_output_dir>}"
SESSION_DIR="${2:-}"

echo "LLM probe"; garak --model_type openai --model_name "$TARGET" 2>&1 | head -30
exit $?
