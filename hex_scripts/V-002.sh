#!/usr/bin/env bash
# V-002.sh — Sub-domain enumeration
# Category: Discovery, Web and API
# Tool: subfinder
# Usage: bash V-002.sh <SESSION> <TARGET>
# Place at: ~/Desktop/trinetra/scripts/hexstrike/V-002.sh
set -euo pipefail

SESSION="${1:?ERROR: usage: bash V-002.sh <session> <target>}"
TARGET="${2:?ERROR: usage: bash V-002.sh <session> <target>}"

# ROOT = ~/Desktop/trinetra  (two levels up from scripts/hexstrike/)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION_DIR="$ROOT/sessions/$SESSION"
SESSION_FILE="$SESSION_DIR/$SESSION.json"
HEX="http://127.0.0.1:8888/api/command"
CMD="subfinder -d $TARGET -silent -o /dev/stdout"

echo "[hex] V-002: Sub-domain enumeration → $TARGET"

# Build JSON payload safely
PAYLOAD=$(python3 -c "
import json, sys
cmd = sys.argv[1].replace('\$TARGET', sys.argv[2])
print(json.dumps({'command': cmd}))" "$CMD" "$TARGET")

START_MS=$(date +%s%3N)

RAW=$(curl -sf -X POST "$HEX" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" 2>/dev/null) || RAW=""

END_MS=$(date +%s%3N)
ELAPSED=$(python3 -c "print(round(($END_MS - $START_MS) / 1000.0, 3))")

if [[ -z "$RAW" ]]; then
    STDOUT="HexStrike server not reachable or command timed out"
    RC=1; SUCCESS=false; TIMED_OUT=false
else
    STDOUT=$(echo "$RAW"    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('stdout',''))" 2>/dev/null || echo "")
    STDERR=$(echo "$RAW"    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('stderr',''))" 2>/dev/null || echo "")
    RC=$(echo "$RAW"        | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('return_code',1))" 2>/dev/null || echo 1)
    SUCCESS=$(echo "$RAW"   | python3 -c "import json,sys; d=json.load(sys.stdin); print(str(d.get('success',False)).lower())" 2>/dev/null || echo false)
    TIMED_OUT=$(echo "$RAW" | python3 -c "import json,sys; d=json.load(sys.stdin); print(str(d.get('timed_out',False)).lower())" 2>/dev/null || echo false)
fi

mkdir -p "$SESSION_DIR"

# Append entry to session JSON atomically
python3 - \
    "$SESSION_FILE" "$SESSION" "$TARGET" \
    "V-002" "Sub-domain enumeration" "Discovery, Web and API" "subfinder" \
    "$RC" "$SUCCESS" "$ELAPSED" "$TIMED_OUT" \
    "$STDOUT" "${STDERR:-}" \
    <<'PY'
import json, sys, datetime, pathlib, os

sf, session, target, code, name, category, tool, rc, success, elapsed, timed_out, stdout, stderr = sys.argv[1:14]

p = pathlib.Path(sf)
data = {}
findings = []
if p.exists() and p.stat().st_size > 0:
    try:
        data = json.loads(p.read_text())
        if isinstance(data, dict):
            findings = data.get("findings", [])
        elif isinstance(data, list):
            findings = data
    except json.JSONDecodeError:
        findings = []

entry = {
    "timestamp":      datetime.datetime.utcnow().isoformat() + "Z",
    "session":        session,
    "source":         "hex",
    "test_code":      code,
    "test_name":      name,
    "category":       category,
    "tool":           tool,
    "target":         target,
    "return_code":    int(rc) if rc.isdigit() else 1,
    "success":        success == "true",
    "execution_time": float(elapsed),
    "timed_out":      timed_out == "true",
    "stdout":         stdout,
    "stderr":         stderr
}

findings.append(entry)
data["findings"] = findings

tmp = str(p) + ".tmp"
with open(tmp, "w") as f:
    json.dump(data if data else findings, f, indent=2, ensure_ascii=False)
os.replace(tmp, str(p))

print(f"[hex] ✓ {code} appended to {sf}")
PY
