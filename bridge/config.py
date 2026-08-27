import os
from pathlib import Path

# Bridge configuration — lightweight, no hardcoding
# All values overridable via environment variables.

# Host/port for Flask dev server
BRIDGE_HOST = os.getenv("TRINETRA_BRIDGE_HOST", "127.0.0.1")
BRIDGE_PORT = int(os.getenv("TRINETRA_BRIDGE_PORT", "5000"))

# Path to the trinetra CLI entrypoint
# Default: <repo_root>/trinetra wrapper script (uses TRINETRA_ROOT)
_DEFAULT_ROOT = Path(__file__).resolve().parent.parent
TRINETRA_BIN = os.getenv("TRINETRA_BIN", str(_DEFAULT_ROOT / "trinetra"))

# Project root for -Dtrinetra.root (used when invoking java directly)
TRINETRA_ROOT = os.getenv("TRINETRA_ROOT", str(_DEFAULT_ROOT))

# Java classpath helper (out + lib/*)
JAVA_OUT = str(_DEFAULT_ROOT / "out")
JAVA_LIB = str(_DEFAULT_ROOT / "lib" / "*")

# Subprocess timeouts (seconds)
SUBPROCESS_TIMEOUT = int(os.getenv("TRINETRA_SUBPROCESS_TIMEOUT", "60"))

# Flask secret (dev only)
FLASK_SECRET = os.getenv("FLASK_SECRET", "trinetra-bridge-dev")
