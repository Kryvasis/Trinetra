#!/usr/bin/env python3
"""One-command local backend startup for Linux/WSL, using Python 3.10+."""
import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def run(command):
    subprocess.run(command, cwd=ROOT, check=True)


def main():
    if sys.version_info < (3, 10):
        raise RuntimeError("Python 3.10+ is required.")
    if os.name != "posix":
        raise RuntimeError("Run this command in your Ubuntu/WSL terminal.")
    for tool in ("java", "javac"):
        if not shutil.which(tool):
            raise RuntimeError("Install a JDK first: sudo apt install default-jdk")
    host = os.environ.get("TRINETRA_BRIDGE_HOST", "127.0.0.1")
    port = int(os.environ.get("TRINETRA_BRIDGE_PORT", "5000"))
    with socket.socket() as probe:
        try:
            probe.bind((host, port))
        except OSError as exc:
            raise RuntimeError(f"Cannot use {host}:{port}. Stop the existing backend or set TRINETRA_BRIDGE_PORT.") from exc

    environment = ROOT / ".venv"
    python = environment / "bin" / "python"
    if not python.exists():
        print("Creating isolated backend environment...", flush=True)
        try:
            run([sys.executable, "-m", "venv", str(environment)])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Could not create environment. Install python3-venv and retry.") from exc
    requirements = ROOT / "bridge" / "requirements.txt"
    digest = hashlib.sha256(requirements.read_bytes()).hexdigest()
    stamp = environment / ".cortex-requirements.sha256"
    if not stamp.exists() or stamp.read_text().strip() != digest:
        print("Installing backend dependencies (first run or changed requirements)...", flush=True)
        run([str(python), "-m", "pip", "install", "-r", str(requirements)])
        stamp.write_text(digest + "\n")

    print("Compiling Java engine...", flush=True)
    output = ROOT / "out"
    output.mkdir(exist_ok=True)
    sources = sorted(str(path) for path in (ROOT / "src").glob("*.java"))
    run(["javac", "-Xlint:-unchecked", "-d", str(output), *sources])
    wrapper = ROOT / "trinetra"
    wrapper.chmod(wrapper.stat().st_mode | 0o100)
    print(f"Cortex API: http://{host}:{port}\nPress Ctrl+C to stop.", flush=True)
    os.chdir(ROOT)
    # Replace this process: signals and exit status belong directly to Flask.
    os.execv(str(python), [str(python), "-m", "bridge.app"])


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"Startup failed: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
