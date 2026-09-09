#!/usr/bin/env python3
"""One-command local Cortex startup for Linux/WSL, using Python 3.10+."""
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
    for tool in ("java", "javac", "node", "npm"):
        resolved = shutil.which(tool)
        package = "default-jdk" if tool in ("java", "javac") else "nodejs npm"
        if not resolved:
            raise RuntimeError(f"Missing {tool}. Install it inside WSL first: sudo apt install {package}")
        # Windows npm inherited through WSL interop runs lifecycle scripts from a
        # UNC working directory and fails in cmd.exe. Require a native WSL tool.
        if tool in ("node", "npm") and Path(resolved).as_posix().startswith("/mnt/"):
            raise RuntimeError(
                "Windows Node/npm was found, but Cortex is running in WSL. "
                "Install Node.js 20+ inside WSL, then reopen the terminal."
            )
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
    frontend = ROOT / "frontend"
    frontend_stamp = frontend / "node_modules" / ".cortex-package-lock.sha256"
    lock_digest = hashlib.sha256((frontend / "package-lock.json").read_bytes()).hexdigest()
    if not frontend_stamp.exists() or frontend_stamp.read_text().strip() != lock_digest:
        print("Installing frontend dependencies (first run or changed lockfile)...", flush=True)
        subprocess.run(["npm", "ci"], cwd=frontend, check=True)
        frontend_stamp.parent.mkdir(parents=True, exist_ok=True)
        frontend_stamp.write_text(lock_digest + "\n")
    print("Building Cortex workspace...", flush=True)
    subprocess.run(["npm", "run", "build"], cwd=frontend, check=True)
    wrapper = ROOT / "trinetra"
    wrapper.chmod(wrapper.stat().st_mode | 0o100)
    print(f"Cortex workspace: http://{host}:{port}\nPress Ctrl+C to stop.", flush=True)
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
