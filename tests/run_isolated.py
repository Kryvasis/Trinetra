"""Run Python and Java suites without modifying the working repository's evidence.

Usage from WSL/Linux: .venv/bin/python tests/run_isolated.py
Requires the existing project dependencies, Java and make. No packages are installed.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile


def main():
    source = Path(__file__).resolve().parents[1]
    excluded = shutil.ignore_patterns(
        ".git", ".venv", "node_modules", "sessions", "out", "dist",
        "__pycache__", ".pytest_cache", ".env", ".env.*", "*.db", "*.db-*",
        "brain_state.json", "*.lock", "*.log",
    )
    with tempfile.TemporaryDirectory(prefix="cortex-tests-") as scratch:
        root = Path(scratch) / "repo"
        shutil.copytree(source, root, ignore=excluded, symlinks=True)
        # Fail closed rather than following links back into the live repository.
        if any(path.is_symlink() for path in root.rglob("*")):
            raise RuntimeError("Test copy contains symlinks; review/remove them from the fixture before running.")
        env = dict(os.environ)
        for key in ("TRINETRA_ROOT", "TRINETRA_BIN", "PYTHONPATH", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
            env.pop(key, None)
        env["TRINETRA_ROOT"] = str(root)
        env["TRINETRA_BIN"] = str(root / "trinetra")
        subprocess.run(["make", "test-java"], cwd=root, env=env, check=True)
        subprocess.run([sys.executable, "-m", "pytest", "bridge/tests", "-q"], cwd=root, env=env, check=True)
    print("Isolated tests complete; working repository evidence was not used or modified.")


if __name__ == "__main__":
    main()
