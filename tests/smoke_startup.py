"""Exercise first-run setup, warm startup, health, and occupied-port handling."""
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request

root = Path(__file__).resolve().parents[1]
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
env = dict(os.environ, TRINETRA_BRIDGE_PORT=str(port), TRINETRA_BRIDGE_HOST='127.0.0.1')
for attempt in range(2):
    with tempfile.TemporaryFile(mode='w+') as log:
        process = subprocess.Popen(['make', 'start'], cwd=root, env=env,
                                   stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(log.read())
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=1) as response:
                        assert response.status == 200
                    break
                except OSError:
                    time.sleep(.25)
            else:
                raise AssertionError('Backend did not become ready')
            blocked = subprocess.run(['python3', 'start_backend.py'], cwd=root, env=env,
                                     capture_output=True, text=True, timeout=10)
            assert blocked.returncode == 1 and 'Cannot use' in blocked.stderr
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
            process.wait(timeout=10)
        log.seek(0)
        output = log.read()
        if attempt == 1:
            assert 'Installing backend dependencies' not in output
        print(f'Run {attempt + 1}: health, port-conflict rejection, Ctrl+C shutdown passed')
