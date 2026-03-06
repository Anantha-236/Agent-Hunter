#!/usr/bin/env python3
"""
One-command local startup for Agent-Hunter.

What it does:
1. Installs Python dependencies from requirements.txt
2. Installs dashboard dependencies (npm install)
3. Starts FastAPI backend on http://localhost:8888
4. Starts Vite dashboard on http://localhost:5173
5. Waits for both services to become healthy

Usage:
    python startservers.py
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent
DASHBOARD_DIR = ROOT / "dashboard"
REQ_FILE = ROOT / "requirements.txt"

API_URL = "http://localhost:8888/api/settings"
UI_URL = "http://localhost:5173"


def log(msg: str) -> None:
    print(f"[startservers] {msg}")


def ensure_command(name: str) -> None:
    if shutil.which(name):
        return
    raise RuntimeError(f"Required command not found in PATH: {name}")


def resolve_npm_command() -> str:
    """Return the npm executable name/path that works on the current OS."""
    if os.name == "nt":
        npm_cmd = shutil.which("npm.cmd")
        if npm_cmd:
            return npm_cmd
    npm_bin = shutil.which("npm")
    if npm_bin:
        return npm_bin
    raise RuntimeError("Required command not found in PATH: npm (or npm.cmd on Windows)")


def run_blocking(cmd: List[str], cwd: Optional[Path] = None) -> None:
    log(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True)


def wait_http(url: str, timeout_sec: int = 120) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if 200 <= resp.status < 500:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(1)
    return False


def start_process(cmd: List[str], cwd: Optional[Path] = None) -> subprocess.Popen:
    log(f"Starting: {' '.join(cmd)}")
    # Keep child output visible in this terminal.
    return subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=None,
        stderr=None,
    )


def terminate_process(proc: Optional[subprocess.Popen], name: str) -> None:
    if proc is None or proc.poll() is not None:
        return
    log(f"Stopping {name}...")
    try:
        proc.terminate()
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()


def main() -> int:
    api_proc: Optional[subprocess.Popen] = None
    ui_proc: Optional[subprocess.Popen] = None

    try:
        os.chdir(ROOT)
        npm_cmd = resolve_npm_command()

        if not REQ_FILE.exists():
            raise RuntimeError(f"Missing requirements file: {REQ_FILE}")
        if not DASHBOARD_DIR.exists():
            raise RuntimeError(f"Missing dashboard directory: {DASHBOARD_DIR}")

        # 1) Python deps
        run_blocking([sys.executable, "-m", "pip", "install", "-r", str(REQ_FILE)])

        # 2) Dashboard deps
        run_blocking([npm_cmd, "install"], cwd=DASHBOARD_DIR)

        # 3) Start backend
        api_proc = start_process(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "api_server:app",
                "--host",
                "0.0.0.0",
                "--port",
                "8888",
                "--reload",
            ],
            cwd=ROOT,
        )

        # 4) Start frontend
        ui_proc = start_process(
            [npm_cmd, "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"],
            cwd=DASHBOARD_DIR,
        )

        # 5) Health checks
        log("Waiting for API server...")
        if not wait_http(API_URL, timeout_sec=120):
            raise RuntimeError("API server did not become ready on :8888")

        log("Waiting for dashboard...")
        if not wait_http(UI_URL, timeout_sec=120):
            raise RuntimeError("Dashboard did not become ready on :5173")

        log("Agent-Hunter is online.")
        log("Dashboard: http://localhost:5173")
        log("API:       http://localhost:8888/docs")
        log("Press Ctrl+C to stop both services.")

        while True:
            # Exit if either process crashes.
            if api_proc.poll() is not None:
                raise RuntimeError("API server exited unexpectedly.")
            if ui_proc.poll() is not None:
                raise RuntimeError("Dashboard server exited unexpectedly.")
            time.sleep(1)

    except KeyboardInterrupt:
        log("Interrupted by user.")
        return 0
    except Exception as exc:
        log(f"ERROR: {exc}")
        return 1
    finally:
        terminate_process(ui_proc, "dashboard")
        terminate_process(api_proc, "api")


if __name__ == "__main__":
    # Ensure child processes are cleaned on parent shutdown.
    atexit.register(lambda: None)
    raise SystemExit(main())
