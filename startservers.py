#!/usr/bin/env python3
"""
One-command local startup for Agent-Hunter.

What it does:
1. Optionally installs Python dependencies from requirements.txt
2. Optionally installs dashboard dependencies (npm install)
3. Starts or reuses the FastAPI backend
4. Starts or reuses the Vite dashboard
5. Optionally starts the Telegram bot bridge
6. Waits for the selected services to become healthy

Usage:
    python startservers.py
    python startservers.py --with-telegram --skip-python-install --skip-dashboard-install
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, MutableMapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent
DASHBOARD_DIR = ROOT / "dashboard"
REQ_FILE = ROOT / "requirements.txt"


@dataclass
class ServiceSpec:
    name: str
    cmd: List[str]
    cwd: Path
    health_url: Optional[str] = None


def log(msg: str) -> None:
    print(f"[startservers] {msg}")


def load_local_env(
    root: Path = ROOT,
    environ: Optional[MutableMapping[str, str]] = None,
) -> MutableMapping[str, str]:
    env = environ if environ is not None else os.environ
    for rel_path in (".env.local", ".env"):
        path = root / rel_path
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    env.setdefault(key.strip(), value.strip().strip("\"'"))
        except OSError:
            continue
    return env


def resolve_npm_command() -> str:
    if os.name == "nt":
        npm_cmd = shutil.which("npm.cmd")
        if npm_cmd:
            return npm_cmd
    npm_bin = shutil.which("npm")
    if npm_bin:
        return npm_bin
    raise RuntimeError("Required command not found in PATH: npm (or npm.cmd on Windows)")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agent-Hunter local service launcher")
    parser.add_argument("--api-host", default="0.0.0.0", help="FastAPI bind host")
    parser.add_argument("--api-port", type=int, default=8888, help="FastAPI port")
    parser.add_argument("--ui-host", default="0.0.0.0", help="Dashboard bind host")
    parser.add_argument("--ui-port", type=int, default=5173, help="Dashboard port")
    parser.add_argument("--wait-timeout", type=int, default=120, help="Seconds to wait for HTTP services")
    parser.add_argument("--skip-python-install", action="store_true", help="Skip pip install -r requirements.txt")
    parser.add_argument("--skip-dashboard-install", action="store_true", help="Skip npm install in dashboard/")
    parser.add_argument("--with-telegram", action="store_true", help="Start Hunter Telegram bot using TELEGRAM_BOT_TOKEN")
    parser.add_argument("--telegram-poll-interval", type=float, default=1.0, help="Telegram polling backoff in seconds")
    parser.add_argument("--no-reload", action="store_true", help="Disable uvicorn auto-reload")
    parser.add_argument("--no-reuse-running", action="store_true", help="Always start new API/UI processes even if healthy services already exist")
    return parser.parse_args(list(argv) if argv is not None else None)


def api_health_url(port: int) -> str:
    return f"http://localhost:{port}/api/settings"


def ui_health_url(port: int) -> str:
    return f"http://localhost:{port}"


def build_service_specs(
    args: argparse.Namespace,
    npm_cmd: str,
    python_executable: Optional[str] = None,
) -> List[ServiceSpec]:
    python_bin = python_executable or sys.executable

    api_cmd = [
        python_bin,
        "-m",
        "uvicorn",
        "api_server:app",
        "--host",
        args.api_host,
        "--port",
        str(args.api_port),
    ]
    if not args.no_reload:
        api_cmd.append("--reload")

    specs = [
        ServiceSpec(
            name="api",
            cmd=api_cmd,
            cwd=ROOT,
            health_url=api_health_url(args.api_port),
        ),
        ServiceSpec(
            name="dashboard",
            cmd=[npm_cmd, "run", "dev", "--", "--host", args.ui_host, "--port", str(args.ui_port)],
            cwd=DASHBOARD_DIR,
            health_url=ui_health_url(args.ui_port),
        ),
    ]

    if args.with_telegram:
        telegram_cmd = [python_bin, "main.py", "--telegram-bot"]
        if args.telegram_poll_interval != 1.0:
            telegram_cmd.extend(["--telegram-poll-interval", str(args.telegram_poll_interval)])
        specs.append(
            ServiceSpec(
                name="telegram",
                cmd=telegram_cmd,
                cwd=ROOT,
                health_url=None,
            )
        )

    return specs


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


def partition_service_specs(
    specs: Sequence[ServiceSpec],
    reuse_running: bool,
    health_check: Callable[[str, int], bool] = wait_http,
) -> Tuple[List[ServiceSpec], List[ServiceSpec]]:
    reused: List[ServiceSpec] = []
    pending: List[ServiceSpec] = []
    for spec in specs:
        if reuse_running and spec.health_url and health_check(spec.health_url, timeout_sec=2):
            reused.append(spec)
        else:
            pending.append(spec)
    return reused, pending


def start_process(cmd: List[str], cwd: Optional[Path] = None) -> subprocess.Popen:
    log(f"Starting: {' '.join(cmd)}")
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


def validate_layout() -> None:
    if not REQ_FILE.exists():
        raise RuntimeError(f"Missing requirements file: {REQ_FILE}")
    if not DASHBOARD_DIR.exists():
        raise RuntimeError(f"Missing dashboard directory: {DASHBOARD_DIR}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    load_local_env(ROOT)

    active_procs: List[Tuple[str, subprocess.Popen]] = []

    try:
        os.chdir(ROOT)
        validate_layout()
        npm_cmd = resolve_npm_command()

        if args.with_telegram and not os.getenv("TELEGRAM_BOT_TOKEN", "").strip():
            raise RuntimeError("TELEGRAM_BOT_TOKEN is required when using --with-telegram")

        if not args.skip_python_install:
            run_blocking([sys.executable, "-m", "pip", "install", "-r", str(REQ_FILE)])
        else:
            log("Skipping Python dependency install.")

        if not args.skip_dashboard_install:
            run_blocking([npm_cmd, "install"], cwd=DASHBOARD_DIR)
        else:
            log("Skipping dashboard dependency install.")

        specs = build_service_specs(args, npm_cmd=npm_cmd)
        reused, pending = partition_service_specs(
            specs,
            reuse_running=not args.no_reuse_running,
        )

        for spec in reused:
            log(f"Reusing healthy {spec.name} service at {spec.health_url}")

        for spec in pending:
            proc = start_process(spec.cmd, cwd=spec.cwd)
            active_procs.append((spec.name, proc))

        for spec in specs:
            if spec.health_url:
                log(f"Waiting for {spec.name} on {spec.health_url} ...")
                if not wait_http(spec.health_url, timeout_sec=args.wait_timeout):
                    raise RuntimeError(f"{spec.name} did not become ready at {spec.health_url}")

        log("Agent-Hunter services are online.")
        log(f"Dashboard: http://localhost:{args.ui_port}")
        log(f"API:       http://localhost:{args.api_port}/docs")
        if args.with_telegram:
            log("Telegram:  enabled")
        log("Press Ctrl+C to stop managed services.")

        while True:
            for name, proc in active_procs:
                exit_code = proc.poll()
                if exit_code is not None:
                    raise RuntimeError(f"{name} exited unexpectedly with code {exit_code}")
            time.sleep(1)

    except KeyboardInterrupt:
        log("Interrupted by user.")
        return 0
    except Exception as exc:
        log(f"ERROR: {exc}")
        return 1
    finally:
        for name, proc in reversed(active_procs):
            terminate_process(proc, name)


if __name__ == "__main__":
    raise SystemExit(main())
