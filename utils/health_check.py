"""
Health Check Utility — runs the config-driven health-check sequence.

Usage (CLI):
    python -m utils.health_check

Usage (code):
    from utils.health_check import run_health_checks
    results = await run_health_checks()
"""
from __future__ import annotations
import asyncio
import json
import logging
import sys
from typing import Any, Dict, List

import httpx
from rich.console import Console
from rich.table import Table

from config.settings import (
    OLLAMA_URL, OLLAMA_MODEL, OLLAMA_HEALTH_TIMEOUT,
    HEALTH_CHECK_SEQUENCE, H1_USERNAME, H1_API_TOKEN,
    OLLAMA_ENDPOINTS,
)

logger = logging.getLogger(__name__)
console = Console()


async def run_health_checks(
    *,
    quiet: bool = False,
    sequence: List[Dict] | None = None,
) -> List[Dict[str, Any]]:
    """
    Execute every step in the health-check sequence and return results.

    Each result dict:
        {"step": int, "check": str, "status": "pass"|"fail"|"skip",
         "detail": str}
    """
    steps = sequence or HEALTH_CHECK_SEQUENCE
    if not steps:
        steps = _default_sequence()

    results: List[Dict[str, Any]] = []

    for step_def in sorted(steps, key=lambda s: s.get("step", 0)):
        step_num = step_def.get("step", 0)
        check_name = step_def.get("check", f"Step {step_num}")
        method = step_def.get("method", "GET").upper()
        raw_url = step_def.get("url", "/")
        expect_status = step_def.get("expect_status")
        expect_key = step_def.get("expect_key")

        # Build full URL — relative paths use Ollama base
        if raw_url.startswith("http"):
            url = raw_url
        else:
            url = f"{OLLAMA_URL.rstrip('/')}{raw_url}"

        result = {"step": step_num, "check": check_name, "status": "fail", "detail": ""}

        # Skip H1 checks if creds not configured
        if "H1" in check_name and not (H1_USERNAME and H1_API_TOKEN):
            result["status"] = "skip"
            result["detail"] = "H1 credentials not configured"
            results.append(result)
            continue

        try:
            auth = None
            if "hackerone" in url.lower():
                auth = httpx.BasicAuth(H1_USERNAME, H1_API_TOKEN)

            body = None
            if method == "POST" and "/api/chat" in raw_url:
                body = {
                    "model": OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": "Reply OK"}],
                    "stream": False,
                    "options": {"num_predict": 8},
                }

            async with httpx.AsyncClient(timeout=OLLAMA_HEALTH_TIMEOUT) as client:
                if method == "POST" and body:
                    # Use a longer timeout for chat test
                    async with httpx.AsyncClient(timeout=30) as chat_client:
                        resp = await chat_client.post(url, json=body, auth=auth)
                else:
                    resp = await client.request(method, url, auth=auth)

            # Evaluate expectations
            passed = True
            details = []

            if expect_status and resp.status_code != expect_status:
                passed = False
                details.append(f"got HTTP {resp.status_code}")

            if expect_key:
                try:
                    data = resp.json()
                    if expect_key not in data:
                        passed = False
                        details.append(f"key '{expect_key}' not in response")
                    else:
                        details.append(f"'{expect_key}' present")
                except Exception:
                    passed = False
                    details.append("non-JSON response")

            if not expect_status and not expect_key:
                passed = 200 <= resp.status_code < 300
                details.append(f"HTTP {resp.status_code}")

            result["status"] = "pass" if passed else "fail"
            result["detail"] = "; ".join(details) if details else f"HTTP {resp.status_code}"

        except httpx.ConnectError:
            result["detail"] = "Connection refused"
        except httpx.TimeoutException:
            result["detail"] = "Timeout"
        except Exception as exc:
            result["detail"] = str(exc)[:120]

        results.append(result)

    if not quiet:
        _print_results(results)

    return results


def _default_sequence() -> List[Dict]:
    """Fallback sequence if config has none."""
    return [
        {"step": 1, "check": "Ollama Running",   "url": "/",         "method": "GET", "expect_status": 200},
        {"step": 2, "check": "Model Available",   "url": "/api/tags", "method": "GET", "expect_key": "models"},
        {"step": 3, "check": "Ollama Chat Works",  "url": "/api/chat", "method": "POST", "expect_key": "message"},
        {"step": 4, "check": "H1 Auth Valid",      "url": "https://api.hackerone.com/v1/me",         "method": "GET", "expect_status": 200},
        {"step": 5, "check": "H1 Programs Readable","url": "https://api.hackerone.com/v1/me/programs", "method": "GET", "expect_status": 200},
    ]


def _print_results(results: List[Dict[str, Any]]) -> None:
    """Pretty-print health-check results with Rich."""
    table = Table(title="Health Check", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Check", min_width=22)
    table.add_column("Status", width=6)
    table.add_column("Detail")

    status_style = {"pass": "[green]PASS[/green]", "fail": "[red]FAIL[/red]", "skip": "[yellow]SKIP[/yellow]"}

    for r in results:
        table.add_row(
            str(r["step"]),
            r["check"],
            status_style.get(r["status"], r["status"]),
            r["detail"],
        )

    console.print(table)

    passed = sum(1 for r in results if r["status"] == "pass")
    total = len(results)
    skipped = sum(1 for r in results if r["status"] == "skip")
    console.print(f"\n[bold]{passed}/{total} passed[/bold]", end="")
    if skipped:
        console.print(f"  ({skipped} skipped)", end="")
    console.print()


# ── CLI entry point ───────────────────────────────────────────
if __name__ == "__main__":
    asyncio.run(run_health_checks())
