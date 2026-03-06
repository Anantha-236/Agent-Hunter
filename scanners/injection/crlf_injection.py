"""CRLF Injection Scanner — detects HTTP header injection vulnerabilities."""
from __future__ import annotations
import asyncio, re
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

CRLF_PAYLOADS = [
    "%0d%0aInjected-Header:BugBountyAgent",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%0D%0ASet-Cookie:crlf=injected",
    "\r\nX-Injected: true",
    "%E5%98%8A%E5%98%8DInjected:true",               # Unicode CRLF
    "%0d%0aLocation:%20https://evil.com",              # Redirect via CRLF
    "%23%0d%0aHeader-Inject:true",                     # Hash + CRLF
    "%%0d0d%%0a0aInjected:true",                       # Double encoding
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200",  # Response splitting
]

CRLF_CANARY = "BugBountyAgent"


class CRLFInjectionScanner(BaseScanner):
    name = "crlf_injection"
    description = "Detects CRLF injection / HTTP response splitting"
    tags = ["injection", "crlf", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        tasks = []
        for url, params in state.target.discovered_params.items():
            for param in params:
                for payload in CRLF_PAYLOADS:
                    tasks.append(self._test(url, param, payload))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, Finding)]

    async def _test(self, url, param, payload):
        resp, raw_req = await self.test_payload(url, "GET", param, payload, inject_in="query")
        if not resp:
            return None

        # Check if injected header appears in response headers
        headers_str = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())

        if CRLF_CANARY.lower() in headers_str.lower():
            # Determine severity based on what was injected
            if "Set-Cookie" in headers_str or "Location" in headers_str:
                severity = Severity.HIGH
                vuln_sub = "header_injection_critical"
            else:
                severity = Severity.MEDIUM
                vuln_sub = "header_injection"

            return self.make_finding(
                title=f"CRLF Injection in '{param}'",
                vuln_type=vuln_sub, severity=severity,
                url=url, parameter=param, payload=payload,
                evidence=f"Injected header found in response: {headers_str[:200]}",
                request=raw_req, response=resp.text[:300],
                cwe_id="CWE-113",
                owasp_category="A03:2021 - Injection",
                description=f"Parameter '{param}' allows CRLF injection into HTTP response headers. "
                            f"Can lead to session fixation, XSS via response splitting, or cache poisoning.",
                poc_steps=[
                    f"1. Navigate to {url}",
                    f"2. Set {param}={payload}",
                    "3. Observe injected header in HTTP response",
                ],
            )

        # Check for response splitting (body injection)
        # The URL-encoded payload gets decoded by the server, so check for
        # the decoded form: <script>alert(1)</script> appearing in response body
        if "<script>" in resp.text and "alert(1)" in resp.text:
            return self.make_finding(
                title=f"HTTP Response Splitting via '{param}'",
                vuln_type="response_splitting", severity=Severity.HIGH,
                url=url, parameter=param, payload=payload,
                evidence="CRLF + script injection in response body",
                request=raw_req, response=resp.text[:500],
                cwe_id="CWE-113",
                owasp_category="A03:2021 - Injection",
                description="Full HTTP response splitting — attacker can inject arbitrary response body.",
                poc_steps=[
                    f"1. Navigate to {url}",
                    f"2. Set {param}={payload}",
                    "3. CRLF sequence terminates headers and injects HTML/JS into response body",
                ],
            )

        return None
