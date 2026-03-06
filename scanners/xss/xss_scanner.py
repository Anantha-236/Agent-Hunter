"""XSS Scanner: Reflected, Stored, DOM-based"""
from __future__ import annotations
import asyncio, uuid
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

XSS_PAYLOADS = [
    '<script>alert(1)</script>', '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>', "javascript:alert(1)",
    '<details open ontoggle=alert(1)>', '<body onload=alert(1)>',
    '"-alert(1)-"', '<ScRiPt>alert(1)</sCrIpT>',
]

DOM_XSS_SINKS = ["document.write", "innerHTML", "outerHTML", "insertAdjacentHTML",
                 "eval(", "setTimeout(", "location.href", "document.URL"]

class XSSScanner(BaseScanner):
    name = "xss_scanner"
    description = "Detects Reflected XSS, Stored XSS, and DOM XSS sinks"
    tags = ["xss", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        canary = f"xss{uuid.uuid4().hex[:8]}"
        tasks = [self._test_reflected(url, param, canary)
                 for url, params in state.target.discovered_params.items()
                 for param in params]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list): findings.extend(r)
        # Parallelize DOM XSS checks
        js_files = state.target.metadata.get("js_files", [])
        if js_files:
            dom_tasks = [self._check_dom_xss(js_url) for js_url in js_files]
            dom_results = await asyncio.gather(*dom_tasks, return_exceptions=True)
            for r in dom_results:
                if isinstance(r, list):
                    findings.extend(r)
        return findings

    async def _check_dom_xss(self, js_url: str) -> List[Finding]:
        """Check a JS file for DOM XSS sinks."""
        resp, _ = await self.client.get(js_url)
        if not resp:
            return []
        findings = []
        for sink in DOM_XSS_SINKS:
            if sink in resp.text:
                findings.append(self.make_finding(
                    title=f"DOM XSS Sink: {sink}",
                    vuln_type="dom_xss", severity=Severity.MEDIUM,
                    url=js_url,
                    parameter=sink,
                    evidence=f"Sink '{sink}' found in JavaScript file",
                    response=resp.text[max(0, resp.text.index(sink)-50):resp.text.index(sink)+100][:200],
                    cwe_id="CWE-79", owasp_category="A03:2021 - Injection",
                    description=f"JavaScript file contains DOM XSS sink '{sink}'. "
                                f"If user-controlled input reaches this sink, XSS is possible.",
                    poc_steps=[
                        f"1. Identify DOM XSS sink '{sink}' in {js_url}",
                        "2. Trace data flow from source (URL, document.referrer, etc.) to sink",
                        "3. Inject XSS payload via the identified source",
                    ],
                ))
                break  # One sink per file is enough
        return findings

    async def _test_reflected(self, url, param, canary) -> List[Finding]:
        for payload in XSS_PAYLOADS:
            tagged = payload.replace("alert(1)", f"alert('{canary}')")
            resp, raw_req = await self.test_payload(url, "GET", param, tagged, inject_in="query")
            if resp is None: continue
            body = resp.text
            if tagged in body:
                return [self.make_finding(
                    title=f"Reflected XSS in '{param}'",
                    vuln_type="reflected_xss", severity=Severity.HIGH,
                    url=url, parameter=param, method="GET", payload=tagged,
                    evidence=f"Payload reflected unencoded in response",
                    request=raw_req, response=body[:500],
                    cwe_id="CWE-79", owasp_category="A03:2021 - Injection",
                    description=f"Parameter '{param}' reflects input without sanitization.",
                    poc_steps=[f"1. Navigate to {url}", f"2. Set {param}={tagged}", "3. Script executes"],
                )]
        return []
