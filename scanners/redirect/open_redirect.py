"""Open Redirect Scanner — detects unvalidated redirect vulnerabilities."""
from __future__ import annotations
import asyncio
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnTo", "next", "url", "rurl", "dest", "destination", "redir",
    "continue", "target", "view", "goto", "out", "link", "forward",
    "callback", "path", "to", "checkout_url", "login_url", "image_url",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2F%2F",
    "////evil.com",
    "https:evil.com",
    "https://target.com@evil.com",
    "https://target.com.evil.com",
    "java%0d%0ascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]


class OpenRedirectScanner(BaseScanner):
    name = "open_redirect"
    description = "Detects unvalidated redirect / open redirect vulnerabilities"
    tags = ["redirect", "owasp-a01"]

    async def run(self, state: ScanState) -> List[Finding]:
        tasks = []
        for url, params in state.target.discovered_params.items():
            for param in params:
                if param.lower() in REDIRECT_PARAMS:
                    for payload in REDIRECT_PAYLOADS:
                        tasks.append(self._test(url, param, payload))
        # Also check discovered URLs that look like redirects
        for url in state.target.discovered_urls:
            if any(kw in url.lower() for kw in ["redirect", "return", "next=", "goto", "redir"]):
                tasks.append(self._test_url(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, Finding)]

    async def _test(self, url, param, payload):
        # Use no-redirect request to see raw 3xx responses
        resp, raw_req = await self.test_payload_no_redirect(url, "GET", param, payload, inject_in="query")
        if not resp:
            return None
        # Check 3xx redirect to evil domain
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if "evil.com" in location:
                return self.make_finding(
                    title=f"Open Redirect via '{param}'",
                    vuln_type="open_redirect", severity=Severity.MEDIUM,
                    url=url, parameter=param, payload=payload,
                    evidence=f"Redirects to: {location}",
                    request=raw_req, response="",
                    cwe_id="CWE-601",
                    owasp_category="A01:2021 - Broken Access Control",
                    description=f"Parameter '{param}' allows redirect to arbitrary external URLs.",
                    poc_steps=[f"1. Navigate to {url}", f"2. Set {param}={payload}",
                               f"3. Observe redirect to {location}"],
                )
        # Also check the followed-redirect response for reflected payload
        resp_followed, _ = await self.test_payload(url, "GET", param, payload, inject_in="query")
        if resp_followed and payload in resp_followed.text and ("location" in resp_followed.text.lower() or "refresh" in resp_followed.text.lower()):
            return self.make_finding(
                title=f"Open Redirect (Reflected) via '{param}'",
                vuln_type="open_redirect_reflected", severity=Severity.MEDIUM,
                url=url, parameter=param, payload=payload,
                evidence=f"Payload reflected near redirect context",
                request=raw_req, response=resp_followed.text[:300],
                cwe_id="CWE-601",
                owasp_category="A01:2021 - Broken Access Control",
            )
        return None

    async def _test_url(self, url):
        """Test URLs that already contain redirect-like parameters."""
        resp, raw_req = await self.client.get_no_redirect(url)
        if resp and resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            # Check if the redirect target is user-controllable
            if any(domain in location for domain in ["evil.com", "attacker.com"]):
                return self.make_finding(
                    title=f"Open Redirect in discovered URL",
                    vuln_type="open_redirect", severity=Severity.MEDIUM,
                    url=url, evidence=f"Redirects to: {location}",
                    request=raw_req, cwe_id="CWE-601",
                    owasp_category="A01:2021 - Broken Access Control",
                )
        return None
