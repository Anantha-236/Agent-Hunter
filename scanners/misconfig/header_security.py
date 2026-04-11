"""Advanced Security Header Scanner (low-impact)."""
from __future__ import annotations

import asyncio
from typing import List

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState

MAX_URLS = 20
REQUIRED_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


class HeaderSecurityScanner(BaseScanner):
    name = "header_security"
    description = "Detects missing or weak HTTP security headers"
    tags = ["headers", "misconfig", "owasp-a05"]

    async def run(self, state: ScanState) -> List[Finding]:
        urls = self._candidate_urls(state)
        tasks = [self._check_headers(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: List[Finding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    def _candidate_urls(self, state: ScanState) -> List[str]:
        seen = set()
        urls: List[str] = []

        for url in [state.target.url, *state.target.discovered_urls]:
            if not url or url in seen:
                continue
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            seen.add(url)
            urls.append(url)
            if len(urls) >= MAX_URLS:
                break
        return urls

    async def _check_headers(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        resp, raw_req = await self.client.get(url, extra_headers=self.get_evasion_headers())
        if not resp:
            return findings

        hdrs = {k.lower(): v for k, v in resp.headers.items()}

        missing = []
        for key, label in REQUIRED_HEADERS.items():
            if key not in hdrs:
                # HSTS is expected only on HTTPS endpoints.
                if key == "strict-transport-security" and not url.lower().startswith("https://"):
                    continue
                missing.append(label)

        if missing:
            findings.append(self.make_finding(
                title="Missing security headers",
                vuln_type="header_missing",
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"Missing: {', '.join(missing)}",
                request=raw_req,
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
            ))

        weak_reasons = []

        csp = (hdrs.get("content-security-policy") or "").lower()
        if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
            weak_reasons.append("CSP allows unsafe-inline/unsafe-eval")

        hsts = (hdrs.get("strict-transport-security") or "").lower()
        if hsts and "max-age=" in hsts:
            try:
                max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                if max_age < 15552000:
                    weak_reasons.append("HSTS max-age below 180 days")
            except Exception:
                weak_reasons.append("HSTS max-age parsing failed")

        xfo = (hdrs.get("x-frame-options") or "").upper()
        if xfo and xfo not in ("DENY", "SAMEORIGIN"):
            weak_reasons.append(f"X-Frame-Options is weak: {xfo}")

        xcto = (hdrs.get("x-content-type-options") or "").lower()
        if xcto and xcto != "nosniff":
            weak_reasons.append(f"X-Content-Type-Options should be 'nosniff' (got '{xcto}')")

        if weak_reasons:
            findings.append(self.make_finding(
                title="Weak security header configuration",
                vuln_type="header_weak",
                severity=Severity.MEDIUM,
                url=url,
                evidence="; ".join(weak_reasons),
                request=raw_req,
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
            ))

        return findings
