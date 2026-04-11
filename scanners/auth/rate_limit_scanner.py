"""Advanced Rate-Limit Scanner (production-safe burst checks)."""
from __future__ import annotations

import asyncio
from typing import List, Optional

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState

MAX_ENDPOINTS = 6
BURST_COUNT = 6
LOGIN_HINTS = (
    "login", "signin", "auth", "otp", "verify", "token", "reset", "password",
)


class RateLimitScanner(BaseScanner):
    name = "rate_limit_scanner"
    description = "Detects missing API/auth rate limits and basic IP-header bypass"
    tags = ["auth", "rate-limit", "owasp-a04"]

    async def run(self, state: ScanState) -> List[Finding]:
        # Respect policy-driven restrictions for brute-force-like behavior.
        if state.target.metadata.get("disable_bruteforce"):
            return []

        findings: List[Finding] = []
        for url in self._candidate_urls(state):
            finding = await self._probe_endpoint(url)
            if finding:
                findings.append(finding)
        return findings

    def _candidate_urls(self, state: ScanState) -> List[str]:
        urls: List[str] = []
        seen = set()

        for url in [state.target.url, *state.target.discovered_urls]:
            if not url or url in seen:
                continue
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            if any(h in url.lower() for h in LOGIN_HINTS):
                seen.add(url)
                urls.append(url)
            if len(urls) >= MAX_ENDPOINTS:
                break

        if not urls:
            urls = [state.target.url]
        return urls

    async def _probe_endpoint(self, url: str) -> Optional[Finding]:
        statuses = []
        retry_after_seen = False
        blocked_markers = 0

        baseline_headers = self.get_evasion_headers()
        is_login = any(h in url.lower() for h in LOGIN_HINTS)

        for _ in range(BURST_COUNT):
            if is_login:
                resp, raw_req = await self.client.post(
                    url,
                    data={"username": "rate_limit_probe", "password": "invalid_password"},
                    extra_headers=baseline_headers,
                )
            else:
                resp, raw_req = await self.client.get(url, extra_headers=baseline_headers)
            if not resp:
                continue

            statuses.append(resp.status_code)
            if resp.headers.get("retry-after"):
                retry_after_seen = True

            low = (resp.text or "").lower()
            if any(x in low for x in ("too many requests", "rate limit", "slow down", "try again later")):
                blocked_markers += 1

            # Keep bursts short but still measurable.
            await asyncio.sleep(0.08)

        if not statuses:
            return None

        had_protection = any(s in (429, 503) for s in statuses) or retry_after_seen or blocked_markers > 0

        if not had_protection:
            return self.make_finding(
                title="No effective rate limiting detected",
                vuln_type="rate_limit_missing",
                severity=Severity.MEDIUM,
                url=url,
                method="POST" if is_login else "GET",
                evidence=f"{len(statuses)} rapid requests returned {statuses} with no throttle indicators",
                request=raw_req,
                cwe_id="CWE-770",
                owasp_category="A04:2021 - Insecure Design",
                description="Endpoint appears vulnerable to brute-force/enumeration due to absent throttling.",
            )

        # If protection exists, test a lightweight header-based bypass hypothesis.
        bypass_statuses = []
        for spoof in ("10.0.0.10", "10.0.0.11"):
            hdrs = {"X-Forwarded-For": spoof, **baseline_headers}
            if is_login:
                resp, _ = await self.client.post(
                    url,
                    data={"username": "rate_limit_probe", "password": "invalid_password"},
                    extra_headers=hdrs,
                )
            else:
                resp, _ = await self.client.get(url, extra_headers=hdrs)
            if resp:
                bypass_statuses.append(resp.status_code)

        if bypass_statuses and all(s < 429 for s in bypass_statuses):
            return self.make_finding(
                title="Potential rate-limit bypass via X-Forwarded-For rotation",
                vuln_type="rate_limit_bypass_xff",
                severity=Severity.HIGH,
                url=url,
                method="POST" if is_login else "GET",
                payload="X-Forwarded-For: rotating values",
                evidence=f"Protected baseline but bypass attempts returned {bypass_statuses}",
                cwe_id="CWE-770",
                owasp_category="A04:2021 - Insecure Design",
            )

        return None
