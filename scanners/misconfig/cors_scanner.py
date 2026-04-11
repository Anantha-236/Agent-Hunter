"""Advanced CORS Scanner (WAF-aware, production-safe)."""
from __future__ import annotations

import asyncio
from typing import List

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState

# Keep probe count low to avoid stressing production systems.
MAX_URLS = 25
ORIGIN_PROBES = [
    "https://evil.example",
    "https://sub.evil.example",
    "null",
]


class CORSScanner(BaseScanner):
    name = "cors_scanner"
    description = "Detects dangerous CORS policies with credentialed cross-origin access"
    tags = ["cors", "misconfig", "owasp-a05"]

    async def run(self, state: ScanState) -> List[Finding]:
        urls = self._candidate_urls(state)
        tasks = [self._check_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: List[Finding] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
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

    async def _check_url(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        evasion = self.get_evasion_headers()

        for origin in ORIGIN_PROBES:
            headers = {"Origin": origin, **evasion}
            resp, raw_req = await self.client.get(url, extra_headers=headers)
            if not resp:
                continue

            acao = (resp.headers.get("access-control-allow-origin") or "").strip()
            acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()
            acapn = (resp.headers.get("access-control-allow-private-network") or "").strip().lower()

            if acao == "*" and acac == "true":
                findings.append(self.make_finding(
                    title="CORS wildcard with credentials",
                    vuln_type="cors_wildcard_with_credentials",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter="Origin",
                    payload=origin,
                    evidence=f"ACAO='*', ACAC='true'",
                    request=raw_req,
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description="Browser credentialed requests can be read by arbitrary origins.",
                ))
                continue

            if acao.lower() == origin.lower() and acac == "true":
                findings.append(self.make_finding(
                    title="Credentialed CORS origin reflection",
                    vuln_type="cors_credentials_reflection",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="Origin",
                    payload=origin,
                    evidence=f"Reflected Origin '{origin}' with ACAC='true'",
                    request=raw_req,
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description="Arbitrary trusted origin + credentials enables cross-origin data theft.",
                ))
                continue

            if origin == "null" and acao.lower() == "null" and acac == "true":
                findings.append(self.make_finding(
                    title="CORS trusts null origin with credentials",
                    vuln_type="cors_null_origin_trust",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="Origin",
                    payload="null",
                    evidence="ACAO='null' and ACAC='true'",
                    request=raw_req,
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 - Security Misconfiguration",
                ))
                continue

            if acao == "*" and acapn == "true":
                findings.append(self.make_finding(
                    title="CORS allows private network access from wildcard origin",
                    vuln_type="cors_private_network_wildcard",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="Origin",
                    payload=origin,
                    evidence="ACAO='*' with Access-Control-Allow-Private-Network='true'",
                    request=raw_req,
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 - Security Misconfiguration",
                ))

        return findings
