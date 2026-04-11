"""Advanced Broken Access Control Scanner (beyond basic IDOR)."""
from __future__ import annotations

import asyncio
from difflib import SequenceMatcher
from typing import List, Optional

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState

MAX_ADMIN_ENDPOINTS = 20
MAX_PARAM_CHECKS = 30
MAX_OPTIONS_CHECKS = 12

SENSITIVE_PATH_HINTS = (
    "admin", "internal", "manage", "dashboard", "console", "backoffice", "private",
)
OBJECT_PARAMS = {
    "id", "user_id", "userid", "account_id", "tenant_id", "org_id", "project_id",
    "order_id", "profile_id", "invoice_id", "record_id", "resource_id",
}


class BrokenAccessControlScanner(BaseScanner):
    name = "broken_access_control"
    description = "Detects vertical/horizontal access control weaknesses and method exposure"
    tags = ["authz", "owasp-a01"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings: List[Finding] = []

        admin_tasks = [self._check_unauthenticated_access(url) for url in self._sensitive_urls(state)]
        admin_results = await asyncio.gather(*admin_tasks, return_exceptions=True)
        for r in admin_results:
            if isinstance(r, Finding):
                findings.append(r)

        param_tasks = self._build_param_tasks(state)
        param_results = await asyncio.gather(*param_tasks, return_exceptions=True)
        for r in param_results:
            if isinstance(r, Finding):
                findings.append(r)

        option_tasks = [self._check_options_exposure(url) for url in self._options_urls(state)]
        option_results = await asyncio.gather(*option_tasks, return_exceptions=True)
        for r in option_results:
            if isinstance(r, Finding):
                findings.append(r)

        return findings

    def _sensitive_urls(self, state: ScanState) -> List[str]:
        urls: List[str] = []
        seen = set()

        for url in [state.target.url, *state.target.discovered_urls]:
            if not url or url in seen:
                continue
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            if any(h in url.lower() for h in SENSITIVE_PATH_HINTS):
                seen.add(url)
                urls.append(url)
            if len(urls) >= MAX_ADMIN_ENDPOINTS:
                break

        return urls

    def _options_urls(self, state: ScanState) -> List[str]:
        urls: List[str] = []
        seen = set()

        for url in [state.target.url, *state.target.discovered_urls]:
            if not url or url in seen:
                continue
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            seen.add(url)
            urls.append(url)
            if len(urls) >= MAX_OPTIONS_CHECKS:
                break
        return urls

    def _build_param_tasks(self, state: ScanState):
        tasks = []
        count = 0
        for url, params in state.target.discovered_params.items():
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            for param in params:
                if param.lower() in OBJECT_PARAMS:
                    tasks.append(self._check_horizontal_access(url, param))
                    count += 1
                    if count >= MAX_PARAM_CHECKS:
                        return tasks
        return tasks

    async def _check_unauthenticated_access(self, url: str) -> Optional[Finding]:
        resp, raw_req = await self.client.get(url, extra_headers=self.get_evasion_headers())
        if not resp or resp.status_code != 200:
            return None

        body_low = resp.text.lower()
        if any(marker in body_low for marker in ("login", "sign in", "unauthorized", "forbidden")):
            return None

        return self.make_finding(
            title="Potential unauthenticated access to sensitive endpoint",
            vuln_type="broken_access_control_unauthenticated",
            severity=Severity.HIGH,
            url=url,
            method="GET",
            evidence="Sensitive endpoint returned HTTP 200 without authentication challenge",
            request=raw_req,
            response=resp.text[:300],
            cwe_id="CWE-306",
            owasp_category="A01:2021 - Broken Access Control",
        )

    async def _check_horizontal_access(self, url: str, param: str) -> Optional[Finding]:
        r1, raw1 = await self.test_payload_with_bypass(
            url,
            "GET",
            param,
            "1",
            vuln_type="broken_access_control",
            inject_in="query",
        )
        r2, _ = await self.test_payload_with_bypass(
            url,
            "GET",
            param,
            "2",
            vuln_type="broken_access_control",
            inject_in="query",
        )
        rn, _ = await self.test_payload_with_bypass(
            url,
            "GET",
            param,
            "99999999",
            vuln_type="broken_access_control",
            inject_in="query",
        )

        if not (r1 and r2 and rn):
            return None
        if r1.status_code != 200 or r2.status_code != 200:
            return None

        sim_12 = SequenceMatcher(None, r1.text[:2000], r2.text[:2000]).ratio()
        sim_1n = SequenceMatcher(None, r1.text[:2000], rn.text[:2000]).ratio()

        if sim_12 < 0.85 and sim_1n < 0.75:
            return self.make_finding(
                title=f"Potential horizontal access control bypass via '{param}'",
                vuln_type="broken_access_control_horizontal",
                severity=Severity.HIGH,
                url=url,
                parameter=param,
                method="GET",
                payload="1 -> 2",
                evidence=(
                    f"Response similarity changed (id1/id2={sim_12:.2f}, id1/nonexistent={sim_1n:.2f})"
                ),
                request=raw1,
                response=r1.text[:300],
                cwe_id="CWE-639",
                owasp_category="A01:2021 - Broken Access Control",
            )
        return None

    async def _check_options_exposure(self, url: str) -> Optional[Finding]:
        resp, raw_req = await self.client.options(url, extra_headers=self.get_evasion_headers())
        if not resp:
            return None

        allow = (resp.headers.get("allow") or "").upper()
        if not allow:
            return None

        dangerous = [m for m in ("PUT", "DELETE", "PATCH", "TRACE") if m in allow]
        if not dangerous:
            return None

        return self.make_finding(
            title="Potential method-based access control weakness",
            vuln_type="access_control_method_exposure",
            severity=Severity.MEDIUM,
            url=url,
            method="OPTIONS",
            evidence=f"Allow header exposes risky methods: {', '.join(dangerous)}",
            request=raw_req,
            cwe_id="CWE-285",
            owasp_category="A01:2021 - Broken Access Control",
        )
