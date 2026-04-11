"""Sensitive Data Exposure Scanner (curated, low-impact checks)."""
from __future__ import annotations

import asyncio
import re
from typing import List, Optional, Tuple

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState

# Curated high-signal paths only; keeps request volume bounded.
SENSITIVE_PATHS: List[Tuple[str, str, str, str]] = [
    ("/.env", "Exposed environment file", Severity.CRITICAL, "CWE-200"),
    ("/.env.production", "Exposed production environment file", Severity.CRITICAL, "CWE-200"),
    ("/.git/config", "Exposed git config", Severity.HIGH, "CWE-527"),
    ("/.git/HEAD", "Exposed git HEAD", Severity.HIGH, "CWE-527"),
    ("/backup.zip", "Exposed backup archive", Severity.HIGH, "CWE-530"),
    ("/db_backup.sql", "Exposed DB dump", Severity.CRITICAL, "CWE-530"),
    ("/config.json", "Exposed config.json", Severity.HIGH, "CWE-200"),
    ("/application.yml", "Exposed application.yml", Severity.HIGH, "CWE-200"),
    ("/swagger.json", "Public API schema exposure", Severity.MEDIUM, "CWE-200"),
    ("/v2/api-docs", "Public API docs exposure", Severity.MEDIUM, "CWE-200"),
    ("/actuator/env", "Spring actuator env exposed", Severity.CRITICAL, "CWE-200"),
    ("/actuator/heapdump", "Heap dump exposed", Severity.CRITICAL, "CWE-200"),
    ("/.DS_Store", "Directory metadata file exposed", Severity.MEDIUM, "CWE-538"),
]

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"),
    re.compile(r"(?i)(password|passwd|secret|token|apikey|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/.+=]{8,}"),
]

MAX_PATHS = 24


class SensitiveDataExposureScanner(BaseScanner):
    name = "sensitive_data_exposure"
    description = "Detects exposed sensitive files, debug endpoints, and leaked secret material"
    tags = ["misconfig", "exposure", "owasp-a02"]

    async def run(self, state: ScanState) -> List[Finding]:
        base = state.target.url.rstrip("/")
        tasks = []

        for path, title, severity, cwe in SENSITIVE_PATHS[:MAX_PATHS]:
            url = base + path
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            tasks.append(self._check_path(url, title, severity, cwe))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[Finding] = []
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)
        return findings

    async def _check_path(self, url: str, title: str, severity: str, cwe: str) -> Optional[Finding]:
        resp, raw_req = await self.client.get(url, extra_headers=self.get_evasion_headers())
        if not resp or resp.status_code != 200:
            return None

        body = resp.text or ""
        if len(body) < 12:
            return None

        if url.endswith("/.git/HEAD") and "ref: refs/" not in body:
            return None
        if url.endswith("/.env") and "=" not in body:
            return None

        secret_hit = self._find_secret(body)
        vuln_type = "secret_disclosure" if secret_hit else "sensitive_data_exposure"
        evidence = f"HTTP 200 on sensitive path; preview={body[:120]!r}"
        if secret_hit:
            evidence = f"HTTP 200 and secret-like pattern detected: {secret_hit.pattern}"

        return self.make_finding(
            title=title,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            evidence=evidence,
            request=raw_req,
            response=body[:400],
            cwe_id=cwe,
            owasp_category="A02:2021 - Cryptographic Failures",
            description="Sensitive content is publicly reachable and may leak credentials or internal details.",
        )

    @staticmethod
    def _find_secret(body: str):
        for pattern in SECRET_PATTERNS:
            if pattern.search(body[:25000]):
                return pattern
        return None
