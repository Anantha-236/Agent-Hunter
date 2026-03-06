"""Security Misconfiguration Scanner"""
from __future__ import annotations
import asyncio
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

SENSITIVE_PATHS = [
    ("/.git/HEAD",         "Exposed Git Repository",       Severity.HIGH,     "CWE-527"),
    ("/.env",              "Exposed .env File",            Severity.CRITICAL, "CWE-200"),
    ("/.env.production",   "Exposed .env.production",      Severity.CRITICAL, "CWE-200"),
    ("/wp-config.php",     "WordPress Config Accessible",  Severity.CRITICAL, "CWE-200"),
    ("/actuator/env",      "Spring Actuator /env Exposed", Severity.CRITICAL, "CWE-200"),
    ("/phpinfo.php",       "PHP Info Exposed",             Severity.MEDIUM,   "CWE-200"),
    ("/debug",             "Debug Endpoint",               Severity.MEDIUM,   "CWE-200"),
    ("/_profiler",         "Symfony Profiler",             Severity.HIGH,     "CWE-200"),
    ("/graphiql",          "GraphiQL IDE Exposed",         Severity.MEDIUM,   "CWE-200"),
    ("/actuator/heapdump", "Heap Dump Exposed",            Severity.CRITICAL, "CWE-200"),
    ("/error.log",         "Exposed Error Log",            Severity.HIGH,     "CWE-200"),
    ("/backup.zip",        "Exposed Backup",               Severity.HIGH,     "CWE-530"),
    ("/db_backup.sql",     "Exposed DB Backup",            Severity.CRITICAL, "CWE-530"),
    ("/package.json",      "Exposed package.json",         Severity.MEDIUM,   "CWE-200"),
    ("/.svn/entries",      "Exposed SVN Repository",       Severity.HIGH,     "CWE-527"),
    ("/telescope",         "Laravel Telescope Exposed",    Severity.HIGH,     "CWE-200"),
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS",
    "Content-Security-Policy": "Missing CSP",
    "X-Frame-Options": "Missing X-Frame-Options (Clickjacking)",
    "X-Content-Type-Options": "Missing X-Content-Type-Options",
    "Referrer-Policy": "Missing Referrer-Policy",
}


class MisconfigScanner(BaseScanner):
    name = "misconfig_scanner"
    description = "Detects misconfigurations, exposed files, CORS issues, missing headers"
    tags = ["misconfig", "owasp-a05"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        base = state.target.url.rstrip("/")

        # Sensitive paths
        tasks = [self._check_path(base, path, title, sev, cwe)
                 for path, title, sev, cwe in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings.extend(r for r in results if isinstance(r, Finding))

        # Security headers + CORS
        resp, raw_req = await self.client.get(state.target.url)
        if resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            for header, issue in SECURITY_HEADERS.items():
                if header.lower() not in hdrs:
                    findings.append(self.make_finding(
                        title=issue, vuln_type="missing_security_header",
                        severity=Severity.LOW, url=state.target.url, parameter=header,
                        evidence=f"'{header}' absent", request=raw_req,
                        cwe_id="CWE-693", owasp_category="A05:2021 - Security Misconfiguration",
                    ))
            # CORS wildcard without credentials is low risk
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == "*":
                findings.append(self.make_finding(
                    title="Overly Permissive CORS (Wildcard Origin)",
                    vuln_type="cors_wildcard", severity=Severity.LOW,
                    url=state.target.url, parameter="Access-Control-Allow-Origin",
                    evidence=f"ACAO: {acao}", request=raw_req,
                    cwe_id="CWE-942", owasp_category="A05:2021 - Security Misconfiguration",
                    description="Wildcard CORS without credentials. Low risk unless combined with credentials.",
                ))

        # CORS arbitrary origin reflection
        resp2, raw2 = await self.client.get(state.target.url, extra_headers={"Origin": "https://evil.com"})
        if resp2:
            acao2 = resp2.headers.get("access-control-allow-origin", "")
            acac = resp2.headers.get("access-control-allow-credentials", "")
            if "evil.com" in acao2 and acac == "true":
                findings.append(self.make_finding(
                    title="CORS Origin Reflection with Credentials Allowed",
                    vuln_type="cors_origin_reflection", severity=Severity.HIGH,
                    url=state.target.url, parameter="Origin", payload="Origin: https://evil.com",
                    evidence=f"ACAO: {acao2}, ACAC: {acac}",
                    request=raw2, response="",
                    cwe_id="CWE-942", owasp_category="A05:2021 - Security Misconfiguration",
                    description="Arbitrary origin reflected with credentials=true allows CSRF+data theft.",
                ))

        # Directory listing (parallel)
        dir_tasks = []
        for path in ["/", "/uploads/", "/static/", "/images/"]:
            url = base + path
            if state.target.scope and not state.target.scope.is_in_scope(url): continue
            dir_tasks.append(self._check_dir_listing(url))
        dir_results = await asyncio.gather(*dir_tasks, return_exceptions=True)
        findings.extend(r for r in dir_results if isinstance(r, Finding))

        return findings

    async def _check_dir_listing(self, url: str) -> Finding | None:
        resp_d, raw_d = await self.client.get(url)
        # Check for common directory listing patterns (Apache, Nginx, IIS)
        if resp_d and any(sig in resp_d.text for sig in ["Index of /", "<title>Directory listing", "[To Parent Directory]"]):
            return self.make_finding(
                title=f"Directory Listing Enabled: {url.split('/', 3)[-1] if '/' in url else '/'}",
                vuln_type="directory_listing", severity=Severity.MEDIUM,
                url=url, evidence="Directory listing signature in response",
                request=raw_d, response=resp_d.text[:300],
                cwe_id="CWE-548",
                owasp_category="A05:2021 - Security Misconfiguration",
                description="Directory listing exposes file structure to attackers.",
            )
        return None

    async def _check_path(self, base, path, title, severity, cwe):
        url = base + path
        resp, raw_req = await self.client.get(url)
        if resp and resp.status_code == 200 and len(resp.text) > 10:
            if path == "/.git/HEAD" and "ref: refs/" not in resp.text: return None
            if path == "/.env" and "=" not in resp.text: return None
            return self.make_finding(
                title=title, vuln_type="sensitive_file_exposure",
                severity=severity, url=url,
                evidence=f"HTTP 200: {resp.text[:150]}",
                request=raw_req, response=resp.text[:300],
                cwe_id=cwe, owasp_category="A05:2021 - Security Misconfiguration",
                description=f"Sensitive file accessible at {url}",
            )
        return None
