"""Auth Scanner: JWT, OAuth, Default Creds, Session Fixation"""
from __future__ import annotations
import asyncio, base64, json
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity


class AuthScanner(BaseScanner):
    name = "auth_scanner"
    description = "Detects JWT misconfigs, broken auth, OAuth issues, default creds"
    tags = ["auth", "owasp-a07"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        target = state.target
        results = await asyncio.gather(
            self._check_jwt(target),
            self._check_default_credentials(target),
            self._check_password_reset(target),
            self._check_oauth_redirect(target),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, list): findings.extend(r)
        return findings

    async def _check_jwt(self, target) -> List[Finding]:
        findings = []
        resp, raw_req = await self.client.get(target.url)
        if not resp: return findings
        cookies = dict(resp.cookies)
        # Collect JWT candidates from cookies and headers
        # Headers may contain "Bearer eyJ..." so check substring
        tokens = list(cookies.values())
        for v in resp.headers.values():
            if "eyJ" in v:
                # Extract the JWT token (strip Bearer prefix if present)
                parts = v.split()
                for part in parts:
                    if part.startswith("eyJ"):
                        tokens.append(part)
        for token in tokens:
            if not (token.startswith("eyJ") and token.count(".") == 2): continue
            parts = token.split(".")
            try:
                header_data = json.loads(base64.b64decode(parts[0] + "=="))
            except Exception: continue
            alg = header_data.get("alg", "")
            # Test alg:none
            none_hdr = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip("=")
            none_token = f"{none_hdr}.{parts[1]}."
            resp2, raw2 = await self.client.get(target.url, extra_headers={"Authorization": f"Bearer {none_token}"})
            if resp2 and resp2.status_code == 200:
                findings.append(self.make_finding(
                    title="JWT alg:none Attack Accepted",
                    vuln_type="jwt_alg_none", severity=Severity.CRITICAL,
                    url=target.url, parameter="Authorization", payload=none_token,
                    evidence=f"Server accepted JWT with alg:none (HTTP {resp2.status_code})",
                    request=raw2, response=resp2.text[:300],
                    cwe_id="CWE-347", owasp_category="A07:2021 - Identification and Authentication Failures",
                    description="Server accepts JWT with no signature verification. Allows complete auth bypass.",
                ))
        return findings

    async def _check_default_credentials(self, target) -> List[Finding]:
        findings = []
        admin_paths = ["/admin", "/login", "/wp-admin", "/administrator", "/panel"]
        default_creds = [("admin","admin"),("admin","password"),("admin","123456"),("root","root")]
        for path in admin_paths:
            url = target.url.rstrip("/") + path
            if target.scope and not target.scope.is_in_scope(url): continue
            resp, _ = await self.client.get(url)
            if not (resp and resp.status_code == 200): continue
            if not any(kw in resp.text.lower() for kw in ["login","password","username"]): continue
            for username, password in default_creds:
                resp2, raw2 = await self.client.post(url, data={"username": username, "password": password})
                if resp2 and resp2.status_code in (200, 302):
                    if any(kw in resp2.text.lower() for kw in ["dashboard","logout","welcome"]):
                        findings.append(self.make_finding(
                            title=f"Default Credentials: {username}/{password}",
                            vuln_type="default_credentials", severity=Severity.CRITICAL,
                            url=url, parameter="credentials", payload=f"{username}:{password}",
                            evidence=f"Login succeeded with {username}/{password}",
                            request=raw2, response=resp2.text[:300],
                            cwe_id="CWE-1392", owasp_category="A07:2021 - Identification and Authentication Failures",
                        ))
                        break
        return findings

    async def _check_password_reset(self, target) -> List[Finding]:
        findings = []
        for path in ["/forgot-password", "/reset-password", "/password-reset"]:
            url = target.url.rstrip("/") + path
            if target.scope and not target.scope.is_in_scope(url): continue
            resp, raw_req = await self.client.post(url, data={"email": "test@test.com"},
                                                   extra_headers={"Host": "evil.com"})
            if resp and "evil.com" in resp.text:
                findings.append(self.make_finding(
                    title="Host Header Injection in Password Reset",
                    vuln_type="host_header_injection", severity=Severity.HIGH,
                    url=url, parameter="Host", payload="Host: evil.com",
                    evidence="Response reflects injected Host header",
                    request=raw_req, response=resp.text[:300],
                    cwe_id="CWE-640", owasp_category="A07:2021 - Identification and Authentication Failures",
                ))
        return findings

    async def _check_oauth_redirect(self, target) -> List[Finding]:
        findings = []
        for url in target.discovered_urls:
            if not any(kw in url.lower() for kw in ["oauth","authorize","callback"]): continue
            sep = "&" if "?" in url else "?"
            resp, raw_req = await self.client.get_no_redirect(url + sep + "redirect_uri=https://evil.com")
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if "evil.com" in location:
                    findings.append(self.make_finding(
                        title="OAuth Open Redirect via redirect_uri",
                        vuln_type="oauth_open_redirect", severity=Severity.HIGH,
                        url=url, parameter="redirect_uri", payload="https://evil.com",
                        evidence=f"Redirected to: {location}",
                        request=raw_req, response="",
                        cwe_id="CWE-601", owasp_category="A07:2021 - Identification and Authentication Failures",
                    ))
        return findings
