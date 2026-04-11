"""Advanced JWT Scanner (WAF-aware, production-safe)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Dict, List, Optional, Tuple

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
MAX_COLLECTION_URLS = 15
MAX_PROTECTED_URLS = 12

WEAK_SECRETS = [
    "secret",
    "jwtsecret",
    "password",
    "changeme",
    "admin",
    "123456",
    "qwerty",
    "test",
]

PROTECTED_HINTS = (
    "api", "admin", "account", "profile", "me", "user", "auth", "private",
)


class JWTScanner(BaseScanner):
    name = "jwt_scanner"
    description = "Detects JWT misconfigurations: alg none, weak secrets, and unsafe claims"
    tags = ["auth", "jwt", "owasp-a07"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings: List[Finding] = []

        collection_urls = self._collection_urls(state)
        protected_urls = self._protected_urls(state)

        tokens = await self._collect_tokens(collection_urls)
        if not tokens:
            return findings

        for token, source_url in tokens:
            parsed = self._parse_jwt(token)
            if not parsed:
                continue
            header, payload, signature = parsed

            weak = self._check_weak_secret(token, header, signature)
            if weak:
                findings.append(self.make_finding(
                    title="JWT weak signing secret",
                    vuln_type="jwt_weak_secret",
                    severity=Severity.CRITICAL,
                    url=source_url,
                    parameter="token",
                    payload=token[:80],
                    evidence=f"HS signature validates with weak secret '{weak}'",
                    cwe_id="CWE-798",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                ))

            claim_finding = self._check_claims(header, payload, source_url, token)
            if claim_finding:
                findings.append(claim_finding)

            alg_none_findings = await self._test_alg_none(token, header, payload, protected_urls)
            findings.extend(alg_none_findings)

        return findings

    def _collection_urls(self, state: ScanState) -> List[str]:
        urls: List[str] = []
        seen = set()

        for url in [state.target.url, *state.target.discovered_urls]:
            if not url or url in seen:
                continue
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            seen.add(url)
            urls.append(url)
            if len(urls) >= MAX_COLLECTION_URLS:
                break
        return urls

    def _protected_urls(self, state: ScanState) -> List[str]:
        urls: List[str] = []
        seen = set()

        for url in [state.target.url, *state.target.discovered_urls]:
            if not url or url in seen:
                continue
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            low = url.lower()
            if any(h in low for h in PROTECTED_HINTS):
                seen.add(url)
                urls.append(url)
            if len(urls) >= MAX_PROTECTED_URLS:
                break

        if not urls:
            urls = [state.target.url]
        return urls

    async def _collect_tokens(self, urls: List[str]) -> List[Tuple[str, str]]:
        tokens: List[Tuple[str, str]] = []
        seen = set()

        for url in urls:
            resp, _ = await self.client.get(url, extra_headers=self.get_evasion_headers())
            if not resp:
                continue

            for value in resp.headers.values():
                for token in JWT_RE.findall(str(value)):
                    if token not in seen:
                        seen.add(token)
                        tokens.append((token, url))

            for cookie_val in resp.cookies.values():
                for token in JWT_RE.findall(str(cookie_val)):
                    if token not in seen:
                        seen.add(token)
                        tokens.append((token, url))

            for token in JWT_RE.findall(resp.text[:15000]):
                if token not in seen:
                    seen.add(token)
                    tokens.append((token, url))

        return tokens

    def _parse_jwt(self, token: str) -> Optional[Tuple[Dict, Dict, str]]:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
        except Exception:
            return None
        return header, payload, parts[2]

    def _check_weak_secret(self, token: str, header: Dict, signature: str) -> Optional[str]:
        alg = str(header.get("alg", "")).upper()
        if not alg.startswith("HS"):
            return None

        signing_input = ".".join(token.split(".")[:2]).encode()
        digestmod = hashlib.sha256 if alg == "HS256" else hashlib.sha384 if alg == "HS384" else hashlib.sha512

        for candidate in WEAK_SECRETS:
            expected = hmac.new(candidate.encode(), signing_input, digestmod).digest()
            expected_sig = self._b64url_encode(expected)
            if hmac.compare_digest(expected_sig, signature):
                return candidate
        return None

    def _check_claims(self, header: Dict, payload: Dict, source_url: str, token: str) -> Optional[Finding]:
        now = int(time.time())
        exp = payload.get("exp")

        if exp is None:
            return self.make_finding(
                title="JWT missing expiration claim",
                vuln_type="jwt_missing_exp",
                severity=Severity.MEDIUM,
                url=source_url,
                parameter="token",
                payload=token[:80],
                evidence="Token has no 'exp' claim",
                cwe_id="CWE-613",
                owasp_category="A07:2021 - Identification and Authentication Failures",
            )

        try:
            exp_val = int(exp)
        except Exception:
            return None

        if exp_val > now + 60 * 60 * 24 * 90:
            return self.make_finding(
                title="JWT excessively long lifetime",
                vuln_type="jwt_long_lived",
                severity=Severity.MEDIUM,
                url=source_url,
                parameter="token",
                payload=token[:80],
                evidence=f"exp is more than 90 days in future ({exp_val})",
                cwe_id="CWE-613",
                owasp_category="A07:2021 - Identification and Authentication Failures",
            )
        return None

    async def _test_alg_none(
        self,
        token: str,
        header: Dict,
        payload: Dict,
        protected_urls: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        if str(header.get("alg", "")).lower() == "none":
            return findings

        forged_header = {"alg": "none", "typ": "JWT"}
        forged_token = (
            f"{self._b64url_encode(json.dumps(forged_header).encode())}."
            f"{self._b64url_encode(json.dumps(payload).encode())}."
        )

        baseline_hdrs = {"Authorization": "Bearer invalid.invalid.invalid", **self.get_evasion_headers()}
        forged_hdrs = {"Authorization": f"Bearer {forged_token}", **self.get_evasion_headers()}

        for url in protected_urls:
            baseline_resp, _ = await self.client.get(url, extra_headers=baseline_hdrs)
            forged_resp, forged_raw = await self.client.get(url, extra_headers=forged_hdrs)
            if not forged_resp:
                continue

            if forged_resp.status_code != 200:
                continue

            if baseline_resp and baseline_resp.status_code == 200:
                # Public endpoint; skip to avoid false positives.
                continue

            findings.append(self.make_finding(
                title="JWT alg:none attack accepted",
                vuln_type="jwt_alg_none",
                severity=Severity.CRITICAL,
                url=url,
                parameter="Authorization",
                payload=f"Bearer {forged_token[:80]}",
                evidence=f"Forged alg=none token accepted (HTTP {forged_resp.status_code})",
                request=forged_raw,
                response=forged_resp.text[:300],
                cwe_id="CWE-347",
                owasp_category="A07:2021 - Identification and Authentication Failures",
            ))
            break

        return findings

    @staticmethod
    def _b64url_decode(value: str) -> bytes:
        pad = "=" * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode(value + pad)

    @staticmethod
    def _b64url_encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode().rstrip("=")
