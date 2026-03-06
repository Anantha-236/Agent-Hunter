"""Host Header Injection Scanner — detects host header manipulation vulnerabilities."""
from __future__ import annotations
import asyncio
import re
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

EVIL_HOST = "evil.attacker.com"

HOST_PAYLOADS = [
    {"header": "Host", "value": EVIL_HOST},
    {"header": "X-Forwarded-Host", "value": EVIL_HOST},
    {"header": "X-Host", "value": EVIL_HOST},
    {"header": "X-Forwarded-Server", "value": EVIL_HOST},
    {"header": "X-Original-URL", "value": f"/{EVIL_HOST}"},
    {"header": "X-Rewrite-URL", "value": f"/{EVIL_HOST}"},
    {"header": "Forwarded", "value": f"host={EVIL_HOST}"},
]


class HostHeaderScanner(BaseScanner):
    name = "host_header"
    description = "Detects host header injection / poisoning vulnerabilities"
    tags = ["hostheader", "owasp-a05"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        target_url = state.target.url

        # Test main URL and password reset-like endpoints
        test_urls = [target_url]
        for url in state.target.discovered_urls[:30]:
            url_lower = url.lower()
            if any(kw in url_lower for kw in [
                "reset", "forgot", "password", "register", "confirm",
                "activate", "verify", "invite", "callback",
            ]):
                test_urls.append(url)

        for url in test_urls:
            tasks = [self._test_host(url, p) for p in HOST_PAYLOADS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Finding):
                    findings.append(r)

        # Test for web cache poisoning via Host
        cache_finding = await self._test_cache_poisoning(target_url)
        if cache_finding:
            findings.append(cache_finding)

        return findings

    async def _test_host(self, url: str, payload: dict) -> Finding | None:
        header_name = payload["header"]
        header_value = payload["value"]

        try:
            custom_headers = {header_name: header_value}
            resp, raw_req = await self.client.get(url, extra_headers=custom_headers)
            if not resp:
                return None

            body = resp.text
            headers_str = str(resp.headers)

            # Check if evil host appears in response
            if EVIL_HOST in body:
                # Determine context
                in_link = bool(re.search(
                    rf'(href|src|action|url)[=:]["\']?[^"\']*{re.escape(EVIL_HOST)}',
                    body, re.IGNORECASE,
                ))
                in_reset = any(kw in url.lower() for kw in ["reset", "forgot", "password"])

                if in_reset:
                    return self.make_finding(
                        title=f"Password Reset Poisoning via {header_name}",
                        vuln_type="password_reset_poisoning",
                        severity=Severity.HIGH,
                        url=url, parameter=header_name, payload=header_value,
                        evidence=f"Evil host '{EVIL_HOST}' reflected in password reset page",
                        request=raw_req, response=body[:400],
                        cwe_id="CWE-644",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        description=(
                            f"The password reset flow uses the {header_name} header to "
                            f"construct reset URLs. An attacker can poison the reset link "
                            f"to point to their server, capturing the reset token."
                        ),
                        poc_steps=[
                            f"1. Request password reset for victim",
                            f"2. Intercept request and set {header_name}: {EVIL_HOST}",
                            "3. Victim receives email with reset link pointing to attacker's server",
                            "4. Clicking the link sends the reset token to the attacker",
                            "5. Attacker uses the token to reset victim's password",
                        ],
                    )

                return self.make_finding(
                    title=f"Host Header Injection via {header_name}",
                    vuln_type="host_header_injection",
                    severity=Severity.MEDIUM if not in_link else Severity.HIGH,
                    url=url, parameter=header_name, payload=header_value,
                    evidence=f"Host '{EVIL_HOST}' reflected in response"
                             f"{' (in link/URL context)' if in_link else ''}",
                    request=raw_req, response=body[:400],
                    cwe_id="CWE-644",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )

            # Check if host appears in Location header (redirect)
            # Use a separate no-redirect request to expose raw 3xx
            try:
                resp_nr, raw_nr = await self.client.get_no_redirect(
                    url, extra_headers=custom_headers
                )
                if resp_nr and resp_nr.status_code in (301, 302, 303, 307, 308):
                    nr_location = resp_nr.headers.get("location", "")
                    if EVIL_HOST in nr_location:
                        return self.make_finding(
                            title=f"Host Header Redirect Injection via {header_name}",
                            vuln_type="host_header_redirect",
                            severity=Severity.HIGH,
                            url=url, parameter=header_name, payload=header_value,
                            evidence=f"Redirect to: {nr_location}",
                            request=raw_nr,
                            cwe_id="CWE-644",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        )
            except Exception:
                pass

        except Exception:
            pass
        return None

    async def _test_cache_poisoning(self, url: str) -> Finding | None:
        """Test if Host header injection can poison web cache."""
        try:
            # Add cache buster, handling URLs that may already have query params
            separator = "&" if "?" in url else "?"
            cache_buster = f"{separator}cb={hash(url) % 99999}"
            test_url = url + cache_buster

            # Request 1: inject evil host
            resp1, req1 = await self.client.get(
                test_url, extra_headers={"X-Forwarded-Host": EVIL_HOST}
            )
            if not resp1 or EVIL_HOST not in resp1.text:
                return None

            # Request 2: normal request — check if poisoned
            resp2, _ = await self.client.get(test_url)
            if resp2 and EVIL_HOST in resp2.text:
                return self.make_finding(
                    title="Web Cache Poisoning via Host Header",
                    vuln_type="cache_poisoning_host",
                    severity=Severity.CRITICAL,
                    url=url, parameter="X-Forwarded-Host", payload=EVIL_HOST,
                    evidence="Injected host persisted in cached response served to other users",
                    request=req1,
                    cwe_id="CWE-444",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description=(
                        "The X-Forwarded-Host header value is reflected in the response "
                        "and the response is cached. This allows an attacker to serve "
                        "malicious content to all users hitting the cached page."
                    ),
                )
        except Exception:
            pass
        return None
