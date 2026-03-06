"""CSRF Scanner — detects Cross-Site Request Forgery vulnerabilities."""
from __future__ import annotations
import asyncio
import re
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity


class CSRFScanner(BaseScanner):
    name = "csrf_scanner"
    description = "Detects Cross-Site Request Forgery vulnerabilities"
    tags = ["csrf", "owasp-a01"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        tasks = []

        for url in state.target.discovered_urls[:50]:
            tasks.append(self._check_page(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _check_page(self, url: str) -> List[Finding]:
        findings = []
        resp, raw_req = await self.client.get(url)
        if not resp or resp.status_code != 200:
            return findings

        body = resp.text
        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type:
            return findings

        # Find all forms
        form_tags_and_bodies = re.findall(
            r'<form([^>]*)>(.*?)</form>', body, re.DOTALL | re.IGNORECASE
        )
        for i, (form_attrs, form_html) in enumerate(form_tags_and_bodies):
            method = "GET"
            action = url
            method_match = re.search(r'method=["\']?(\w+)', form_attrs, re.IGNORECASE)
            if method_match:
                method = method_match.group(1).upper()
            action_match = re.search(r'action=["\']?([^"\'\s>]+)', form_attrs, re.IGNORECASE)
            if action_match:
                action = action_match.group(1)

            # Only POST/PUT/DELETE forms are CSRF targets
            if method not in ("POST", "PUT", "DELETE", "PATCH"):
                continue

            # Check for CSRF protections
            has_csrf_token = self._has_csrf_token(form_html)
            has_samesite = self._has_samesite_cookie(resp)
            has_custom_header_req = self._requires_custom_header(body)

            if not has_csrf_token and not has_samesite and not has_custom_header_req:
                # Determine severity based on form purpose
                severity = self._assess_severity(form_html, url)

                finding = self.make_finding(
                    title=f"Missing CSRF Protection on {method} Form",
                    vuln_type="csrf",
                    severity=severity,
                    url=url,
                    parameter=f"form#{i+1} (action: {action})",
                    evidence=f"Form with method={method} has no CSRF token, "
                             f"no SameSite cookie, no custom header requirement",
                    request=raw_req,
                    response=form_html[:300],
                    cwe_id="CWE-352",
                    owasp_category="A01:2021 - Broken Access Control",
                    description=(
                        f"A {method} form at {url} lacks CSRF protection. "
                        f"An attacker can craft a malicious page that submits this form "
                        f"on behalf of an authenticated user."
                    ),
                    poc_steps=[
                        f"1. Identify the {method} form at {url}",
                        f"2. Create an HTML page with auto-submitting form targeting {action}",
                        "3. Host the page on attacker-controlled domain",
                        "4. Trick authenticated user into visiting the page",
                        "5. Form submits with victim's session cookies",
                    ],
                )
                findings.append(finding)

            elif has_csrf_token:
                # Test if token is actually validated
                token_finding = await self._test_token_validation(url, form_html, method, action, raw_req)
                if token_finding:
                    findings.append(token_finding)

        return findings

    def _has_csrf_token(self, form_html: str) -> bool:
        """Check if form has a CSRF token field."""
        csrf_patterns = [
            r'name=["\']?csrf', r'name=["\']?_token',
            r'name=["\']?authenticity_token', r'name=["\']?__RequestVerificationToken',
            r'name=["\']?csrfmiddlewaretoken', r'name=["\']?_csrf',
            r'name=["\']?anti.forgery', r'name=["\']?__VIEWSTATE',
            r'name=["\']?nonce', r'name=["\']?_wpnonce',
            r'x-csrf-token', r'x-xsrf-token',
        ]
        for pattern in csrf_patterns:
            if re.search(pattern, form_html, re.IGNORECASE):
                return True
        return False

    def _has_samesite_cookie(self, resp) -> bool:
        """Check if response sets SameSite cookies."""
        # httpx stores multi-value headers in resp.headers.multi_items()
        cookie_values = []
        try:
            for name, value in resp.headers.multi_items():
                if name.lower() == "set-cookie":
                    cookie_values.append(value)
        except Exception:
            val = resp.headers.get("set-cookie", "")
            if val:
                cookie_values.append(val)
        for cookie_header in cookie_values:
            if "samesite=strict" in cookie_header.lower() or "samesite=lax" in cookie_header.lower():
                return True
        return False

    def _requires_custom_header(self, body: str) -> bool:
        """Check if JS adds custom headers (X-Requested-With, etc.)."""
        return bool(re.search(r'X-Requested-With|X-CSRF|x-xsrf-token', body, re.IGNORECASE))

    def _assess_severity(self, form_html: str, url: str) -> str:
        """Assess CSRF severity based on form purpose."""
        high_risk = ["password", "email", "delete", "admin", "transfer",
                     "payment", "withdraw", "account", "settings", "role"]
        form_lower = form_html.lower() + url.lower()
        if any(kw in form_lower for kw in high_risk):
            return Severity.HIGH
        return Severity.MEDIUM

    async def _test_token_validation(self, url, form_html, method, action, raw_req):
        """Test if CSRF token is actually validated by submitting without/with bad token."""
        # Extract form fields — handle both name-before-value and value-before-name
        fields = {}
        for input_tag in re.finditer(r'<input[^>]*>', form_html, re.IGNORECASE):
            tag_str = input_tag.group(0)
            name_match = re.search(r'name=["\']([^"\']+)["\']', tag_str, re.IGNORECASE)
            value_match = re.search(r'value=["\']([^"\']*)["\']', tag_str, re.IGNORECASE)
            if name_match:
                fields[name_match.group(1)] = value_match.group(1) if value_match else ""
        # Replace CSRF token with empty/bad value
        for key in list(fields.keys()):
            if any(t in key.lower() for t in ["csrf", "token", "_csrf", "nonce"]):
                fields[key] = "INVALID_TOKEN_TEST"

        if not fields:
            return None

        try:
            target_url = action if action.startswith("http") else url
            # Submit all form fields (not just one) to properly test token validation
            resp, _ = await self.client.post(target_url, data=fields)
            if resp and resp.status_code in (200, 301, 302):
                # A redirect to login/error is usually a rejection, not a bypass.
                location = (resp.headers.get("location", "") or "").lower()
                body = (resp.text or "").lower()
                reject_markers = [
                    "login", "signin", "sign-in", "forbidden", "denied",
                    "invalid", "expired", "csrf", "token mismatch", "unauthorized",
                ]
                if any(marker in location for marker in reject_markers):
                    return None
                if any(marker in body for marker in reject_markers):
                    return None

                return self.make_finding(
                    title="CSRF Token Not Validated",
                    vuln_type="csrf_token_bypass",
                    severity=Severity.HIGH,
                    url=url, parameter="csrf_token",
                    method="POST",
                    payload=str(fields),
                    evidence=f"Form accepted invalid CSRF token (HTTP {resp.status_code})",
                    request=raw_req,
                    response=resp.text[:300] if resp else "",
                    cwe_id="CWE-352",
                    owasp_category="A01:2021 - Broken Access Control",
                    description="The application has a CSRF token field but does not validate it server-side.",
                )
        except Exception:
            pass
        return None
