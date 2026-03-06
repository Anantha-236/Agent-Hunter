"""IDOR / Broken Access Control Scanner"""
from __future__ import annotations
import asyncio
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

ID_PARAMS = ["id","user_id","userId","account_id","order_id","profile_id",
             "doc_id","file_id","record_id","item_id","uid","pid"]

class IDORScanner(BaseScanner):
    name = "idor_scanner"
    description = "Detects IDOR and broken horizontal access control"
    tags = ["authz", "idor", "owasp-a01"]

    async def run(self, state: ScanState) -> List[Finding]:
        tasks = [self._test_idor(url, param)
                 for url, params in state.target.discovered_params.items()
                 for param in params if param.lower() in ID_PARAMS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, Finding)]

    async def _test_idor(self, url, param):
        resp1, raw1 = await self.test_payload(url, "GET", param, "1", inject_in="query")
        resp2, raw2 = await self.test_payload(url, "GET", param, "2", inject_in="query")
        # Use a very unlikely ID to establish a "not found" baseline
        resp_base, _ = await self.test_payload(url, "GET", param, "9999999999", inject_in="query")
        if not (resp1 and resp2 and resp_base): return None
        lt, lf, lb = len(resp1.text), len(resp2.text), len(resp_base.text)
        # Non-existent ID should return noticeably smaller or different
        # response than valid IDs. Relaxed: baseline under 1000B or
        # significantly shorter than valid responses.
        baseline_looks_different = lb < 1000 or lb < min(lt, lf) * 0.5
        if (resp1.status_code == 200 and resp2.status_code == 200
                and abs(lt - lf) > 50 and baseline_looks_different):
            return self.make_finding(
                title=f"Potential IDOR — Parameter '{param}'",
                vuln_type="idor", severity=Severity.HIGH,
                url=url, parameter=param, method="GET", payload="1 vs 2",
                evidence=f"ID=1 returns {lt}B, ID=2 returns {lf}B (non-existent ID returns {lb}B)",
                request=raw1, response=resp1.text[:300],
                cwe_id="CWE-639", owasp_category="A01:2021 - Broken Access Control",
                description=f"Different responses for different IDs without auth check.",
                poc_steps=["1. Auth as User A", f"2. Change '{param}' to another user ID",
                           "3. Confirm access to User B's data"],
            )
        return None
