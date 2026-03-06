"""Race Condition Scanner — detects TOCTOU and concurrent request vulnerabilities."""
from __future__ import annotations
import asyncio
import time
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity


class RaceConditionScanner(BaseScanner):
    name = "race_condition"
    description = "Detects race conditions via concurrent request testing"
    tags = ["logic", "race", "owasp-a04"]

    CONCURRENT_REQUESTS = 10
    RACE_KEYWORDS = [
        "coupon", "discount", "redeem", "apply", "promo",
        "transfer", "withdraw", "send", "vote", "like",
        "follow", "invite", "claim", "reward", "bonus",
        "checkout", "order", "purchase", "subscribe",
        "verify", "confirm", "activate", "use",
    ]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        tasks = []

        for url, params in state.target.discovered_params.items():
            url_lower = url.lower()
            if any(kw in url_lower for kw in self.RACE_KEYWORDS):
                tasks.append(self._test_race(url, params, "keyword_match"))

        # Test POST endpoints by checking response consistency
        for url in state.target.discovered_urls[:20]:
            url_lower = url.lower()
            if any(kw in url_lower for kw in self.RACE_KEYWORDS):
                tasks.append(self._test_get_race(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)

        return findings

    async def _test_race(self, url: str, params: list, reason: str) -> Finding | None:
        """Send N concurrent identical requests and analyze responses."""
        # Build request with existing params
        test_params = {p: "1" for p in params[:3]}

        async def single_request():
            start = time.monotonic()
            try:
                resp, _ = await self.client.post(url, data=test_params)
                elapsed = time.monotonic() - start
                if resp:
                    return {
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "time": elapsed,
                        "body_hash": hash(resp.text[:500]),
                    }
            except Exception:
                pass
            return None

        # Fire concurrent requests
        results = await asyncio.gather(
            *[single_request() for _ in range(self.CONCURRENT_REQUESTS)],
            return_exceptions=True,
        )
        valid = [r for r in results if isinstance(r, dict)]

        if len(valid) < 3:
            return None

        return self._analyze_race_results(url, valid, reason)

    async def _test_get_race(self, url: str) -> Finding | None:
        """Test GET endpoint for race conditions."""
        async def single_request():
            start = time.monotonic()
            try:
                resp, _ = await self.client.get(url)
                elapsed = time.monotonic() - start
                if resp:
                    return {
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "time": elapsed,
                        "body_hash": hash(resp.text[:500]),
                    }
            except Exception:
                pass
            return None

        results = await asyncio.gather(
            *[single_request() for _ in range(self.CONCURRENT_REQUESTS)],
            return_exceptions=True,
        )
        valid = [r for r in results if isinstance(r, dict)]

        if len(valid) < 3:
            return None

        return self._analyze_race_results(url, valid, "get_race")

    def _analyze_race_results(self, url, results, reason) -> Finding | None:
        """Analyze concurrent request results for race condition indicators."""
        statuses = [r["status"] for r in results]
        lengths = [r["length"] for r in results]
        hashes = [r["body_hash"] for r in results]

        # Indicator 1: Mixed success/failure (e.g., 200 + 409/429)
        unique_statuses = set(statuses)
        success_count = sum(1 for s in statuses if s in (200, 201, 302))
        has_mixed_status = len(unique_statuses) > 1 and success_count > 1

        # Indicator 2: All succeeded when only one should (e.g., all 200 for coupon apply)
        all_success = all(s in (200, 201, 302) for s in statuses)

        # Indicator 3: Response body varies (different outcomes)
        unique_hashes = len(set(hashes))
        has_varied_responses = unique_hashes > 1 and unique_hashes < len(hashes)

        # Indicator 4: Inconsistent response lengths (sign of race)
        length_variance = max(lengths) - min(lengths) if lengths else 0
        significant_variance = length_variance > 100

        if has_mixed_status or (has_varied_responses and significant_variance):
            method = "POST" if reason == "keyword_match" else "GET"
            return self.make_finding(
                title=f"Potential Race Condition Detected",
                vuln_type="race_condition",
                severity=Severity.MEDIUM,
                url=url,
                method=method,
                parameter="concurrent_requests",
                payload=f"{self.CONCURRENT_REQUESTS} simultaneous {method} requests",
                evidence=(
                    f"Sent {len(results)} concurrent requests. "
                    f"Status codes: {dict((s, statuses.count(s)) for s in unique_statuses)}. "
                    f"Unique responses: {unique_hashes}/{len(results)}. "
                    f"Response length variance: {length_variance} bytes. "
                    f"Detection reason: {reason}"
                ),
                response=f"Status distribution: {dict((s, statuses.count(s)) for s in unique_statuses)}",
                cwe_id="CWE-362",
                owasp_category="A04:2021 - Insecure Design",
                description=(
                    f"The endpoint shows inconsistent behavior under concurrent access, "
                    f"suggesting a Time-of-Check-to-Time-of-Use (TOCTOU) vulnerability. "
                    f"This may allow duplicate actions (coupon reuse, double payments, etc.)."
                ),
                poc_steps=[
                    f"1. Prepare a valid request to {url}",
                    f"2. Send {self.CONCURRENT_REQUESTS} identical requests simultaneously",
                    "3. Observe mixed response codes or multiple success responses",
                    "4. Verify if the action was performed multiple times (e.g., balance changed, coupon applied twice)",
                ],
            )

        return None
