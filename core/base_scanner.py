"""Base scanner class."""
from __future__ import annotations
import asyncio, logging
from abc import ABC, abstractmethod
from typing import List, Optional, TYPE_CHECKING
from core.models import Finding, ScanState
from utils.http_client import HttpClient

if TYPE_CHECKING:
    from core.waf_engine import WAFEngine
    from core.payload_engine import AdaptivePayloadEngine

class BaseScanner(ABC):
    name: str = "base"
    description: str = ""
    severity_baseline: str = "medium"
    tags: List[str] = []

    def __init__(self, client: HttpClient):
        self.client = client
        self.logger = logging.getLogger(f"scanner.{self.name}")
        # WAF-aware bypass — injected by Orchestrator when a WAF is detected
        self.waf_engine: Optional["WAFEngine"] = None
        self.payload_engine: Optional["AdaptivePayloadEngine"] = None
        self._tech_stack: str = ""
        self._waf_name: str = ""

    @abstractmethod
    async def run(self, state: ScanState) -> List[Finding]: ...

    async def setup(self) -> None: pass
    async def teardown(self) -> None: pass

    def make_finding(self, **kwargs) -> Finding:
        f = Finding(**kwargs)
        f.module = self.name
        return f

    async def test_payload(self, url, method, param, payload,
                           baseline_resp=None, inject_in="query",
                           extra_headers=None):
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
        # Policy-enforce: sanitize payload before sending
        if self.client._policy_enforcer:
            sanitized = self.client._policy_enforcer.sanitize_payload(payload, "")
            if sanitized is None:
                self.logger.debug(f"Policy blocked payload: {payload[:50]}...")
                return None, ""
            payload = sanitized
        try:
            if inject_in == "query":
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                return await self.client.request(method, test_url, extra_headers=extra_headers)
            elif inject_in == "body":
                return await self.client.post(url, data={param: payload}, extra_headers=extra_headers)
            elif inject_in == "header":
                return await self.client.get(url, extra_headers={param: payload, **(extra_headers or {})})
            elif inject_in == "json":
                return await self.client.post(url, json={param: payload}, extra_headers=extra_headers)
            else:
                return await self.client.get(url, extra_headers=extra_headers)
        except Exception as exc:
            self.logger.debug(f"Payload test error ({url}): {exc}")
            return None, ""

    async def test_payload_no_redirect(self, url, method, param, payload,
                                       inject_in="query", extra_headers=None):
        """Like test_payload but does NOT follow redirects — exposes raw 3xx."""
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
        # Policy-enforce: sanitize payload before sending (mirrors test_payload)
        if self.client._policy_enforcer:
            sanitized = self.client._policy_enforcer.sanitize_payload(payload, "")
            if sanitized is None:
                self.logger.debug(f"Policy blocked payload (no-redirect): {payload[:50]}...")
                return None, ""
            payload = sanitized
        try:
            if inject_in == "query":
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                return await self.client.request_no_redirect(method, test_url, extra_headers=extra_headers)
            elif inject_in == "body":
                return await self.client.request_no_redirect("POST", url, data={param: payload}, extra_headers=extra_headers)
            elif inject_in == "header":
                return await self.client.get_no_redirect(url, extra_headers={param: payload, **(extra_headers or {})})
            else:
                return await self.client.get_no_redirect(url, extra_headers=extra_headers)
        except Exception as exc:
            self.logger.debug(f"Payload test (no-redirect) error ({url}): {exc}")
            return None, ""

    # ── WAF-aware payload helpers ─────────────────────────────

    def get_prioritized_payloads(self, payloads: List[str], vuln_type: str) -> List[str]:
        """Reorder payloads using AdaptivePayloadEngine learning data.

        Proven-successful payloads first, known-blocked ones last.
        Falls back to original order when no engine is available.
        """
        if not self.payload_engine:
            return payloads
        return self.payload_engine.prioritize_payloads(
            payloads, vuln_type, tech_stack=self._tech_stack, waf=self._waf_name,
        )

    def get_waf_bypass_variants(self, payload: str, vuln_type: str = "") -> List[str]:
        """Generate WAF bypass variants for a payload.

        Returns [original, variant1, variant2, ...] when a WAF is detected,
        or just [original] when no WAF engine is available.
        """
        if not self.waf_engine or not self._waf_name:
            return [payload]
        return self.waf_engine.apply_bypasses(payload, vuln_type)

    def get_evasion_headers(self) -> dict:
        """Get WAF evasion headers (e.g. X-Forwarded-For spoofing)."""
        if not self.waf_engine or not self._waf_name:
            return {}
        return self.waf_engine.get_evasion_headers()

    def record_payload_result(self, payload: str, vuln_type: str,
                              success: bool, blocked: bool = False) -> None:
        """Record whether a payload worked — feeds the adaptive learning loop."""
        if self.payload_engine:
            self.payload_engine.record_result(
                payload, vuln_type, success=success, blocked=blocked,
                tech_stack=self._tech_stack, waf=self._waf_name,
            )
        if blocked and self.waf_engine:
            self.waf_engine.record_block(payload)

    async def test_payload_with_bypass(self, url, method, param, payload,
                                       vuln_type: str = "",
                                       baseline_resp=None,
                                       inject_in="query",
                                       extra_headers=None):
        """Like test_payload, but tries WAF bypass variants on 403/block.

        1. Tries the original payload.
        2. If blocked (403/406/503 or empty response), tries bypass variants.
        3. Records success/failure/block in the AdaptivePayloadEngine.
        Returns (resp, body) from the first successful variant, or (None, "").
        """
        evasion = self.get_evasion_headers()
        merged_headers = {**(extra_headers or {}), **evasion}

        # Try original first
        resp, body = await self.test_payload(
            url, method, param, payload,
            baseline_resp=baseline_resp,
            inject_in=inject_in,
            extra_headers=merged_headers,
        )

        if resp and resp.status_code not in (403, 406, 503):
            self.record_payload_result(payload, vuln_type, success=True)
            return resp, body

        # Original was blocked — try bypass variants
        if resp and resp.status_code in (403, 406, 503):
            self.record_payload_result(payload, vuln_type, success=False, blocked=True)

        variants = self.get_waf_bypass_variants(payload, vuln_type)
        for variant in variants[1:]:  # skip index 0 = original
            try:
                v_resp, v_body = await self.test_payload(
                    url, method, param, variant,
                    baseline_resp=baseline_resp,
                    inject_in=inject_in,
                    extra_headers=merged_headers,
                )
                if v_resp and v_resp.status_code not in (403, 406, 503):
                    self.logger.info(
                        f"WAF bypass succeeded for {self._waf_name}: "
                        f"{payload[:40]}... → variant"
                    )
                    self.record_payload_result(variant, vuln_type, success=True)
                    return v_resp, v_body
                elif v_resp and v_resp.status_code in (403, 406, 503):
                    self.record_payload_result(variant, vuln_type, success=False, blocked=True)
            except Exception:
                pass

        # All variants blocked
        return resp, body or ""
