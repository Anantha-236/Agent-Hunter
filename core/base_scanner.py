"""Base scanner class."""
from __future__ import annotations
import asyncio, logging
from abc import ABC, abstractmethod
from typing import List, Optional
from core.models import Finding, ScanState
from utils.http_client import HttpClient

class BaseScanner(ABC):
    name: str = "base"
    description: str = ""
    severity_baseline: str = "medium"
    tags: List[str] = []

    def __init__(self, client: HttpClient):
        self.client = client
        self.logger = logging.getLogger(f"scanner.{self.name}")

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
