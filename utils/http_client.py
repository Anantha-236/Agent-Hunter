"""Async HTTP client with scope enforcement and rate limiting."""
from __future__ import annotations
import asyncio, time, logging
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
import httpx
from config.settings import (
    HTTP_TIMEOUT, HTTP_MAX_RETRIES, HTTP_CONCURRENCY,
    HTTP_DELAY_BETWEEN_REQUESTS, DEFAULT_HEADERS,
)
from core.models import Scope

logger = logging.getLogger(__name__)


class ScopeViolationError(Exception):
    pass


class RateLimiter:
    def __init__(self, delay: float = HTTP_DELAY_BETWEEN_REQUESTS):
        self._delay = delay
        self._last_request: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._delay - (now - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()


class HttpClient:
    def __init__(self, scope=None, headers=None, cookies=None, proxy=None,
                 verify_ssl=True, policy_enforcer=None, concurrency: Optional[int] = None,
                 timeout: Optional[int] = None, follow_redirects: bool = True,
                 rate_limit: Optional[int] = None, user_agent: Optional[str] = None):
        self._scope = scope
        self._policy_enforcer = policy_enforcer
        delay = HTTP_DELAY_BETWEEN_REQUESTS
        if rate_limit and rate_limit > 0:
            delay = 1.0 / rate_limit
        self._rate_limiter = RateLimiter(delay=delay)
        self._semaphore = asyncio.Semaphore(concurrency or HTTP_CONCURRENCY)
        self._session_headers = {**DEFAULT_HEADERS}
        if user_agent:
            self._session_headers["User-Agent"] = user_agent
        self._session_headers.update(headers or {})
        self._cookies = cookies or {}
        self._proxy = proxy
        self._verify_ssl = verify_ssl
        self._timeout = timeout or HTTP_TIMEOUT
        self._follow_redirects = follow_redirects
        self._client = None
        self._no_redir_client = None
        self.request_log = []

    async def __aenter__(self):
        kwargs = dict(
            headers=self._session_headers, cookies=self._cookies,
            timeout=self._timeout, verify=self._verify_ssl,
            follow_redirects=self._follow_redirects,
        )
        no_redir_kwargs = dict(
            headers=self._session_headers, cookies=self._cookies,
            timeout=self._timeout, verify=self._verify_ssl,
            follow_redirects=False,
        )
        if self._proxy:
            kwargs["proxy"] = self._proxy
            no_redir_kwargs["proxy"] = self._proxy
        self._client = httpx.AsyncClient(**kwargs)
        self._no_redir_client = httpx.AsyncClient(**no_redir_kwargs)
        return self

    async def __aexit__(self, *_):
        if self._no_redir_client:
            await self._no_redir_client.aclose()
        if self._client:
            await self._client.aclose()

    def _check_scope(self, url: str) -> None:
        if self._scope and not self._scope.is_in_scope(url):
            raise ScopeViolationError(f"OUT-OF-SCOPE: {url}")
        if self._policy_enforcer:
            allowed, reason = self._policy_enforcer.is_url_allowed(url)
            if not allowed:
                raise ScopeViolationError(f"POLICY-BLOCKED: {reason}")

    def _build_raw_request(self, method, url, headers, data, json_body) -> str:
        parsed = urlparse(url)
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        raw = f"{method} {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\n"
        for k, v in headers.items():
            raw += f"{k}: {v}\r\n"
        if data:
            raw += f"\r\n{data}"
        elif json_body:
            import json as _json
            raw += f"\r\n{_json.dumps(json_body)}"
        return raw

    async def request(self, method, url, params=None, headers=None, data=None,
                      json=None, content=None, extra_headers=None, retries=HTTP_MAX_RETRIES):
        self._check_scope(url)
        merged = {**self._session_headers, **(headers or {}), **(extra_headers or {})}
        raw_req = self._build_raw_request(method, url, merged, data, json)
        last_exc = None
        for attempt in range(retries + 1):
            try:
                await self._rate_limiter.acquire()
                async with self._semaphore:
                    resp = await self._client.request(
                        method=method, url=url, params=params,
                        headers=merged, data=data, json=json,
                        content=content,
                    )
                    self.request_log.append((method, url, resp.status_code))
                    return resp, raw_req
            except ScopeViolationError:
                raise
            except Exception as exc:
                last_exc = exc
                if attempt < retries:
                    await asyncio.sleep(2 ** attempt)
        logger.warning(f"All retries exhausted for {url}: {last_exc}")
        return None, raw_req

    async def request_no_redirect(self, method, url, params=None, headers=None,
                                   data=None, json=None, content=None,
                                   extra_headers=None, retries=HTTP_MAX_RETRIES):
        """Like request() but does NOT follow redirects — exposes raw 3xx responses."""
        self._check_scope(url)
        merged = {**self._session_headers, **(headers or {}), **(extra_headers or {})}
        raw_req = self._build_raw_request(method, url, merged, data, json)
        last_exc = None
        for attempt in range(retries + 1):
            try:
                await self._rate_limiter.acquire()
                async with self._semaphore:
                    resp = await self._no_redir_client.request(
                        method=method, url=url, params=params,
                        headers=merged, data=data, json=json,
                        content=content,
                    )
                    self.request_log.append((method, url, resp.status_code))
                    return resp, raw_req
            except ScopeViolationError:
                raise
            except Exception as exc:
                last_exc = exc
                if attempt < retries:
                    await asyncio.sleep(2 ** attempt)
        logger.warning(f"All retries exhausted (no-redirect) for {url}: {last_exc}")
        return None, raw_req

    async def get(self, url, params=None, **kw):
        return await self.request("GET", url, params=params, **kw)

    async def get_no_redirect(self, url, params=None, **kw):
        """GET without following redirects."""
        return await self.request_no_redirect("GET", url, params=params, **kw)

    async def post(self, url, data=None, json=None, **kw):
        return await self.request("POST", url, data=data, json=json, **kw)

    async def put(self, url, **kw):
        return await self.request("PUT", url, **kw)

    async def delete(self, url, **kw):
        return await self.request("DELETE", url, **kw)

    async def options(self, url, **kw):
        return await self.request("OPTIONS", url, **kw)
