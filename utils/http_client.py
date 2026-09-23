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
from core.evidence import EvidenceManifest, Redactor, ResponseFingerprint
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
                 rate_limit: Optional[int] = None, user_agent: Optional[str] = None,
                 evidence_manifest: Optional[EvidenceManifest] = None,
                 redactor: Optional[Redactor] = None):
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
        self.redactor = redactor or Redactor()
        self.evidence_manifest = evidence_manifest

    async def __aenter__(self):
        async def enforce_redirect_scope(request: httpx.Request) -> None:
            # httpx creates a fresh request for every redirect hop. Checking
            # those requests here prevents an in-scope endpoint from bouncing
            # the client to an unapproved host, port, or path.
            self._check_scope(str(request.url))

        kwargs = dict(
            headers=self._session_headers, cookies=self._cookies,
            timeout=self._timeout, verify=self._verify_ssl,
            follow_redirects=self._follow_redirects,
            event_hooks={"request": [enforce_redirect_scope]},
        )
        no_redir_kwargs = dict(
            headers=self._session_headers, cookies=self._cookies,
            timeout=self._timeout, verify=self._verify_ssl,
            follow_redirects=False,
            event_hooks={"request": [enforce_redirect_scope]},
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
        safe_headers = self.redactor.redact(headers)
        for k, v in safe_headers.items():
            raw += f"{k}: {v}\r\n"
        if data is not None or json_body is not None:
            raw += "\r\n[REDACTED BODY]"
        return raw

    def _capture_exchange(
        self,
        method: str,
        url: str,
        response: httpx.Response,
        elapsed_seconds: float,
    ) -> None:
        if self.evidence_manifest is None:
            return
        fingerprint = ResponseFingerprint.from_values(
            status_code=response.status_code,
            headers=response.headers,
            body=response.text,
            elapsed_seconds=elapsed_seconds,
        )
        self.evidence_manifest.add(
            kind="http_exchange",
            value={
                "request": {
                    "method": method.upper(),
                    "url": self.redactor.redact_url(url),
                },
                "response": fingerprint.to_dict(),
            },
            summary=f"{method.upper()} response {response.status_code}",
        )

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
                    started = time.monotonic()
                    resp = await self._client.request(
                        method=method, url=url, params=params,
                        headers=merged, data=data, json=json,
                        content=content,
                    )
                    elapsed = time.monotonic() - started
                    safe_url = self.redactor.redact_url(url)
                    self.request_log.append((method, safe_url, resp.status_code))
                    self._capture_exchange(method, url, resp, elapsed)
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
                    started = time.monotonic()
                    resp = await self._no_redir_client.request(
                        method=method, url=url, params=params,
                        headers=merged, data=data, json=json,
                        content=content,
                    )
                    elapsed = time.monotonic() - started
                    safe_url = self.redactor.redact_url(url)
                    self.request_log.append((method, safe_url, resp.status_code))
                    self._capture_exchange(method, url, resp, elapsed)
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
