"""Passive, bounded OpenAPI discovery scanner."""
from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse, urlunparse

from config.settings import (
    OPENAPI_MAX_DEPTH,
    OPENAPI_MAX_DOCUMENT_BYTES,
    OPENAPI_MAX_PROBES,
    OPENAPI_SPEC_PATHS,
)
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from scanners.recon.openapi_model import OpenApiDocument, OpenApiParseError, OpenApiOperation


class OpenAPIScanner(BaseScanner):
    name = "openapi_scanner"
    description = "Passively discovers bounded OpenAPI 3 operation candidates"
    tags = ["recon", "openapi", "api"]

    def __init__(
        self,
        client,
        *,
        spec_paths: Iterable[str] = OPENAPI_SPEC_PATHS,
        max_probes: int = OPENAPI_MAX_PROBES,
        max_document_bytes: int = OPENAPI_MAX_DOCUMENT_BYTES,
        max_depth: int = OPENAPI_MAX_DEPTH,
    ):
        super().__init__(client)
        self.spec_paths = tuple(_safe_spec_path(path) for path in spec_paths)
        self.max_probes = max(0, int(max_probes))
        self.max_document_bytes = max(1, int(max_document_bytes))
        self.max_depth = max(1, int(max_depth))

    async def run(self, state: ScanState) -> list[Finding]:
        await self.scan(state)
        return []

    async def scan(self, state: ScanState) -> tuple[OpenApiOperation, ...]:
        candidates: dict[tuple[str, str], OpenApiOperation] = {}
        blocked_servers: list[str] = []
        blocked_references: list[str] = []
        parse_errors: list[dict[str, str]] = []

        for source_url in self._probe_urls(state)[: self.max_probes]:
            try:
                response, _ = await self.client.get(source_url)
            except Exception as exc:
                parse_errors.append({"source_url": source_url, "reason": type(exc).__name__})
                continue
            if response is None or response.status_code != 200:
                continue
            content = getattr(response, "content", None)
            raw = content if isinstance(content, bytes) else response.text
            if len(raw if isinstance(raw, bytes) else raw.encode("utf-8")) > self.max_document_bytes:
                parse_errors.append({"source_url": source_url, "reason": "document exceeds size limit"})
                continue
            try:
                document = OpenApiDocument.parse(
                    raw,
                    source_url,
                    max_bytes=self.max_document_bytes,
                    max_depth=self.max_depth,
                )
            except OpenApiParseError as exc:
                parse_errors.append({"source_url": source_url, "reason": str(exc)[:200]})
                continue

            blocked_servers.extend(document.blocked_servers)
            blocked_references.extend(document.blocked_references)
            for operation in document.operations:
                if state.target.scope and not state.target.scope.is_in_scope(operation.url):
                    blocked_servers.append(operation.url)
                    continue
                if not _safe_candidate(operation):
                    blocked_servers.append(operation.url)
                    continue
                candidates.setdefault((operation.method, operation.url), operation)

        normalized = tuple(candidates.values())
        state.target.metadata["openapi_candidates"] = [
            operation.to_candidate() for operation in normalized
        ]
        state.target.metadata["openapi_blocked_servers"] = list(
            dict.fromkeys(blocked_servers)
        )
        state.target.metadata["openapi_blocked_references"] = list(
            dict.fromkeys(blocked_references)
        )
        state.target.metadata["openapi_parse_errors"] = parse_errors
        # Candidates intentionally remain metadata.  A later policy decision
        # must promote one before any operation is executed.
        return normalized

    def _probe_urls(self, state: ScanState) -> list[str]:
        parsed = urlparse(state.target.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return []
        origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        urls = []
        for path in self.spec_paths:
            url = f"{origin}{path}"
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            urls.append(url)
        return urls


def _safe_spec_path(path: str) -> str:
    value = str(path).strip()
    if not value.startswith("/") or any(ord(char) < 32 for char in value):
        raise ValueError(f"invalid OpenAPI spec path: {path!r}")
    if "?" in value or "#" in value or "\\" in value:
        raise ValueError(f"invalid OpenAPI spec path: {path!r}")
    return value


def _safe_candidate(operation: OpenApiOperation) -> bool:
    parsed = urlparse(operation.url)
    return bool(
        parsed.scheme in {"http", "https"}
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and not any(ord(char) < 32 for char in operation.url)
    )
