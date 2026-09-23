"""Bounded, side-effect-free OpenAPI 3 document normalization."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urljoin, urlparse, urlunparse

import yaml


HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


class OpenApiParseError(ValueError):
    """Raised when a document cannot be safely normalized."""


@dataclass(frozen=True)
class OpenApiOperation:
    method: str
    url: str
    operation_id: str = ""
    path_parameters: tuple[str, ...] = ()
    query_parameters: tuple[str, ...] = ()
    source_url: str = ""

    def to_candidate(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "operation_id": self.operation_id,
            "path_parameters": list(self.path_parameters),
            "query_parameters": list(self.query_parameters),
            "source_url": self.source_url,
        }


@dataclass(frozen=True)
class OpenApiDocument:
    source_url: str
    version: str
    operations: tuple[OpenApiOperation, ...]
    blocked_references: tuple[str, ...] = ()
    blocked_servers: tuple[str, ...] = ()

    @classmethod
    def parse(
        cls,
        raw: str | bytes,
        source_url: str,
        *,
        max_bytes: int = 1_048_576,
        max_depth: int = 40,
    ) -> "OpenApiDocument":
        source = _validated_http_url(source_url)
        if isinstance(raw, bytes):
            encoded = raw
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise OpenApiParseError("document must be UTF-8") from exc
        elif isinstance(raw, str):
            text = raw
            encoded = raw.encode("utf-8")
        else:
            raise OpenApiParseError("document must be text or bytes")
        if len(encoded) > max_bytes:
            raise OpenApiParseError(f"document exceeds size limit of {max_bytes} bytes")

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                raise OpenApiParseError("malformed JSON/YAML document") from exc

        if not isinstance(data, dict):
            raise OpenApiParseError("OpenAPI document root must be an object")
        _assert_depth(data, max_depth=max_depth)
        version = data.get("openapi")
        paths = data.get("paths")
        if not isinstance(version, str) or not version.startswith("3."):
            raise OpenApiParseError("OpenAPI 3 version is required")
        if not isinstance(paths, dict):
            raise OpenApiParseError("OpenAPI paths must be an object")

        blocked_references = _external_references(data)
        blocked_servers: list[str] = []
        operations: dict[tuple[str, str], OpenApiOperation] = {}
        root_servers = _server_urls(
            data.get("servers"), source, source, blocked_servers
        )

        for path, path_item in paths.items():
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            if not isinstance(path_item, dict):
                continue
            path_parameters = _parameters(path_item.get("parameters"), data)
            path_servers = _server_urls(
                path_item.get("servers"), source, None, blocked_servers
            ) or root_servers
            for method, operation in path_item.items():
                if str(method).lower() not in HTTP_METHODS or not isinstance(operation, dict):
                    continue
                operation_parameters = path_parameters + _parameters(
                    operation.get("parameters"), data
                )
                servers = _server_urls(
                    operation.get("servers"), source, None, blocked_servers
                ) or path_servers
                for server in servers:
                    url = _join_server_path(server, path)
                    path_names = _names_for(operation_parameters, "path")
                    query_names = _names_for(operation_parameters, "query")
                    normalized = OpenApiOperation(
                        method=str(method).upper(),
                        url=url,
                        operation_id=str(operation.get("operationId") or "")[:256],
                        path_parameters=path_names,
                        query_parameters=query_names,
                        source_url=source,
                    )
                    key = (normalized.method, normalized.url)
                    operations.setdefault(key, normalized)

        return cls(
            source_url=source,
            version=version,
            operations=tuple(operations.values()),
            blocked_references=tuple(dict.fromkeys(blocked_references)),
            blocked_servers=tuple(dict.fromkeys(blocked_servers)),
        )


def _validated_http_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise OpenApiParseError("source URL must be absolute HTTP(S)")
    if parsed.username or parsed.password:
        raise OpenApiParseError("source URL must not contain user info")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def _assert_depth(value: Any, *, max_depth: int) -> None:
    stack = [(value, 1)]
    visited = set()
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise OpenApiParseError(f"document exceeds depth limit of {max_depth}")
        if isinstance(current, (dict, list)):
            identity = id(current)
            if identity in visited:
                raise OpenApiParseError("document contains a recursive alias")
            visited.add(identity)
            children = current.values() if isinstance(current, dict) else current
            stack.extend((child, depth + 1) for child in children)


def _same_origin(left: str, right: str) -> bool:
    def origin(url: str):
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme.lower(), (parsed.hostname or "").lower(), port
    return origin(left) == origin(right)


def _server_urls(
    raw_servers: Any,
    source_url: str,
    fallback_url: str | None,
    blocked: list[str],
) -> tuple[str, ...]:
    if raw_servers is None:
        if fallback_url is None:
            return ()
        parsed = urlparse(fallback_url)
        return (urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")),)
    if not isinstance(raw_servers, list):
        return ()
    allowed: list[str] = []
    for item in raw_servers:
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            continue
        raw_url = item["url"].strip()
        if not raw_url or "{" in raw_url or "}" in raw_url:
            blocked.append(raw_url)
            continue
        absolute = urljoin(source_url, raw_url)
        try:
            normalized = _validated_http_url(absolute)
        except OpenApiParseError:
            blocked.append(raw_url)
            continue
        if not _same_origin(source_url, normalized):
            blocked.append(raw_url)
            continue
        allowed.append(normalized.rstrip("/"))
    return tuple(dict.fromkeys(allowed))


def _join_server_path(server: str, path: str) -> str:
    parsed = urlparse(server)
    base_path = parsed.path.rstrip("/")
    combined = f"{base_path}{path}"
    return urlunparse((parsed.scheme, parsed.netloc, combined or "/", "", "", ""))


def _external_references(value: Any) -> list[str]:
    blocked: list[str] = []
    stack = [value]
    visited = set()
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            identity = id(current)
            if identity in visited:
                continue
            visited.add(identity)
            ref = current.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#/"):
                blocked.append(ref)
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return blocked


def _resolve_local_ref(root: Mapping[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        return None
    current: Any = root
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _parameters(raw: Any, root: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(raw, list):
        return ()
    values: list[Mapping[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        ref = item.get("$ref")
        if isinstance(ref, str):
            resolved = _resolve_local_ref(root, ref)
            if isinstance(resolved, dict):
                item = resolved
            else:
                continue
        values.append(item)
    return tuple(values)


def _names_for(parameters: tuple[Mapping[str, Any], ...], location: str) -> tuple[str, ...]:
    names = []
    for parameter in parameters:
        name = parameter.get("name")
        if parameter.get("in") == location and isinstance(name, str) and name.strip():
            names.append(name.strip()[:128])
    return tuple(dict.fromkeys(names))
