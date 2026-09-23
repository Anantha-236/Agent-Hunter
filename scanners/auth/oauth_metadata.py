"""Strict, bounded OAuth 2.0/OpenID Connect discovery metadata parser."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from core.models import EvidenceStatus


class OAuthMetadataError(ValueError):
    pass


@dataclass(frozen=True)
class OAuthObservation:
    code: str
    message: str
    severity: str = "info"
    evidence_status: EvidenceStatus = EvidenceStatus.OBSERVED


@dataclass(frozen=True)
class OAuthMetadata:
    source_url: str
    issuer: str | None
    authorization_endpoint: str | None
    token_endpoint: str | None
    jwks_uri: str | None
    code_challenge_methods_supported: tuple[str, ...]
    id_token_signing_alg_values_supported: tuple[str, ...]
    blocked_endpoints: tuple[str, ...]
    observations: tuple[OAuthObservation, ...]

    @classmethod
    def parse(
        cls,
        raw: str | bytes,
        source_url: str,
        *,
        expected_issuer: str | None = None,
        max_bytes: int = 262_144,
    ) -> "OAuthMetadata":
        source = _absolute_url(source_url)
        if source is None:
            raise OAuthMetadataError("source URL must be absolute HTTP(S)")
        if isinstance(raw, bytes):
            encoded = raw
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise OAuthMetadataError("metadata must be UTF-8") from exc
        elif isinstance(raw, str):
            text, encoded = raw, raw.encode("utf-8")
        else:
            raise OAuthMetadataError("metadata must be text or bytes")
        if len(encoded) > max_bytes:
            raise OAuthMetadataError(f"metadata exceeds size limit of {max_bytes} bytes")

        duplicates: set[str] = set()

        def pairs_hook(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    duplicates.add(str(key))
                value[key] = item
            return value

        try:
            data = json.loads(text, object_pairs_hook=pairs_hook)
        except json.JSONDecodeError as exc:
            raise OAuthMetadataError("malformed JSON metadata") from exc
        if duplicates:
            raise OAuthMetadataError(f"duplicate JSON keys: {', '.join(sorted(duplicates))}")
        if not isinstance(data, dict):
            raise OAuthMetadataError("metadata root must be an object")

        observations: list[OAuthObservation] = []
        issuer = _absolute_url(data.get("issuer"))
        if data.get("issuer") is not None and issuer is None:
            observations.append(OAuthObservation("malformed_issuer", "Issuer URL is malformed.", "low"))
        expected = _absolute_url(expected_issuer) if expected_issuer else None
        if expected and issuer != expected:
            observations.append(OAuthObservation(
                "issuer_mismatch",
                "Discovery issuer does not match the configured issuer.",
                "medium",
            ))

        endpoints: dict[str, str | None] = {}
        blocked: list[str] = []
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            raw_value = data.get(field)
            normalized = _absolute_url(raw_value)
            if normalized is None or not _same_origin(source, normalized):
                endpoints[field] = None
                if raw_value is not None:
                    blocked.append(_safe_url_label(raw_value))
                    observations.append(OAuthObservation(
                        "blocked_endpoint",
                        f"{field} is malformed or cross-origin and was blocked.",
                        "low",
                    ))
            else:
                endpoints[field] = normalized

        pkce = _string_tuple(data.get("code_challenge_methods_supported"))
        if "S256" not in pkce:
            observations.append(OAuthObservation(
                "pkce_s256_not_advertised",
                "Metadata does not advertise PKCE S256 support.",
                "info",
            ))
        algorithms = _string_tuple(data.get("id_token_signing_alg_values_supported"))
        if any(value.lower() == "none" for value in algorithms):
            observations.append(OAuthObservation(
                "none_alg_advertised",
                "Metadata advertises the unsigned 'none' ID-token algorithm.",
                "medium",
            ))

        return cls(
            source_url=source,
            issuer=issuer,
            authorization_endpoint=endpoints["authorization_endpoint"],
            token_endpoint=endpoints["token_endpoint"],
            jwks_uri=endpoints["jwks_uri"],
            code_challenge_methods_supported=pkce,
            id_token_signing_alg_values_supported=algorithms,
            blocked_endpoints=tuple(dict.fromkeys(blocked)),
            observations=tuple(observations),
        )


def _absolute_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), "", parsed.query, ""))


def _same_origin(left: str, right: str) -> bool:
    def origin(value: str):
        parsed = urlparse(value)
        return (
            parsed.scheme,
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
    return origin(left) == origin(right)


def _safe_url_label(value: Any) -> str:
    text = str(value)[:512]
    parsed = urlparse(text)
    if parsed.hostname:
        port = f":{parsed.port}" if parsed.port else ""
        return urlunparse((parsed.scheme, f"{parsed.hostname}{port}", parsed.path, "", "", ""))
    return text.replace("\r", "").replace("\n", "")


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict.fromkeys(str(item)[:128] for item in value if isinstance(item, str)))
