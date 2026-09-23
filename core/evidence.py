"""Secret-safe evidence capture and vulnerability-specific validation."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.models import EvidenceRef, EvidenceStatus


_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "cookies",
    "set-cookie",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "x-api-key",
    "otp",
    "totp",
    "cvv",
    "card",
    "card_number",
    "body",
    "request_body",
}
_SENSITIVE_QUERY_KEYS = _SENSITIVE_KEYS.difference({"body", "request_body"})
_SAFE_RESPONSE_HEADERS = {
    "age",
    "cache-control",
    "content-length",
    "content-type",
    "etag",
    "expires",
    "location",
    "pragma",
    "vary",
    "x-cache",
}


class Redactor:
    """Remove secrets recursively before data crosses a persistence boundary."""

    _assignment = re.compile(
        r"(?i)(\b(?:password|passwd|pwd|token|secret|otp|totp|cookie|session|"
        r"authorization|api[_-]?key|cvv|card(?:_number)?)\b[\"']?\s*[:=]\s*)"
        r"(?:[\"'])?([^&\s,;\"'}]+)"
    )
    _bearer = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+")

    @staticmethod
    def _key(key: Any) -> str:
        return str(key).strip().lower().replace("-", "_")

    def redact_url(self, value: str) -> str:
        try:
            parsed = urlsplit(value)
        except ValueError:
            return self.redact_text(value)
        if not parsed.scheme or not parsed.netloc:
            return self.redact_text(value)
        sanitized_query = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            sanitized_query.append(
                (key, _REDACTED if self._key(key) in _SENSITIVE_QUERY_KEYS else self.redact_text(item))
            )
        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(sanitized_query, doseq=True),
                "",
            )
        )

    def redact_text(self, value: str) -> str:
        if not value:
            return value
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                decoded = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                pass
            else:
                return json.dumps(
                    self.redact(decoded),
                    sort_keys=True,
                    separators=(",", ":"),
                )
        result = self._bearer.sub(r"\1" + _REDACTED, value)
        return self._assignment.sub(r"\1" + _REDACTED, result)

    def redact(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            sanitized: dict[str, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                if self._key(key) in _SENSITIVE_KEYS:
                    sanitized[key_text] = _REDACTED
                else:
                    sanitized[key_text] = self.redact(item)
            return sanitized
        if isinstance(value, (list, tuple, set)):
            return [self.redact(item) for item in value]
        if isinstance(value, str):
            return self.redact_text(value)
        return value


def _length_bucket(length: int) -> str:
    if length == 0:
        return "empty"
    if length < 256:
        return "small"
    if length < 1024:
        return "medium"
    if length < 16384:
        return "large"
    return "very_large"


def _timing_bucket(seconds: float) -> str:
    if seconds < 0.1:
        return "very_fast"
    if seconds < 1.0:
        return "normal"
    if seconds < 5.0:
        return "slow"
    return "very_slow"


@dataclass(frozen=True)
class ResponseFingerprint:
    status_code: int
    content_type: str
    body_digest: str
    body_length_bucket: str
    timing_bucket: str
    headers: dict[str, str]

    @classmethod
    def from_values(
        cls,
        *,
        status_code: int,
        headers: Mapping[str, str],
        body: str,
        elapsed_seconds: float,
    ) -> "ResponseFingerprint":
        normalized_body = " ".join((body or "").split())
        lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        redactor = Redactor()
        safe_headers = {
            key: (
                redactor.redact_url(value)
                if key == "location"
                else redactor.redact_text(value)
            )
            for key, value in lower_headers.items()
            if key in _SAFE_RESPONSE_HEADERS
        }
        return cls(
            status_code=int(status_code),
            content_type=lower_headers.get("content-type", "").split(";", 1)[0].strip().lower(),
            body_digest=hashlib.sha256(normalized_body.encode("utf-8")).hexdigest(),
            body_length_bucket=_length_bucket(len(body or "")),
            timing_bucket=_timing_bucket(max(0.0, elapsed_seconds)),
            headers=safe_headers,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "content_type": self.content_type,
            "body_digest": self.body_digest,
            "body_length_bucket": self.body_length_bucket,
            "timing_bucket": self.timing_bucket,
            "headers": dict(self.headers),
        }


@dataclass(frozen=True)
class EvidenceRule:
    name: str
    decisive: bool
    required_controls: tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidationResult:
    status: EvidenceStatus
    confidence: float
    reason: str
    validator_evidence_ids: tuple[str, ...] = ()


class EvidenceValidator:
    def validate(
        self,
        baseline: ResponseFingerprint,
        probe: ResponseFingerprint,
        controls: Mapping[str, bool],
        rule: EvidenceRule,
        validator_evidence_ids: tuple[str, ...] = (),
    ) -> ValidationResult:
        changed = baseline.body_digest != probe.body_digest
        if not changed:
            return ValidationResult(
                EvidenceStatus.REFUTED,
                0.05,
                "Probe is semantically identical to the baseline.",
            )

        missing = [
            name for name in rule.required_controls if not controls.get(name, False)
        ]
        if missing:
            return ValidationResult(
                EvidenceStatus.UNRESOLVED,
                0.35,
                "Required controls did not pass: " + ", ".join(missing),
            )

        if not rule.decisive:
            return ValidationResult(
                EvidenceStatus.SUSPECTED,
                0.45,
                f"{rule.name} is a heuristic signal, not decisive proof.",
            )

        if not validator_evidence_ids:
            return ValidationResult(
                EvidenceStatus.UNRESOLVED,
                0.6,
                "Decisive rule passed but validator evidence was not recorded.",
            )

        return ValidationResult(
            EvidenceStatus.CONFIRMED,
            0.95,
            f"{rule.name} passed with all required controls.",
            tuple(validator_evidence_ids),
        )


@dataclass
class EvidenceManifest:
    redactor: Redactor = field(default_factory=Redactor)
    _entries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add(self, *, kind: str, value: Any, summary: str = "") -> EvidenceRef:
        sanitized = self.redactor.redact(value)
        canonical = json.dumps(
            sanitized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        evidence_id = str(uuid.uuid4())
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        captured_at = datetime.now(UTC)
        self._entries[evidence_id] = {
            "kind": kind,
            "captured_at": captured_at.isoformat(),
            "digest": digest,
            "redacted": True,
            "summary": self.redactor.redact_text(summary),
            "value": sanitized,
        }
        return EvidenceRef(
            evidence_id=evidence_id,
            kind=kind,
            captured_at=captured_at,
            digest=digest,
            redacted=True,
            summary=self.redactor.redact_text(summary),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"entries": dict(self._entries)}
