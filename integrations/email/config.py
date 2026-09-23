"""Secret-safe SMTP settings and strict recipient policy."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from email.utils import parseaddr

from config.settings import (
    SMTP_DEFAULT_MAX_ATTACHMENT_BYTES,
    SMTP_DEFAULT_PORT,
)


class EmailConfigError(ValueError):
    """Raised when SMTP runtime configuration is missing or insecure."""


class EmailPolicyError(ValueError):
    """Raised when an email address violates the local recipient policy."""


@dataclass(frozen=True, repr=False)
class SecretStr:
    _value: str

    def get_secret_value(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretStr('**********')"

    __str__ = __repr__


_LOCAL_PART = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_ENV_KEYS = (
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_STARTTLS",
    "SMTP_REPORT_FROM",
    "SMTP_REPORT_TO",
    "SMTP_RECIPIENT_ALLOWLIST",
    "SMTP_MAX_ATTACHMENT_BYTES",
)


def _reject_controls(value: str, field: str) -> str:
    candidate = (value or "").strip()
    if not candidate:
        raise EmailConfigError(f"{field} is required")
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        raise EmailConfigError(f"{field} contains control characters")
    return candidate


def normalize_mailbox(value: str) -> str:
    """Return a lower-case mailbox with an IDNA-normalized domain."""
    if not value or "\r" in value or "\n" in value:
        raise EmailPolicyError("mailbox contains a header injection or is empty")
    raw_value = value.strip()
    if "<" not in raw_value and any(char.isspace() for char in raw_value):
        raise EmailPolicyError(f"malformed mailbox: {value!r}")
    try:
        _display_name, address = parseaddr(raw_value, strict=True)
    except TypeError:  # pragma: no cover - compatibility with older Python
        _display_name, address = parseaddr(raw_value)
    if any(char.isspace() for char in address):
        raise EmailPolicyError(f"malformed mailbox: {value!r}")
    if not address or address.count("@") != 1:
        raise EmailPolicyError(f"malformed mailbox: {value!r}")
    local, domain = address.rsplit("@", 1)
    local = local.strip().lower()
    domain = domain.strip().rstrip(".").lower()
    if not local or len(local) > 64 or not _LOCAL_PART.fullmatch(local):
        raise EmailPolicyError(f"malformed mailbox local part: {value!r}")
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise EmailPolicyError(f"malformed mailbox local part: {value!r}")
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise EmailPolicyError(f"malformed mailbox domain: {value!r}") from exc
    labels = ascii_domain.split(".")
    if (
        not ascii_domain
        or len(ascii_domain) > 253
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        )
    ):
        raise EmailPolicyError(f"malformed mailbox domain: {value!r}")
    return f"{local}@{ascii_domain}"


def _normalize_many(values) -> tuple[str, ...]:
    normalized = []
    seen = set()
    for value in values:
        mailbox = normalize_mailbox(str(value))
        if mailbox not in seen:
            normalized.append(mailbox)
            seen.add(mailbox)
    return tuple(normalized)


def validate_recipients(recipients, allowlist) -> tuple[str, ...]:
    normalized_allowlist = set(_normalize_many(allowlist))
    normalized_recipients = _normalize_many(recipients)
    if not normalized_recipients:
        raise EmailPolicyError("at least one report recipient is required")
    outside = [
        recipient for recipient in normalized_recipients
        if recipient not in normalized_allowlist
    ]
    if outside:
        raise EmailPolicyError(
            f"recipient is not allowlisted: {', '.join(outside)}"
        )
    return normalized_recipients


def _csv_env(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    if "\r" in raw or "\n" in raw:
        raise EmailPolicyError(f"{name} contains header injection")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True, repr=False)
class SmtpSettings:
    host: str
    port: int
    username: str
    password: SecretStr
    starttls: bool
    report_from: str
    report_to: tuple[str, ...]
    recipient_allowlist: tuple[str, ...]
    max_attachment_bytes: int

    @staticmethod
    def environment_keys() -> tuple[str, ...]:
        return _ENV_KEYS

    @classmethod
    def from_env(cls, *, required: bool = False) -> "SmtpSettings | None":
        configured = any(os.getenv(key, "").strip() for key in _ENV_KEYS)
        if not configured and not required:
            return None

        host = _reject_controls(os.getenv("SMTP_HOST", ""), "SMTP_HOST")
        if "://" in host or any(char.isspace() for char in host):
            raise EmailConfigError("SMTP_HOST must be a hostname, not a URL")
        username = _reject_controls(
            os.getenv("SMTP_USERNAME", ""), "SMTP_USERNAME"
        )
        password = _reject_controls(
            os.getenv("SMTP_PASSWORD", ""), "SMTP_PASSWORD"
        )

        try:
            port = int(os.getenv("SMTP_PORT", str(SMTP_DEFAULT_PORT)))
        except ValueError as exc:
            raise EmailConfigError("SMTP_PORT must be a valid port") from exc
        if not 1 <= port <= 65535:
            raise EmailConfigError("SMTP_PORT must be between 1 and 65535")

        starttls_value = os.getenv("SMTP_STARTTLS", "true").strip().lower()
        if starttls_value not in {"true", "1", "yes", "on"}:
            raise EmailConfigError("SMTP_STARTTLS must be true; insecure SMTP is rejected")

        try:
            max_attachment_bytes = int(os.getenv(
                "SMTP_MAX_ATTACHMENT_BYTES",
                str(SMTP_DEFAULT_MAX_ATTACHMENT_BYTES),
            ))
        except ValueError as exc:
            raise EmailConfigError(
                "SMTP_MAX_ATTACHMENT_BYTES must be an integer"
            ) from exc
        if max_attachment_bytes <= 0:
            raise EmailConfigError(
                "SMTP_MAX_ATTACHMENT_BYTES attachment limit must be positive"
            )

        report_from = normalize_mailbox(os.getenv("SMTP_REPORT_FROM", ""))
        allowlist = _normalize_many(_csv_env("SMTP_RECIPIENT_ALLOWLIST"))
        recipients = validate_recipients(_csv_env("SMTP_REPORT_TO"), allowlist)

        return cls(
            host=host,
            port=port,
            username=username,
            password=SecretStr(password),
            starttls=True,
            report_from=report_from,
            report_to=recipients,
            recipient_allowlist=allowlist,
            max_attachment_bytes=max_attachment_bytes,
        )

    def __repr__(self) -> str:
        return (
            "SmtpSettings("
            f"host={self.host!r}, port={self.port!r}, username={self.username!r}, "
            f"password={self.password!r}, starttls={self.starttls!r}, "
            f"report_from={self.report_from!r}, report_to={self.report_to!r}, "
            f"recipient_allowlist={self.recipient_allowlist!r}, "
            f"max_attachment_bytes={self.max_attachment_bytes!r})"
        )
