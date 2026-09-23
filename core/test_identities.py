"""In-memory synthetic identities for controlled authorization testing."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Mapping


_FINGERPRINT_KEY = os.urandom(32)
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


@dataclass(frozen=True)
class TestIdentity:
    """A label plus a provider whose secret headers never enter serialized state."""

    __test__ = False

    label: str
    sanitized_headers_provider: Callable[[], Mapping[str, str]] = field(repr=False)

    def __post_init__(self):
        label = self.label.strip()
        if not label or len(label) > 64:
            raise ValueError("test identity label must be 1-64 characters")
        if any(ord(char) < 32 for char in label):
            raise ValueError("test identity label contains control characters")
        object.__setattr__(self, "label", label)
        if not callable(self.sanitized_headers_provider):
            raise TypeError("sanitized_headers_provider must be callable")

    def headers(self) -> dict[str, str]:
        supplied = self.sanitized_headers_provider()
        if not isinstance(supplied, Mapping):
            raise TypeError("identity provider must return a header mapping")
        headers: dict[str, str] = {}
        for raw_name, raw_value in supplied.items():
            name, value = str(raw_name), str(raw_value)
            if not _HEADER_NAME.fullmatch(name):
                raise ValueError("identity provider returned an invalid header name")
            if any(char in value for char in ("\r", "\n", "\x00")):
                raise ValueError("identity provider returned an invalid header value")
            headers[name] = value
        return headers

    @property
    def fingerprint(self) -> str:
        canonical = "\n".join(
            f"{name.lower()}:{value}" for name, value in sorted(self.headers().items())
        ).encode("utf-8")
        return hmac.new(_FINGERPRINT_KEY, canonical, hashlib.sha256).hexdigest()

    def to_dict(self) -> dict[str, str]:
        return {"label": self.label, "fingerprint": self.fingerprint}


def secret_state_fingerprint(values: Mapping[str, str]) -> str:
    canonical = "\n".join(
        f"{str(name).lower()}:{str(value)}" for name, value in sorted(values.items())
    ).encode("utf-8")
    return hmac.new(_FINGERPRINT_KEY, canonical, hashlib.sha256).hexdigest()
