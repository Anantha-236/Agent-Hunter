"""Machine-readable safety and evidence contracts for scanner modules."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping


class TrafficClass(str, Enum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    STATE_CHANGING = "state_changing"
    DISRUPTIVE = "disruptive"


class CapabilityError(ValueError):
    """Raised when a scanner has no complete capability contract."""


@dataclass(frozen=True)
class ScannerCapability:
    module: str
    version: str
    traffic_class: TrafficClass
    request_cost: int
    max_concurrency: int
    required_permissions: tuple[str, ...]
    positive_controls: tuple[str, ...]
    negative_controls: tuple[str, ...]
    fallback_module: str | None
    idempotent: bool

    def validate(self) -> None:
        if not self.module.strip():
            raise CapabilityError("capability module name is required")
        if not self.version.strip():
            raise CapabilityError(f"{self.module}: version is required")
        if self.request_cost < 0:
            raise CapabilityError(f"{self.module}: request cost cannot be negative")
        if self.max_concurrency < 1:
            raise CapabilityError(f"{self.module}: max concurrency must be positive")
        if not self.positive_controls:
            raise CapabilityError(f"{self.module}: positive control is required")
        if not self.negative_controls:
            raise CapabilityError(f"{self.module}: negative control is required")


def _capability(
    module: str,
    traffic_class: TrafficClass,
    request_cost: int,
    *,
    max_concurrency: int = 2,
    permissions: tuple[str, ...] = (),
    fallback: str | None = None,
    idempotent: bool = True,
) -> ScannerCapability:
    return ScannerCapability(
        module=module,
        version="1.0",
        traffic_class=traffic_class,
        request_cost=request_cost,
        max_concurrency=max_concurrency,
        required_permissions=permissions,
        positive_controls=("vulnerability-specific differential",),
        negative_controls=("safe baseline or negative control",),
        fallback_module=fallback,
        idempotent=idempotent,
    )


_DEFAULT_CAPABILITIES = {
    "sql_injection": _capability("sql_injection", TrafficClass.SAFE_ACTIVE, 120),
    "ssti": _capability("ssti", TrafficClass.SAFE_ACTIVE, 30),
    "crlf_injection": _capability("crlf_injection", TrafficClass.SAFE_ACTIVE, 20),
    "xss_scanner": _capability("xss_scanner", TrafficClass.SAFE_ACTIVE, 60),
    "ssrf": _capability("ssrf", TrafficClass.SAFE_ACTIVE, 30, permissions=("internal_address_probes",)),
    "auth_scanner": _capability("auth_scanner", TrafficClass.SAFE_ACTIVE, 20, permissions=("test_account_auth",)),
    "oauth_oidc_scanner": _capability("oauth_oidc_scanner", TrafficClass.PASSIVE, 2),
    "session_cookie_scanner": _capability("session_cookie_scanner", TrafficClass.PASSIVE, 5),
    "jwt_scanner": _capability("jwt_scanner", TrafficClass.SAFE_ACTIVE, 20, permissions=("synthetic_token_testing",)),
    "rate_limit_scanner": _capability("rate_limit_scanner", TrafficClass.DISRUPTIVE, 50, max_concurrency=1, permissions=("rate_limit_testing",)),
    "idor_scanner": _capability("idor_scanner", TrafficClass.SAFE_ACTIVE, 30, permissions=("test_identity_access",)),
    "bola_scanner": _capability("bola_scanner", TrafficClass.SAFE_ACTIVE, 20, permissions=("test_identity_access",)),
    "mass_assignment_scanner": _capability(
        "mass_assignment_scanner", TrafficClass.STATE_CHANGING, 6,
        permissions=("mass_assignment_testing",), idempotent=False,
    ),
    "broken_access_control": _capability("broken_access_control", TrafficClass.SAFE_ACTIVE, 30, permissions=("test_identity_access",)),
    "path_traversal": _capability("path_traversal", TrafficClass.SAFE_ACTIVE, 40),
    "lfi_rfi_scanner": _capability("lfi_rfi_scanner", TrafficClass.SAFE_ACTIVE, 40),
    "misconfig_scanner": _capability("misconfig_scanner", TrafficClass.SAFE_ACTIVE, 20),
    "cors_scanner": _capability("cors_scanner", TrafficClass.SAFE_ACTIVE, 10),
    "header_security": _capability("header_security", TrafficClass.PASSIVE, 1),
    "sensitive_data_exposure": _capability("sensitive_data_exposure", TrafficClass.PASSIVE, 1),
    "open_redirect": _capability("open_redirect", TrafficClass.SAFE_ACTIVE, 20),
    "subdomain_takeover": _capability("subdomain_takeover", TrafficClass.PASSIVE, 1),
    "ssl_tls_scanner": _capability("ssl_tls_scanner", TrafficClass.PASSIVE, 2),
    "openapi_scanner": _capability("openapi_scanner", TrafficClass.PASSIVE, 5),
    "csrf_scanner": _capability("csrf_scanner", TrafficClass.STATE_CHANGING, 10, permissions=("reversible_state_change",), idempotent=False),
    "host_header": _capability("host_header", TrafficClass.SAFE_ACTIVE, 10),
    "cache_behavior_scanner": _capability(
        "cache_behavior_scanner", TrafficClass.SAFE_ACTIVE, 10,
        permissions=("test_identity_access",),
    ),
    "xxe_scanner": _capability("xxe_scanner", TrafficClass.SAFE_ACTIVE, 20, permissions=("xml_parser_testing",)),
    "race_condition": _capability("race_condition", TrafficClass.DISRUPTIVE, 100, max_concurrency=1, permissions=("concurrency_testing",), idempotent=False),
    "command_injection": _capability("command_injection", TrafficClass.SAFE_ACTIVE, 50),
    "graphql_scanner": _capability("graphql_scanner", TrafficClass.SAFE_ACTIVE, 30),
    "websocket_scanner": _capability(
        "websocket_scanner", TrafficClass.SAFE_ACTIVE, 4,
        permissions=("websocket_testing",),
    ),
}


class CapabilityRegistry:
    def __init__(self, capabilities: Mapping[str, ScannerCapability]):
        self._capabilities = dict(capabilities)
        for name, capability in self._capabilities.items():
            if name != capability.module:
                raise CapabilityError(
                    f"capability key {name!r} does not match module {capability.module!r}"
                )
            capability.validate()

    @classmethod
    def default(cls) -> "CapabilityRegistry":
        return cls(_DEFAULT_CAPABILITIES)

    def require(self, module: str) -> ScannerCapability:
        try:
            return self._capabilities[module]
        except KeyError as exc:
            raise CapabilityError(f"missing capability metadata for scanner {module!r}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(self._capabilities)

    def validate_complete(self, modules: Iterable[str]) -> None:
        for module in modules:
            self.require(module)
