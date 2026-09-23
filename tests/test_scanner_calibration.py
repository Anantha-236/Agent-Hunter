"""Paired vulnerable/safe calibration for every registered scanner.

This corpus deliberately uses only loopback fixtures.  A scanner entry cannot be
added to the orchestrator without adding an explicit calibration case here.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

import httpx
import pytest

from core.models import EvidenceStatus, ScanState, Scope, Target
from core.orchestrator import SCANNER_REGISTRY, load_scanner
from core.scanner_capabilities import CapabilityRegistry
from tests.fixtures.safe_server import start_safe_server, stop_safe_server
from tests.vuln_server import start_vuln_server, stop_vuln_server
from utils.http_client import HttpClient


@dataclass(frozen=True)
class ScannerCase:
    module: str
    vulnerable_url: str
    safe_url: str
    expected_types: tuple[str, ...]
    max_requests: int


# The values are vulnerability families, not exact titles.  Matching accepts an
# exact value or a subtype prefix (for example ``sql_injection_error``).
EXPECTED_TYPES = {
    "sql_injection": ("sql_injection",),
    "ssti": ("ssti",),
    "crlf_injection": ("crlf", "response_splitting"),
    "xss_scanner": ("reflected_xss",),
    "ssrf": ("ssrf",),
    "auth_scanner": ("default_credentials", "jwt_alg_none"),
    "oauth_oidc_scanner": (),
    "session_cookie_scanner": (),
    "jwt_scanner": ("jwt_weak_secret",),
    "rate_limit_scanner": ("rate_limit_missing",),
    "idor_scanner": ("idor",),
    "bola_scanner": (),
    "mass_assignment_scanner": (),
    "broken_access_control": ("broken_access_control",),
    "path_traversal": ("path_traversal",),
    "lfi_rfi_scanner": ("lfi_rfi", "lfi_wrapper"),
    "misconfig_scanner": ("sensitive_file_exposure", "directory_listing"),
    "cors_scanner": ("cors_credentials_reflection",),
    "header_security": ("header_missing",),
    "sensitive_data_exposure": ("secret_disclosure", "sensitive_data_exposure"),
    "open_redirect": ("open_redirect",),
    "subdomain_takeover": ("subdomain_takeover",),
    "ssl_tls_scanner": ("tls_missing_https",),
    "openapi_scanner": (),
    "csrf_scanner": ("csrf",),
    "host_header": ("host_header", "password_reset_poisoning"),
    "cache_behavior_scanner": (),
    "xxe_scanner": ("xxe",),
    "race_condition": ("race_condition",),
    "command_injection": ("command_injection",),
    "graphql_scanner": ("graphql_introspection",),
    "websocket_scanner": (),
}

MAX_REQUESTS = {
    "sql_injection": 220, "ssti": 100, "crlf_injection": 35,
    "xss_scanner": 120, "ssrf": 100, "auth_scanner": 30,
    "oauth_oidc_scanner": 2,
    "session_cookie_scanner": 5,
    "jwt_scanner": 5, "rate_limit_scanner": 10, "idor_scanner": 40,
    "bola_scanner": 20, "mass_assignment_scanner": 6,
    "broken_access_control": 20, "path_traversal": 70,
    "lfi_rfi_scanner": 45, "misconfig_scanner": 140,
    "cors_scanner": 4, "header_security": 2,
    "sensitive_data_exposure": 14, "open_redirect": 90,
    "subdomain_takeover": 2, "ssl_tls_scanner": 2, "csrf_scanner": 3,
    "openapi_scanner": 5,
    "host_header": 30, "xxe_scanner": 30, "race_condition": 22,
    "cache_behavior_scanner": 10,
    "command_injection": 120, "graphql_scanner": 20,
    "websocket_scanner": 0,
}


def _matches(actual: str, expected: Iterable[str]) -> bool:
    return any(actual == item or actual.startswith(f"{item}_") for item in expected)


@pytest.fixture(scope="module")
def paired_servers():
    vulnerable = start_vuln_server()
    safe = start_safe_server()
    try:
        yield vulnerable, safe
    finally:
        stop_safe_server()
        stop_vuln_server()


def scanner_cases(vulnerable: str, safe: str) -> tuple[ScannerCase, ...]:
    return tuple(
        ScannerCase(
            module=module,
            vulnerable_url=vulnerable,
            safe_url=safe,
            expected_types=EXPECTED_TYPES[module],
            max_requests=MAX_REQUESTS[module],
        )
        for module in SCANNER_REGISTRY
    )


def _state(base_url: str, module: str) -> ScanState:
    scope = Scope(allowed_domains=["127.0.0.1", "localhost"])
    route_by_module = {
        "sql_injection": ("/products?cat=1", "/products", ["cat"]),
        "ssti": ("/template?name=World", "/template", ["name"]),
        "crlf_injection": ("/redirect?ref=home", "/redirect", ["ref"]),
        "xss_scanner": ("/search?q=test", "/search", ["q"]),
        "ssrf": ("/fetch?url=http://example.invalid", "/fetch", ["url"]),
        "rate_limit_scanner": ("/login", "/login", []),
        "idor_scanner": ("/profile?id=1", "/profile", ["id"]),
        "path_traversal": ("/view?file=readme.txt", "/view", ["file"]),
        "lfi_rfi_scanner": ("/view?file=readme.txt", "/view", ["file"]),
        "cors_scanner": ("/robots.txt", "/robots.txt", []),
        "open_redirect": ("/login?redirect=/", "/login", ["redirect"]),
        "csrf_scanner": ("/transfer", "/transfer", []),
        "host_header": ("/forgot-password", "/forgot-password", []),
        "xxe_scanner": ("/api/xml", "/api/xml", []),
        "race_condition": ("/coupon/apply?code=TEST10", "/coupon/apply", ["code"]),
        "command_injection": ("/ping?ip=127.0.0.1", "/ping", ["ip"]),
        "graphql_scanner": ("/graphql", "/graphql", []),
    }
    route, param_route, param_names = route_by_module.get(module, ("/", "/", []))
    primary = (
        f"{base_url}{route}"
        if module in {"rate_limit_scanner", "cors_scanner", "xxe_scanner", "graphql_scanner"}
        else base_url
    )
    urls = [f"{base_url}{route}"]
    if module == "auth_scanner":
        urls = [f"{base_url}/login"]
    elif module == "broken_access_control":
        urls = [f"{base_url}/admin", f"{base_url}/profile?id=1"]
    params = {f"{base_url}{param_route}": param_names} if param_names else {}
    if module == "broken_access_control":
        params = {f"{base_url}/profile": ["id"]}
    target = Target(
        url=primary,
        scope=scope,
        discovered_urls=urls,
        discovered_params=params,
        technologies=["php", "mysql", "apache", "graphql"],
    )
    return ScanState(target=target)


async def _run_case(module: str, base_url: str):
    scanner_cls = load_scanner(module)
    assert scanner_cls is not None
    state = _state(base_url, module)
    async with HttpClient(
        scope=state.target.scope,
        verify_ssl=False,
        timeout=4,
        rate_limit=10_000,
        concurrency=20,
    ) as client:
        scanner = scanner_cls(client)
        if module == "subdomain_takeover":
            async def fixture_cname(_hostname):
                return "unclaimed.github.io"
            scanner._resolve_cname = fixture_cname
            port = urlparse(base_url).port
            finding = await scanner._check_subdomain(f"127.0.0.1:{port}")
            return ([finding] if finding else []), len(client.request_log)
        if module == "ssl_tls_scanner" and base_url.endswith(":18944"):
            state.target.url = "https://safe.fixture"
            scanner._handshake_info = lambda _host, _port: (
                {"notAfter": "Jan 01 00:00:00 2035 GMT"},
                "TLSv1.3",
                "TLS_AES_256_GCM_SHA384",
            )
            scanner._legacy_protocol_support = lambda _host, _port: []
        await scanner.setup()
        try:
            findings = await asyncio.wait_for(scanner.run(state), timeout=45)
        finally:
            await scanner.teardown()
        return findings or [], len(client.request_log)


def test_every_registered_scanner_has_a_calibration_case(paired_servers):
    vulnerable, safe = paired_servers
    cases = scanner_cases(vulnerable, safe)
    assert {case.module for case in cases} == set(SCANNER_REGISTRY)
    assert set(EXPECTED_TYPES) == set(SCANNER_REGISTRY)
    assert set(MAX_REQUESTS) == set(SCANNER_REGISTRY)


def test_safe_fixture_exposes_misleading_controls(paired_servers):
    _, safe = paired_servers
    with httpx.Client(follow_redirects=False, timeout=3) as client:
        generic_error = client.get(f"{safe}/products?cat=%27")
        escaped = client.get(f"{safe}/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
        denied_a = client.get(f"{safe}/profile?id=1")
        denied_b = client.get(f"{safe}/profile?id=99999999")
        json_response = client.get(f"{safe}/api/data")
        redirect = client.get(f"{safe}/redirect?ref=https://evil.example")
        compressed = client.get(f"{safe}/compressed")
        delayed = client.get(f"{safe}/delayed?sleep=1")

    assert generic_error.status_code == 500 and "SQL" not in generic_error.text.upper()
    assert "<script>" not in escaped.text and "&lt;script&gt;" in escaped.text
    assert denied_a.status_code == denied_b.status_code == 403
    assert len(denied_a.content) == len(denied_b.content)
    assert json_response.headers["content-type"].startswith("application/json")
    assert "content-security-policy" not in json_response.headers
    assert redirect.headers["location"].startswith("/")
    assert compressed.headers.get("content-encoding") == "gzip"
    assert delayed.status_code == 200


@pytest.mark.parametrize("module", tuple(SCANNER_REGISTRY))
def test_scanner_paired_calibration(module, paired_servers, monkeypatch):
    vulnerable, safe = paired_servers
    case = next(item for item in scanner_cases(vulnerable, safe) if item.module == module)

    vulnerable_findings, vulnerable_requests = asyncio.run(
        _run_case(case.module, case.vulnerable_url)
    )
    safe_findings, safe_requests = asyncio.run(_run_case(case.module, case.safe_url))

    if case.expected_types:
        assert any(
            _matches(finding.vuln_type, case.expected_types)
            for finding in vulnerable_findings
        ), f"{module} missed {case.expected_types}: {[f.vuln_type for f in vulnerable_findings]}"
    else:
        # Discovery-only scanners produce coverage candidates, never
        # vulnerability findings.
        assert vulnerable_findings == []
    assert not any(
        _matches(finding.vuln_type, case.expected_types)
        for finding in safe_findings
    ), f"{module} false positive: {[f.vuln_type for f in safe_findings]}"
    assert vulnerable_requests <= case.max_requests
    assert safe_requests <= case.max_requests

    capability = CapabilityRegistry.default().require(module)
    for finding in [*vulnerable_findings, *safe_findings]:
        if (
            finding.evidence_status is EvidenceStatus.CONFIRMED
            and str(finding.severity).lower() in {"high", "critical"}
        ):
            assert any(ref.kind == "validator" for ref in finding.evidence_refs)
            controls = set(finding.control_results)
            assert set(capability.positive_controls).issubset(controls)
            assert set(capability.negative_controls).issubset(controls)
