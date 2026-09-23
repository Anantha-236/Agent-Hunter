from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from core.models import CoverageStatus, EvidenceStatus, ScanState, Scope, Target
from core.test_identities import TestIdentity
from scanners.auth.session_cookie_scanner import SessionCookieScanner, parse_set_cookie_metadata
from scanners.misconfig.cache_behavior_scanner import CacheBehaviorScanner


def _identity(label):
    return TestIdentity(label, lambda: {"Authorization": f"Bearer {label}-secret"})


def test_cookie_metadata_discards_values_and_scopes_duplicate_names():
    headers = [
        "session=secret-one; Path=/; Secure; HttpOnly; SameSite=Lax",
        "session=secret-two; Path=/admin; Domain=example.test; Secure; SameSite=Strict",
    ]
    observations = parse_set_cookie_metadata(headers, "https://example.test/login")
    assert len(observations) == 2
    assert {(item.name, item.path, item.domain) for item in observations} == {
        ("session", "/", "example.test"),
        ("session", "/admin", "example.test"),
    }
    serialized = repr([item.to_dict() for item in observations])
    assert "secret-one" not in serialized and "secret-two" not in serialized
    assert all(item.value_fingerprint for item in observations)


def test_cookie_prefix_rules_and_missing_flags_remain_observations():
    observations = parse_set_cookie_metadata([
        "__Host-bad=value; Domain=example.test; Path=/admin",
        "plain=value; Path=/",
    ], "https://example.test/")
    host = observations[0]
    assert "host_prefix_requires_secure" in host.issues
    assert "host_prefix_forbids_domain" in host.issues
    assert "host_prefix_requires_root_path" in host.issues
    assert "missing_secure" in observations[1].issues
    assert all(item.evidence_status is EvidenceStatus.OBSERVED for item in observations)


@dataclass
class Response:
    status_code: int
    value: dict
    headers: dict = field(default_factory=dict)

    @property
    def text(self):
        import json
        return json.dumps(self.value)

    def json(self):
        return dict(self.value)


class CacheClient:
    def __init__(self, mode):
        self.mode = mode
        self.request_log = []
        self._policy_enforcer = None
        self.primed_owner = None

    async def get(self, url, *, extra_headers=None, **_kwargs):
        headers = dict(extra_headers or {})
        owner = "alice" if "alice" in headers.get("Authorization", "") else "bob"
        self.request_log.append(("GET", url, headers))
        if self.mode == "expired":
            return Response(401, {"error": "expired"}), "GET"
        if self.mode == "public":
            return Response(200, {"message": "same public content"}, {"Age": "12"}), "GET"
        if self.mode == "conditional" and "If-None-Match" in headers:
            return Response(304, {}, {"ETag": '"alice"', "Vary": "Authorization"}), "GET"
        if headers.get("Cache-Control") == "no-cache":
            return Response(200, {"owner": owner, "private": f"{owner}-data"}, {"Vary": "Authorization"}), "GET"
        if owner == "alice":
            self.primed_owner = "alice"
            response_headers = {"Age": "0"}
            if self.mode == "conditional":
                response_headers["ETag"] = '"alice"'
            return Response(200, {"owner": "alice", "private": "alice-data"}, response_headers), "GET"
        if self.mode == "vulnerable" and self.primed_owner == "alice":
            return Response(200, {"owner": "alice", "private": "alice-data"}, {"Age": "3"}), "GET"
        return Response(200, {"owner": "bob", "private": "bob-data"}, {"Vary": "Authorization"}), "GET"


def _state():
    return ScanState(target=Target(
        url="https://api.example.test",
        scope=Scope(allowed_domains=["api.example.test"]),
        metadata={"cache_test_urls": ["https://api.example.test/private"]},
    ))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["safe", "public", "conditional"])
async def test_cache_scanner_refutes_safe_private_and_identical_public_content(mode):
    state = _state()
    scanner = CacheBehaviorScanner(
        CacheClient(mode), identities=[_identity("alice"), _identity("bob")]
    )
    assert await scanner.run(state) == []
    assert state.coverage[-1].status is CoverageStatus.TESTED


@pytest.mark.asyncio
async def test_cache_scanner_confirms_repeatable_cross_principal_private_content():
    client = CacheClient("vulnerable")
    state = _state()
    scanner = CacheBehaviorScanner(client, identities=[_identity("alice"), _identity("bob")])
    findings = await scanner.run(state)
    assert len(findings) == 1
    assert findings[0].evidence_status is EvidenceStatus.CONFIRMED
    assert findings[0].validator_results["cross_principal_owner"] == "alice"
    assert len(client.request_log) == 5
    assert any(call[2].get("Cache-Control") == "no-cache" for call in client.request_log)
    assert "secret" not in repr(findings[0].to_dict())


@pytest.mark.asyncio
async def test_cache_scanner_stops_on_authentication_ambiguity():
    client = CacheClient("expired")
    state = _state()
    scanner = CacheBehaviorScanner(client, identities=[_identity("alice"), _identity("bob")])
    assert await scanner.run(state) == []
    assert len(client.request_log) == 1
    assert state.coverage[-1].status is CoverageStatus.DEFERRED
