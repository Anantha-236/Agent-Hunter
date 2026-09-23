from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from core.models import DecisionOutcome, EvidenceStatus, ScanState, Scope, Target
from scanners.auth.oauth_metadata import OAuthMetadata, OAuthMetadataError
from scanners.auth.oauth_oidc_scanner import OAuthOIDCScanner, SyntheticOAuthClient


def _metadata(**overrides):
    value = {
        "issuer": "https://id.example.test",
        "authorization_endpoint": "https://id.example.test/authorize",
        "token_endpoint": "https://id.example.test/token",
        "jwks_uri": "https://id.example.test/jwks.json",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    value.update(overrides)
    return json.dumps(value)


def test_metadata_parses_bounded_valid_document():
    metadata = OAuthMetadata.parse(
        _metadata(),
        "https://id.example.test/.well-known/openid-configuration",
        expected_issuer="https://id.example.test",
    )
    assert metadata.issuer == "https://id.example.test"
    assert metadata.authorization_endpoint == "https://id.example.test/authorize"
    assert metadata.blocked_endpoints == ()
    assert metadata.observations == ()


def test_metadata_records_issuer_pkce_algorithm_and_external_endpoint_observations():
    metadata = OAuthMetadata.parse(
        _metadata(
            issuer="https://wrong.example.test",
            token_endpoint="https://outside.invalid/token",
            code_challenge_methods_supported=["plain"],
            id_token_signing_alg_values_supported=["none", "HS256"],
        ),
        "https://id.example.test/.well-known/openid-configuration",
        expected_issuer="https://id.example.test",
    )
    codes = {item.code for item in metadata.observations}
    assert {"issuer_mismatch", "pkce_s256_not_advertised", "none_alg_advertised"} <= codes
    assert metadata.token_endpoint is None
    assert metadata.blocked_endpoints == ("https://outside.invalid/token",)
    assert all(item.evidence_status is EvidenceStatus.OBSERVED for item in metadata.observations)


def test_duplicate_keys_oversize_and_malformed_urls_are_rejected_or_blocked():
    duplicate = '{"issuer":"https://id.example.test","issuer":"https://evil.invalid","authorization_endpoint":"https://id.example.test/a"}'
    with pytest.raises(OAuthMetadataError, match="duplicate"):
        OAuthMetadata.parse(duplicate, "https://id.example.test/.well-known/openid-configuration")

    with pytest.raises(OAuthMetadataError, match="size"):
        OAuthMetadata.parse(
            _metadata(padding="x" * 2048),
            "https://id.example.test/.well-known/openid-configuration",
            max_bytes=256,
        )

    parsed = OAuthMetadata.parse(
        _metadata(authorization_endpoint="javascript:alert(1)", jwks_uri="https://user:pass@id.example.test/jwks"),
        "https://id.example.test/.well-known/openid-configuration",
    )
    assert parsed.authorization_endpoint is None
    assert len(parsed.blocked_endpoints) == 2


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)

    @property
    def content(self):
        return self.text.encode()


class OAuthClient:
    def __init__(self, responses):
        self.responses = responses
        self.request_log = []
        self._policy_enforcer = None

    async def get(self, url, **_kwargs):
        self.request_log.append(("GET", url, {}))
        return self.responses.get(url, FakeResponse(404)), f"GET {url}"

    async def get_no_redirect(self, url, *, params=None, **_kwargs):
        self.request_log.append(("GET_NO_REDIRECT", url, dict(params or {})))
        return self.responses.get(url, FakeResponse(200, "login")), f"GET {url}"


def _state():
    return ScanState(target=Target(
        url="https://id.example.test",
        scope=Scope(allowed_domains=["id.example.test"]),
    ))


@pytest.mark.asyncio
async def test_passive_scanner_only_fetches_standard_in_scope_documents():
    source = "https://id.example.test/.well-known/openid-configuration"
    client = OAuthClient({source: FakeResponse(200, _metadata(token_endpoint="https://outside.invalid/token"))})
    scanner = OAuthOIDCScanner(client)
    state = _state()

    findings = await scanner.run(state)

    assert len(client.request_log) == 2
    assert {entry[1] for entry in client.request_log} == {
        "https://id.example.test/.well-known/openid-configuration",
        "https://id.example.test/.well-known/oauth-authorization-server",
    }
    assert all(entry[1].startswith("https://id.example.test/") for entry in client.request_log)
    assert all(finding.evidence_status is EvidenceStatus.OBSERVED for finding in findings)
    assert all(not finding.confirmed for finding in findings)
    assert state.target.metadata["oauth_blocked_endpoints"] == ["https://outside.invalid/token"]


@pytest.mark.asyncio
async def test_active_flow_defers_without_explicit_synthetic_client():
    client = OAuthClient({})
    state = _state()
    scanner = OAuthOIDCScanner(client, active_flow_enabled=True)
    await scanner.run(state)
    assert state.decisions[-1].outcome is DecisionOutcome.DEFER
    assert all(entry[0] != "GET_NO_REDIRECT" for entry in client.request_log)


@pytest.mark.asyncio
async def test_active_flow_does_not_request_scope_excluded_authorization_endpoint():
    source = "https://id.example.test/.well-known/openid-configuration"
    client = OAuthClient({source: FakeResponse(200, _metadata())})
    state = _state()
    state.target.scope.excluded_paths = ["/authorize"]
    scanner = OAuthOIDCScanner(
        client,
        active_flow_enabled=True,
        synthetic_client=SyntheticOAuthClient(
            client_id="fixture",
            redirect_uri="https://id.example.test/callback",
            expected_issuer="https://id.example.test",
            permitted=True,
        ),
    )
    await scanner.run(state)
    assert all(entry[0] != "GET_NO_REDIRECT" for entry in client.request_log)
    assert state.decisions[-1].outcome is DecisionOutcome.DEFER


@pytest.mark.asyncio
async def test_active_flow_uses_only_in_scope_callback_and_persists_no_credentials():
    source = "https://id.example.test/.well-known/openid-configuration"
    authorize = "https://id.example.test/authorize"
    client = OAuthClient({
        source: FakeResponse(200, _metadata()),
        authorize: FakeResponse(302, headers={"location": "https://id.example.test/callback?code=fixture&state=returned"}),
    })
    synthetic = SyntheticOAuthClient(
        client_id="public-fixture-client",
        redirect_uri="https://id.example.test/callback",
        expected_issuer="https://id.example.test",
        permitted=True,
    )
    state = _state()
    scanner = OAuthOIDCScanner(
        client,
        active_flow_enabled=True,
        synthetic_client=synthetic,
    )
    findings = await scanner.run(state)

    active = [entry for entry in client.request_log if entry[0] == "GET_NO_REDIRECT"]
    assert len(active) == 1 and active[0][1] == authorize
    params = active[0][2]
    assert params["redirect_uri"] == "https://id.example.test/callback"
    assert params["code_challenge_method"] == "S256"
    assert params["state"] != "returned"
    assert "code_verifier" not in params
    serialized = repr([finding.to_dict() for finding in findings]) + repr(state.target.metadata)
    assert "public-fixture-client" not in serialized
    assert "code_verifier" not in serialized


def test_synthetic_client_rejects_external_or_unpermitted_callback():
    with pytest.raises(ValueError, match="same origin"):
        SyntheticOAuthClient(
            client_id="fixture",
            redirect_uri="https://outside.invalid/callback",
            expected_issuer="https://id.example.test",
            permitted=True,
        )
    with pytest.raises(ValueError, match="permitted"):
        SyntheticOAuthClient(
            client_id="fixture",
            redirect_uri="https://id.example.test/callback",
            expected_issuer="https://id.example.test",
            permitted=False,
        )
