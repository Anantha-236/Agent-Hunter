from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from core.auth_session import AuthSession
from core.models import CoverageStatus, DecisionOutcome, EvidenceStatus, ScanState, Scope, Target
from core.test_identities import TestIdentity
from scanners.authz.bola_scanner import BOLAScanner
from scanners.authz.mass_assignment_scanner import MassAssignmentScanner


def _identity(label: str, token: str) -> TestIdentity:
    return TestIdentity(label, lambda: {"Authorization": f"Bearer {token}"})


def test_identity_headers_stay_in_memory_and_serialization_is_secret_free():
    identity = _identity("alice", "alice-secret-token")
    assert identity.headers()["Authorization"] == "Bearer alice-secret-token"
    serialized = identity.to_dict()
    assert serialized["label"] == "alice"
    assert serialized["fingerprint"]
    assert "alice-secret-token" not in repr(serialized)
    assert "provider" not in serialized

    session = AuthSession()
    session.set_bearer_token("session-secret-token")
    session.set_cookies({"session": "cookie-secret"})
    session.set_test_identities([identity])
    persisted = session.to_dict()
    assert "session-secret-token" not in repr(persisted)
    assert "cookie-secret" not in repr(persisted)
    assert persisted["test_identities"][0]["label"] == "alice"


@dataclass
class FakeResponse:
    status_code: int
    value: dict
    headers: dict = field(default_factory=lambda: {"content-type": "application/json"})

    @property
    def text(self):
        import json
        return json.dumps(self.value)

    def json(self):
        return dict(self.value)


class AuthzClient:
    def __init__(self, *, vulnerable: bool, missing_status: int = 403):
        self.vulnerable = vulnerable
        self.missing_status = missing_status
        self.request_log = []
        self._policy_enforcer = None
        self.objects = {
            "1": {"id": "1", "owner": "alice", "display_name": "A"},
            "2": {
                "id": "2", "owner": "bob",
                "display_name": "Bob has deliberately much longer public content",
            },
        }

    @staticmethod
    def _principal(headers):
        value = (headers or {}).get("Authorization", "")
        if "alice" in value:
            return "alice"
        if "bob" in value:
            return "bob"
        return "unknown"

    async def get(self, url, *, extra_headers=None, headers=None, **_kwargs):
        active_headers = extra_headers or headers or {}
        self.request_log.append(("GET", url, dict(active_headers)))
        object_id = url.rstrip("/").rsplit("/", 1)[-1]
        value = self.objects.get(object_id)
        if value is None:
            return FakeResponse(404, {"error": "not found"}), "GET"
        if not self.vulnerable and value["owner"] != self._principal(active_headers):
            return FakeResponse(self.missing_status, {"error": "not available"}), "GET"
        return FakeResponse(200, value), "GET"


def _state() -> ScanState:
    return ScanState(target=Target(
        url="https://api.example.test",
        scope=Scope(allowed_domains=["api.example.test"]),
        metadata={
            "openapi_candidates": [{
                "method": "GET",
                "url": "https://api.example.test/users/{id}",
                "operation_id": "getUser",
                "path_parameters": ["id"],
                "query_parameters": [],
                "source_url": "https://api.example.test/openapi.json",
            }],
            "authz_test_objects": {
                "https://api.example.test/users/{id}": {"alice": "1", "bob": "2"}
            },
        },
    ))


@pytest.mark.asyncio
async def test_bola_requires_two_explicit_identities():
    state = _state()
    client = AuthzClient(vulnerable=True)
    scanner = BOLAScanner(client, identities=[_identity("alice", "alice-secret")])
    assert await scanner.run(state) == []
    assert client.request_log == []
    assert state.decisions[-1].outcome is DecisionOutcome.DEFER
    assert state.coverage[-1].status is CoverageStatus.NOT_TESTED


@pytest.mark.asyncio
async def test_bola_confirms_only_semantic_cross_principal_object_access():
    state = _state()
    scanner = BOLAScanner(
        AuthzClient(vulnerable=True),
        identities=[_identity("alice", "alice-secret"), _identity("bob", "bob-secret")],
    )
    findings = await scanner.run(state)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.vuln_type == "bola"
    assert finding.evidence_status is EvidenceStatus.CONFIRMED
    assert finding.validator_results["cross_principal_object_id"] in {"1", "2"}
    assert any(ref.kind == "validator" for ref in finding.evidence_refs)
    assert "secret" not in repr(finding.to_dict())


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_status", [403, 404])
async def test_bola_refutes_equal_denial_and_ignores_authorized_length_differences(missing_status):
    state = _state()
    scanner = BOLAScanner(
        AuthzClient(vulnerable=False, missing_status=missing_status),
        identities=[_identity("alice", "alice-secret"), _identity("bob", "bob-secret")],
    )
    assert await scanner.run(state) == []
    assert state.coverage[-1].status is CoverageStatus.TESTED
    assert "denied" in state.coverage[-1].reason.lower()


class MassAssignmentClient:
    def __init__(self):
        self.profile = {"id": "1", "nickname": "before", "role": "user"}
        self.request_log = []
        self._policy_enforcer = None

    async def get(self, url, *, extra_headers=None, **_kwargs):
        self.request_log.append(("GET", url, dict(extra_headers or {}), None))
        return FakeResponse(200, self.profile), "GET"

    async def request(self, method, url, *, json=None, extra_headers=None, **_kwargs):
        self.request_log.append((method, url, dict(extra_headers or {}), dict(json or {})))
        if method == "PATCH":
            self.profile.update(json or {})
            return FakeResponse(200, self.profile), f"{method}"
        return FakeResponse(405, {"error": "method"}), f"{method}"


def _mass_state() -> ScanState:
    state = _state()
    state.target.metadata["openapi_candidates"] = [{
        "method": "PATCH",
        "url": "https://api.example.test/profiles/{id}",
        "operation_id": "updateProfile",
        "path_parameters": ["id"],
        "query_parameters": [],
        "source_url": "https://api.example.test/openapi.json",
    }]
    state.target.metadata["authz_test_objects"] = {
        "https://api.example.test/profiles/{id}": {"alice": "1"}
    }
    return state


@pytest.mark.asyncio
async def test_mass_assignment_is_disabled_without_all_safety_gates():
    client = MassAssignmentClient()
    state = _mass_state()
    scanner = MassAssignmentScanner(
        client,
        identities=[_identity("alice", "alice-secret")],
        field_allowlist=("nickname",),
    )
    assert await scanner.run(state) == []
    assert client.request_log == []
    assert state.decisions[-1].outcome is DecisionOutcome.DEFER


def test_mass_assignment_rejects_privilege_and_billing_fields_even_if_allowlisted():
    for field_name in ("role", "is_admin", "billing_plan", "account_balance"):
        with pytest.raises(ValueError, match="unsafe mass-assignment field"):
            MassAssignmentScanner(
                MassAssignmentClient(),
                identities=[_identity("alice", "alice-secret")],
                field_allowlist=(field_name,),
            )


@pytest.mark.asyncio
async def test_mass_assignment_requires_before_after_and_verified_cleanup():
    client = MassAssignmentClient()
    state = _mass_state()

    async def cleanup(client, url, identity, field, before_value, idempotency_key):
        response, _ = await client.request(
            "PATCH", url, json={field: before_value},
            extra_headers={**identity.headers(), "Idempotency-Key": idempotency_key},
        )
        return response.status_code == 200

    scanner = MassAssignmentScanner(
        client,
        identities=[_identity("alice", "alice-secret")],
        field_allowlist=("nickname",),
        cleanup_handler=cleanup,
        enabled=True,
        policy_permissions={"mass_assignment_testing"},
        operator_confirmed=True,
        idempotency_key="fixture-idempotency-key",
    )
    findings = await scanner.run(state)

    assert len(findings) == 1
    assert findings[0].evidence_status is EvidenceStatus.CONFIRMED
    assert findings[0].control_results["cleanup_verified"] is True
    assert client.profile["nickname"] == "before"
    patch_calls = [entry for entry in client.request_log if entry[0] == "PATCH"]
    assert len(patch_calls) == 2
    assert all(call[2]["Idempotency-Key"] == "fixture-idempotency-key" for call in patch_calls)


@pytest.mark.asyncio
async def test_mass_assignment_escalates_when_cleanup_cannot_be_verified():
    client = MassAssignmentClient()
    state = _mass_state()

    async def failed_cleanup(*_args, **_kwargs):
        raise RuntimeError("synthetic cleanup transport failed")

    scanner = MassAssignmentScanner(
        client,
        identities=[_identity("alice", "alice-secret")],
        field_allowlist=("nickname",),
        cleanup_handler=failed_cleanup,
        enabled=True,
        policy_permissions={"mass_assignment_testing"},
        operator_confirmed=True,
        idempotency_key="fixture-idempotency-key",
    )
    assert await scanner.run(state) == []
    assert state.decisions[-1].outcome is DecisionOutcome.ESCALATE
    assert state.coverage[-1].status is CoverageStatus.BLOCKED
