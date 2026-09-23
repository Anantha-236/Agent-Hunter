from __future__ import annotations

import json

import pytest

from core.models import EvidenceStatus, ScanState, Scope, Target
from core.test_identities import TestIdentity
from scanners.injection.graphql_scanner import GraphQLScanner
from scanners.realtime.websocket_scanner import WebSocketRedirectBlocked, WebSocketScanner


class GraphResponse:
    def __init__(self, value, status=200):
        self.value, self.status_code = value, status
        self.text = json.dumps(value)
        self.headers = {"content-type": "application/json"}
    def json(self): return self.value


class GraphClient:
    _policy_enforcer = None
    def __init__(self, mode): self.mode, self.request_log = mode, []
    async def post(self, url, *, json=None, content=None, **_kwargs):
        query = content or (json and json.get("query", "")) or ""
        self.request_log.append((url, query))
        if not url.endswith("/graphql"): return GraphResponse({}, 404), "POST"
        if "__schema" in query:
            if self.mode == "disabled": return GraphResponse({"errors": [{"message": "disabled"}]}), "POST"
            return GraphResponse({"data": {"__schema": {"types": [{"name": "Query"}]}}}), "POST"
        if "user(id:" in query:
            return GraphResponse({"data": {"user": {"id": 1, "email": "a@example.test", "role": "user"}}}), "POST"
        if query.startswith("["): return GraphResponse([{"data": {"__typename": "Query"}}] * 10), "POST"
        if "a:__typename" in query: return GraphResponse({"data": {key: "Query" for key in "abcde"}}), "POST"
        if "XYZ" in query: return GraphResponse({"errors": [{"message": "generic error"}]}), "POST"
        return GraphResponse({"data": {"__typename": "Query"}}), "POST"


def _state():
    return ScanState(target=Target(url="https://api.example.test", scope=Scope(allowed_domains=["api.example.test"])))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["enabled", "disabled"])
async def test_graphql_configuration_checks_are_bounded_and_never_high_impact_confirmed(mode):
    client = GraphClient(mode)
    findings = await GraphQLScanner(client).run(_state())
    assert len(client.request_log) <= 20
    introspection = [f for f in findings if f.vuln_type == "graphql_introspection"]
    if mode == "enabled":
        assert introspection and introspection[0].severity == "info"
        assert introspection[0].evidence_status is EvidenceStatus.OBSERVED
    else:
        assert not introspection
    assert not any(f.evidence_status is EvidenceStatus.CONFIRMED for f in findings)
    bola = [f for f in findings if f.vuln_type == "graphql_bola"]
    assert all(f.evidence_status is EvidenceStatus.SUSPECTED for f in bola)


class Connection:
    def __init__(self, connector, headers):
        self.connector, self.headers, self.sent, self.closed = connector, headers, None, False
    async def send(self, value): self.sent = json.loads(value); self.connector.messages += 1
    async def recv(self):
        topic = self.sent["topic"]
        owner = "alice" if topic == "topic-a" else "bob"
        requester = "alice" if "alice" in self.headers.get("Authorization", "") else "bob"
        if self.connector.vulnerable or requester == owner: return json.dumps({"owner": owner})
        return json.dumps({"error": "forbidden"})
    async def close(self): self.closed = True


class Connector:
    def __init__(self, vulnerable=True, redirect=False):
        self.vulnerable, self.redirect, self.connections, self.messages = vulnerable, redirect, [], 0
    async def __call__(self, endpoint, *, origin, headers):
        if self.redirect: raise WebSocketRedirectBlocked("wss://outside.invalid/socket")
        connection = Connection(self, headers)
        self.connections.append((endpoint, origin, dict(headers), connection))
        return connection


def _ws_state():
    state = _state()
    state.target.metadata.update({
        "websocket_endpoints": ["wss://api.example.test/socket", "wss://outside.invalid/socket"],
        "websocket_subscription_testing": True,
        "websocket_test_topics": {"wss://api.example.test/socket": {"alice": "topic-a", "bob": "topic-b"}},
    })
    return state


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable,expected", [(True, 1), (False, 0)])
async def test_websocket_two_principal_topic_checks_are_bounded_closed_and_secret_free(vulnerable, expected):
    connector = Connector(vulnerable=vulnerable)
    scanner = WebSocketScanner(
        object(), connector=connector,
        identities=[TestIdentity("alice", lambda: {"Authorization": "Bearer alice-secret"}), TestIdentity("bob", lambda: {"Authorization": "Bearer bob-secret"})],
    )
    findings = await scanner.run(_ws_state())
    confirmed = [f for f in findings if f.evidence_status is EvidenceStatus.CONFIRMED]
    assert len(confirmed) == expected
    assert scanner.connection_count <= 4 and scanner.message_count <= 2
    assert all(entry[3].closed for entry in connector.connections)
    assert "secret" not in repr([f.to_dict() for f in findings])
    assert "wss://outside.invalid/socket" in _ws_state().target.metadata["websocket_endpoints"]


@pytest.mark.asyncio
async def test_websocket_redirect_is_recorded_and_never_followed():
    connector = Connector(redirect=True)
    state = _ws_state()
    state.target.metadata["websocket_subscription_testing"] = False
    scanner = WebSocketScanner(object(), connector=connector)
    await scanner.run(state)
    assert state.target.metadata["websocket_blocked_endpoints"] == [
        "wss://outside.invalid/socket"
    ]
    assert scanner.connection_count == 2
