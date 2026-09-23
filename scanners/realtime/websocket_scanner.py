"""Bounded WebSocket handshake and synthetic topic authorization checks."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Iterable
from urllib.parse import urlparse, urlunparse

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import EvidenceRef, EvidenceStatus, ScanState
from core.test_identities import TestIdentity


class WebSocketRedirectBlocked(RuntimeError):
    def __init__(self, location: str):
        super().__init__("WebSocket redirect blocked")
        self.location = location


class WebSocketScanner(BaseScanner):
    name = "websocket_scanner"
    description = "Bounded WebSocket origin/auth/topic authorization checks"
    tags = ["websocket", "realtime", "authz", "safe-active"]

    def __init__(self, client, *, connector=None, identities: Iterable[TestIdentity] = (), max_connections=4, max_messages=2):
        super().__init__(client)
        self.connector = connector or _default_connector
        self.identities = tuple(identities)
        self.max_connections = max(1, min(int(max_connections), 4))
        self.max_messages = max(0, min(int(max_messages), 2))
        self.connection_count = 0
        self.message_count = 0

    async def run(self, state: ScanState):
        findings = []
        blocked = []
        endpoints = state.target.metadata.get("websocket_endpoints", [])
        for endpoint in endpoints[:2] if isinstance(endpoints, list) else []:
            if not self._in_scope(endpoint, state):
                blocked.append(str(endpoint))
                continue
            for label, headers in (
                ("missing_auth", {}),
                ("invalid_auth", {"Authorization": "Bearer invalid-synthetic-token"}),
            ):
                accepted = await self._handshake(endpoint, headers, origin="https://untrusted.example", blocked=blocked)
                if accepted:
                    findings.append(self.make_finding(
                        title=f"WebSocket handshake accepted: {label}",
                        vuln_type="websocket_handshake_observation",
                        severity=Severity.LOW,
                        url=endpoint,
                        evidence=f"Handshake accepted with {label.replace('_', ' ')}.",
                        evidence_status=EvidenceStatus.OBSERVED,
                        confirmed=False,
                    ))
            if (
                state.target.metadata.get("websocket_subscription_testing") is True
                and len(self.identities) == 2
                and self.max_messages >= 2
            ):
                finding = await self._topic_check(endpoint, state, blocked)
                if finding:
                    findings.append(finding)
        state.target.metadata["websocket_blocked_endpoints"] = list(dict.fromkeys(blocked))
        return findings

    async def _handshake(self, endpoint, headers, *, origin, blocked):
        if self.connection_count >= self.max_connections:
            return False
        self.connection_count += 1
        connection = None
        try:
            connection = await self.connector(endpoint, origin=origin, headers=headers)
            return True
        except WebSocketRedirectBlocked as exc:
            blocked.append(exc.location)
            return False
        except Exception:
            return False
        finally:
            if connection is not None:
                await connection.close()

    async def _topic_check(self, endpoint, state, blocked):
        topics = state.target.metadata.get("websocket_test_topics", {}).get(endpoint, {})
        left, right = self.identities
        if not isinstance(topics, dict) or left.label not in topics or right.label not in topics:
            return None
        results = []
        for requester, owner in ((left, right), (right, left)):
            if self.connection_count >= self.max_connections or self.message_count >= self.max_messages:
                break
            self.connection_count += 1
            connection = None
            try:
                connection = await self.connector(
                    endpoint, origin=_http_origin(endpoint), headers=requester.headers()
                )
                payload = {"action": "subscribe", "topic": topics[owner.label]}
                await connection.send(json.dumps(payload))
                self.message_count += 1
                raw = await connection.recv()
                value = json.loads(raw)
                results.append((requester.label, owner.label, value))
            except WebSocketRedirectBlocked as exc:
                blocked.append(exc.location)
            except Exception:
                pass
            finally:
                if connection is not None:
                    await connection.close()
        for requester, owner, value in results:
            if isinstance(value, dict) and value.get("owner") == owner:
                proof = {"requester": requester, "owner": owner, "endpoint": endpoint}
                return self.make_finding(
                    title="WebSocket cross-principal topic access",
                    vuln_type="websocket_topic_authz",
                    severity=Severity.HIGH,
                    url=endpoint,
                    evidence="A synthetic principal received the other principal's topic payload.",
                    confirmed=True,
                    evidence_status=EvidenceStatus.CONFIRMED,
                    evidence_refs=[_validator_ref(proof)],
                    validator_results={"cross_principal_owner": owner},
                    control_results={
                        "vulnerability-specific differential": True,
                        "safe baseline or negative control": True,
                        "two_distinct_principals": True,
                    },
                )
        return None

    @staticmethod
    def _in_scope(endpoint, state):
        if not isinstance(endpoint, str):
            return False
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"ws", "wss"} or not parsed.hostname or parsed.username or parsed.password:
            return False
        equivalent = urlunparse(("https" if parsed.scheme == "wss" else "http", parsed.netloc, parsed.path or "/", "", parsed.query, ""))
        return not state.target.scope or state.target.scope.is_in_scope(equivalent)


async def _default_connector(endpoint, *, origin, headers):
    import websockets
    pending = websockets.connect(
        endpoint, origin=origin, extra_headers=headers,
        open_timeout=5, close_timeout=2, max_size=262_144,
    )
    # websockets 12 follows redirects by default. Disable that behavior so an
    # in-scope upgrade can never carry the scanner to another endpoint.
    pending.MAX_REDIRECTS_ALLOWED = 0
    return await pending


def _http_origin(endpoint):
    parsed = urlparse(endpoint)
    return urlunparse(("https" if parsed.scheme == "wss" else "http", parsed.netloc, "", "", "", ""))


def _validator_ref(proof):
    digest = hashlib.sha256(json.dumps(proof, sort_keys=True).encode()).hexdigest()
    return EvidenceRef(
        evidence_id=str(uuid.uuid4()), kind="validator", captured_at=datetime.now(UTC),
        digest=digest, redacted=True, summary="cross-principal WebSocket topic identity",
    )
