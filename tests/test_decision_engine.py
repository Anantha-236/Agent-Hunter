from __future__ import annotations

from dataclasses import replace

from core.decision_engine import DecisionContext, DecisionEngine
from core.models import DecisionOutcome, Scope, Target
from core.scanner_capabilities import (
    CapabilityRegistry,
    ScannerCapability,
    TrafficClass,
)


def capability(
    module: str = "candidate",
    traffic_class: TrafficClass = TrafficClass.SAFE_ACTIVE,
    *,
    request_cost: int = 1,
    permissions: tuple[str, ...] = (),
    idempotent: bool = True,
) -> ScannerCapability:
    return ScannerCapability(
        module=module,
        version="1.0",
        traffic_class=traffic_class,
        request_cost=request_cost,
        max_concurrency=1,
        required_permissions=permissions,
        positive_controls=("expected-positive",),
        negative_controls=("expected-negative",),
        fallback_module=None,
        idempotent=idempotent,
    )


def context_for(
    traffic_class: TrafficClass = TrafficClass.SAFE_ACTIVE,
) -> tuple[DecisionEngine, DecisionContext]:
    registry = CapabilityRegistry({"candidate": capability(traffic_class=traffic_class)})
    engine = DecisionEngine(registry)
    context = DecisionContext(
        target=Target(
            url="https://example.com/app",
            scope=Scope(allowed_urls=["https://example.com/app"]),
        ),
        candidate_actions=["candidate"],
        policy_snapshot_hash="a" * 64,
        policy_fresh=True,
        allowed_traffic_classes={TrafficClass.PASSIVE, TrafficClass.SAFE_ACTIVE},
        granted_permissions=set(),
        remaining_request_budget=10,
        remaining_risk_budget=10,
    )
    return engine, context


def test_state_changing_scanner_denied_without_permission():
    engine, context = context_for(TrafficClass.STATE_CHANGING)

    record = engine.evaluate(context)

    assert record.outcome is DecisionOutcome.DEFER
    assert record.allowed_actions == []
    assert record.denied_actions["candidate"] == "traffic_class_not_allowed"


def test_stale_policy_stops_all_actions():
    engine, context = context_for()

    record = engine.evaluate(replace(context, policy_fresh=False))

    assert record.outcome is DecisionOutcome.STOP
    assert record.allowed_actions == []


def test_out_of_scope_target_stops_all_actions():
    engine, context = context_for()
    target = Target(
        url="https://example.com.evil.test/app",
        scope=Scope(allowed_domains=["example.com", "*.example.com"]),
    )

    record = engine.evaluate(replace(context, target=target))

    assert record.outcome is DecisionOutcome.STOP
    assert "scope" in record.reason.lower()


def test_ambiguous_non_idempotent_action_escalates():
    registry = CapabilityRegistry(
        {"candidate": capability(idempotent=False)}
    )
    engine, context = context_for()

    record = DecisionEngine(registry).evaluate(replace(context, ambiguous_state=True))

    assert record.outcome is DecisionOutcome.ESCALATE
    assert record.allowed_actions == []


def test_request_budget_denies_expensive_action():
    registry = CapabilityRegistry(
        {"candidate": capability(request_cost=11)}
    )
    engine, context = context_for()

    record = DecisionEngine(registry).evaluate(context)

    assert record.outcome is DecisionOutcome.DEFER
    assert record.denied_actions["candidate"] == "request_budget_exceeded"


def test_allowed_action_continues_with_expected_evidence():
    engine, context = context_for()

    record = engine.evaluate(context)

    assert record.outcome is DecisionOutcome.CONTINUE
    assert record.chosen_action == "candidate"
    assert record.expected_evidence == ["expected-positive", "expected-negative"]


def test_scope_normalization_exact_and_wildcard_hosts():
    scope = Scope(allowed_domains=["example.com", "*.example.com"])

    assert scope.is_in_scope("https://example.com/path")
    assert scope.is_in_scope("https://api.example.com/path")
    assert not scope.is_in_scope("https://example.com.evil.test/path")


def test_scope_normalization_handles_idna():
    scope = Scope(allowed_domains=["xn--bcher-kva.example"])

    assert scope.is_in_scope("https://bücher.example/catalog")


def test_scope_enforces_scheme_and_explicit_port():
    scope = Scope(allowed_urls=["https://example.com:8443/api"])

    assert scope.is_in_scope("https://example.com:8443/api/items")
    assert not scope.is_in_scope("https://example.com/api/items")
    assert not scope.is_in_scope("http://example.com:8443/api/items")


def test_scope_handles_ip_literals_exactly():
    scope = Scope(allowed_domains=["127.0.0.1"])

    assert scope.is_in_scope("http://127.0.0.1:8080/")
    assert not scope.is_in_scope("http://127.0.0.2:8080/")


def test_discovery_does_not_grant_scope():
    target = Target(
        url="https://example.com/",
        scope=Scope(allowed_domains=["example.com"]),
        discovered_urls=["https://outside.test/admin"],
    )

    assert target.scope.is_in_scope(target.discovered_urls[0]) is False
