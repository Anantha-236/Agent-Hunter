from __future__ import annotations

import asyncio

import pytest

from core.bbp_policy import BBPPolicy, PolicyEnforcer
from core.models import ScanState, Target
from core.scanner_capabilities import (
    CapabilityError,
    CapabilityRegistry,
    ScannerCapability,
    TrafficClass,
)
from core.base_scanner import BaseScanner, ScannerPolicyDenied


def capability(module: str, traffic_class: TrafficClass) -> ScannerCapability:
    return ScannerCapability(
        module=module,
        version="1.0",
        traffic_class=traffic_class,
        request_cost=1,
        max_concurrency=1,
        required_permissions=(),
        positive_controls=("positive",),
        negative_controls=("negative",),
        fallback_module=None,
        idempotent=True,
    )


def test_unknown_scanner_fails_closed():
    registry = CapabilityRegistry({})

    with pytest.raises(CapabilityError, match="missing capability"):
        registry.require("unknown")


def test_incomplete_capability_is_rejected():
    with pytest.raises(CapabilityError, match="positive control"):
        CapabilityRegistry(
            {
                "weak": ScannerCapability(
                    module="weak",
                    version="1.0",
                    traffic_class=TrafficClass.SAFE_ACTIVE,
                    request_cost=1,
                    max_concurrency=1,
                    required_permissions=(),
                    positive_controls=(),
                    negative_controls=("negative",),
                    fallback_module=None,
                    idempotent=True,
                )
            }
        )


def test_default_registry_covers_orchestrator_registry():
    from core.orchestrator import SCANNER_REGISTRY

    registry = CapabilityRegistry.default()

    assert set(registry.names()) == set(SCANNER_REGISTRY)


def test_policy_denies_disruptive_scanner():
    registry = CapabilityRegistry(
        {"race_condition": capability("race_condition", TrafficClass.DISRUPTIVE)}
    )
    enforcer = PolicyEnforcer(BBPPolicy(), capability_registry=registry)

    allowed, reason = enforcer.is_module_allowed("race_condition")

    assert allowed is False
    assert "disruptive" in reason.lower()


def test_denied_scanner_does_not_execute_run_body():
    class DeniedScanner(BaseScanner):
        name = "state_writer"

        def __init__(self):
            super().__init__(client=None)
            self.executed = False

        async def run(self, state):
            self.executed = True
            return []

    registry = CapabilityRegistry(
        {"state_writer": capability("state_writer", TrafficClass.STATE_CHANGING)}
    )
    enforcer = PolicyEnforcer(BBPPolicy(), capability_registry=registry)
    scanner = DeniedScanner()

    with pytest.raises(ScannerPolicyDenied, match="state_changing"):
        asyncio.run(
            scanner.execute(ScanState(Target(url="https://example.test")), enforcer)
        )

    assert scanner.executed is False
