"""Cross-module acceptance invariants for the modern scanner set."""
from core.orchestrator import SCANNER_REGISTRY, load_scanner
from core.scanner_capabilities import CapabilityRegistry, TrafficClass
from tests.test_scanner_calibration import EXPECTED_TYPES, MAX_REQUESTS


MODERN_MODULES = {
    "openapi_scanner",
    "bola_scanner",
    "mass_assignment_scanner",
    "oauth_oidc_scanner",
    "session_cookie_scanner",
    "cache_behavior_scanner",
    "websocket_scanner",
}


def test_modern_modules_are_mounted_and_calibrated():
    assert MODERN_MODULES <= set(SCANNER_REGISTRY)
    assert set(SCANNER_REGISTRY) == set(EXPECTED_TYPES) == set(MAX_REQUESTS)
    assert all(load_scanner(module) is not None for module in SCANNER_REGISTRY)


def test_modern_traffic_classes_and_permissions_are_explicit():
    registry = CapabilityRegistry.default()
    assert registry.require("openapi_scanner").traffic_class is TrafficClass.PASSIVE
    assert registry.require("oauth_oidc_scanner").traffic_class is TrafficClass.PASSIVE
    assert registry.require("session_cookie_scanner").traffic_class is TrafficClass.PASSIVE
    assert registry.require("bola_scanner").traffic_class is TrafficClass.SAFE_ACTIVE
    assert registry.require("cache_behavior_scanner").traffic_class is TrafficClass.SAFE_ACTIVE
    assert registry.require("websocket_scanner").traffic_class is TrafficClass.SAFE_ACTIVE
    mass = registry.require("mass_assignment_scanner")
    assert mass.traffic_class is TrafficClass.STATE_CHANGING
    assert mass.required_permissions == ("mass_assignment_testing",)
    assert mass.idempotent is False


def test_discovery_and_gated_modules_do_not_claim_fixture_vulnerability_types():
    for module in MODERN_MODULES:
        assert EXPECTED_TYPES[module] == ()
