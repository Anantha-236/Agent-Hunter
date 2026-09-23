from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.models import (
    CoverageRecord,
    CoverageStatus,
    DecisionOutcome,
    DecisionRecord,
    EvidenceRef,
    EvidenceStatus,
    Finding,
    ScanState,
    Target,
)


def test_legacy_confirmed_maps_to_confirmed():
    finding = Finding(confirmed=True, false_positive=False)

    finding.normalize_legacy_status()

    assert finding.evidence_status is EvidenceStatus.CONFIRMED


def test_contradictory_legacy_flags_are_unresolved():
    finding = Finding(confirmed=True, false_positive=True)

    finding.normalize_legacy_status()

    assert finding.evidence_status is EvidenceStatus.UNRESOLVED


def test_legacy_false_positive_maps_to_refuted():
    finding = Finding(false_positive=True)

    finding.normalize_legacy_status()

    assert finding.evidence_status is EvidenceStatus.REFUTED


def test_finding_dict_has_explicit_evidence_status():
    finding = Finding(evidence_status=EvidenceStatus.SUSPECTED)

    assert finding.to_dict()["evidence_status"] == "suspected"


def test_confirmed_requires_validator_reference():
    finding = Finding(
        evidence_status=EvidenceStatus.CONFIRMED,
        evidence_refs=[],
    )

    with pytest.raises(ValueError, match="validator evidence"):
        finding.validate_evidence_state()


def test_confirmed_accepts_validator_reference():
    finding = Finding(
        evidence_status=EvidenceStatus.CONFIRMED,
        evidence_refs=[
            EvidenceRef(
                evidence_id="evidence-1",
                kind="validator",
                captured_at=datetime(2026, 9, 23, tzinfo=UTC),
                digest="a" * 64,
                redacted=True,
            )
        ],
    )

    finding.validate_evidence_state()


def test_scan_state_serializes_decisions_and_coverage_without_callbacks():
    state = ScanState(target=Target(url="https://example.test"))
    state.decisions.append(
        DecisionRecord(
            decision_id="decision-1",
            outcome=DecisionOutcome.DEFER,
            reason="Needs a second test identity",
            policy_snapshot_hash="b" * 64,
        )
    )
    state.coverage.append(
        CoverageRecord(
            module="bola_scanner",
            status=CoverageStatus.DEFERRED,
            reason="second identity unavailable",
        )
    )

    data = state.to_dict()

    assert data["decisions"][0]["outcome"] == "defer"
    assert data["coverage"][0]["status"] == "deferred"
    assert "thought_callback" not in data


def test_evidence_enum_values_are_stable():
    assert {status.value for status in EvidenceStatus} == {
        "not_tested",
        "observed",
        "suspected",
        "confirmed",
        "refuted",
        "unresolved",
    }
