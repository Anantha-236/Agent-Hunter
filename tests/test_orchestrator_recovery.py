import asyncio
import json

import pytest

from core.models import DecisionOutcome, Scope, ScanState, Target
from core.orchestrator import Orchestrator, ResumeBlocked
from core.recovery import AtomicJsonStore
from core.scanner_capabilities import CapabilityRegistry


def _target() -> Target:
    return Target(
        url="https://example.test/",
        scope=Scope(allowed_domains=["example.test"]),
    )


def _orchestrator(tmp_path, *, modules=None, registry=None) -> Orchestrator:
    return Orchestrator(
        _target(),
        modules=modules or ["header_security"],
        use_ai=False,
        use_tui=False,
        use_memory=False,
        checkpoint_root=tmp_path,
        capability_registry=registry,
        policy_snapshot_hash="policy-v1",
    )


def test_resume_uses_last_known_good_checkpoint(tmp_path):
    orchestrator = _orchestrator(tmp_path)
    state = ScanState(target=orchestrator.target, policy_snapshot_hash="policy-v1")
    state.phase = "scan"
    state.modules_pending = ["header_security"]
    orchestrator._save_checkpoint(state)

    state.modules_run = ["header_security"]
    state.modules_pending = []
    orchestrator._save_checkpoint(state)
    checkpoint = orchestrator.checkpoint_path_for(state.scan_id)
    checkpoint.write_text("{corrupt", encoding="utf-8")

    resumed = orchestrator.resume(checkpoint, policy_hash="policy-v1")

    assert resumed.modules_run == []
    assert resumed.modules_pending == ["header_security"]
    assert json.loads(checkpoint.read_text(encoding="utf-8"))["generation"] == 1


def test_resume_rejects_changed_policy_hash(tmp_path):
    orchestrator = _orchestrator(tmp_path)
    state = ScanState(target=orchestrator.target, policy_snapshot_hash="policy-v1")
    orchestrator._save_checkpoint(state)

    with pytest.raises(ResumeBlocked, match="policy snapshot changed"):
        orchestrator.resume(
            orchestrator.checkpoint_path_for(state.scan_id),
            policy_hash="different",
        )


def test_resume_escalates_unfinished_non_idempotent_action(tmp_path):
    orchestrator = _orchestrator(tmp_path, modules=["csrf_scanner"])
    state = ScanState(target=orchestrator.target, policy_snapshot_hash="policy-v1")
    state.action_journal["csrf-1"] = {
        "module": "csrf_scanner",
        "status": "started",
        "idempotent": False,
    }
    orchestrator._save_checkpoint(state)

    resumed = orchestrator.resume(
        orchestrator.checkpoint_path_for(state.scan_id),
        policy_hash="policy-v1",
    )

    assert resumed.decisions[-1].outcome is DecisionOutcome.ESCALATE
    assert "csrf_scanner" not in resumed.modules_pending
    assert resumed.action_journal["csrf-1"]["status"] == "ambiguous"


def test_missing_capability_metadata_never_constructs_scanner(tmp_path, monkeypatch):
    constructed = []

    class ScannerSpy:
        def __init__(self, _client):
            constructed.append(True)

    registry = CapabilityRegistry({})
    orchestrator = _orchestrator(
        tmp_path,
        modules=["unknown_scanner"],
        registry=registry,
    )
    monkeypatch.setattr("core.orchestrator.load_scanner", lambda _name: ScannerSpy)
    state = ScanState(
        target=orchestrator.target,
        modules_pending=["unknown_scanner"],
        policy_snapshot_hash="policy-v1",
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(orchestrator._phase_scan(state))

    assert constructed == []
    assert state.coverage[-1].module == "unknown_scanner"
    assert state.coverage[-1].status.value == "deferred"
    assert state.decisions[-1].denied_actions == {
        "unknown_scanner": "capability_metadata_missing"
    }


def test_legacy_checkpoint_requires_policy_reacknowledgement(tmp_path):
    checkpoint = tmp_path / "scan_checkpoint.json"
    checkpoint.write_text(
        json.dumps({"scan_id": "legacy", "target_url": "https://example.test/"}),
        encoding="utf-8",
    )
    orchestrator = _orchestrator(tmp_path)

    with pytest.raises(ResumeBlocked, match="legacy checkpoint"):
        orchestrator.resume(checkpoint, policy_hash="policy-v1")


def test_checkpoint_is_an_atomic_versioned_envelope(tmp_path):
    orchestrator = _orchestrator(tmp_path)
    state = ScanState(target=orchestrator.target, policy_snapshot_hash="policy-v1")
    orchestrator._save_checkpoint(state)

    checkpoint = orchestrator.checkpoint_path_for(state.scan_id)
    envelope = json.loads(checkpoint.read_text(encoding="utf-8"))

    assert checkpoint == tmp_path / state.scan_id / "checkpoint.json"
    assert envelope["schema"] == "agent-hunter.scan-checkpoint.v2"
    assert envelope["payload"]["target_url"] == "https://example.test/"
    assert AtomicJsonStore(checkpoint, envelope["schema"]).read()["scan_id"] == state.scan_id


def test_repeated_module_failures_quarantine_only_that_module(tmp_path):
    orchestrator = _orchestrator(
        tmp_path,
        modules=["header_security", "ssl_tls_scanner"],
    )
    state = ScanState(
        target=orchestrator.target,
        policy_snapshot_hash="policy-v1",
        failure_counts={"header_security": 3},
    )

    quarantined = orchestrator._decide_module(state, "header_security")
    unrelated = orchestrator._decide_module(state, "ssl_tls_scanner")

    assert quarantined.outcome is DecisionOutcome.DEFER
    assert quarantined.denied_actions["header_security"] == (
        "module_quarantined_after_failures"
    )
    assert unrelated.outcome is DecisionOutcome.CONTINUE
