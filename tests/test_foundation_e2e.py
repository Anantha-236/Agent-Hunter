import asyncio
import json
import threading
from http.server import HTTPServer

import pytest

from core.decision_engine import DecisionContext, DecisionEngine
from core.models import (
    CoverageRecord,
    CoverageStatus,
    DecisionOutcome,
    ScanState,
    Scope,
    Target,
)
from core.orchestrator import Orchestrator
from core.scanner_capabilities import CapabilityRegistry, TrafficClass
from reporting.reporter import Reporter
from scanners.misconfig.header_security import HeaderSecurityScanner
from tests.vuln_server import VulnHandler
from utils.http_client import HttpClient, ScopeViolationError


def _run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@pytest.fixture
def local_vulnerable_server():
    server = HTTPServer(("127.0.0.1", 0), VulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _decision(target, module, *, classes, permissions=()):
    registry = CapabilityRegistry.default()
    return DecisionEngine(registry).evaluate(DecisionContext(
        target=target,
        candidate_actions=[module],
        policy_snapshot_hash="local-e2e-policy-v1",
        policy_fresh=True,
        allowed_traffic_classes=set(classes),
        granted_permissions=set(permissions),
        remaining_request_budget=500,
        remaining_risk_budget=20,
    ))


def test_foundation_restore_drill(tmp_path, local_vulnerable_server):
    base_url = local_vulnerable_server
    target = Target(
        url=base_url,
        scope=Scope(allowed_urls=[base_url]),
    )

    allowed = _decision(target, "header_security", classes={TrafficClass.PASSIVE})
    denied = _decision(target, "race_condition", classes={TrafficClass.PASSIVE})
    assert allowed.outcome is DecisionOutcome.CONTINUE
    assert denied.outcome is DecisionOutcome.DEFER

    async def exercise_network():
        async with HttpClient(scope=target.scope, rate_limit=100) as client:
            scanner = HeaderSecurityScanner(client)
            state = ScanState(
                target=target,
                policy_snapshot_hash="local-e2e-policy-v1",
            )
            findings = await scanner.run(state)
            assert findings

        redirect_scope = Scope(allowed_urls=[f"{base_url}/login"])
        redirect = (
            f"{base_url}/login?redirect="
            f"//127.0.0.1:{base_url.rsplit(':', 1)[1]}/outside"
        )
        async with HttpClient(scope=redirect_scope, rate_limit=100) as client:
            with pytest.raises(ScopeViolationError, match="OUT-OF-SCOPE"):
                await client.get(redirect)

        return findings

    findings = _run(exercise_network())

    orchestrator = Orchestrator(
        target,
        modules=["header_security", "csrf_scanner"],
        use_ai=False,
        use_tui=False,
        use_memory=False,
        checkpoint_root=tmp_path / "checkpoints",
        policy_snapshot_hash="local-e2e-policy-v1",
    )
    state = ScanState(
        target=target,
        phase="scan",
        findings=findings,
        modules_run=["csrf_scanner"],
        modules_pending=["header_security"],
        policy_snapshot_hash="local-e2e-policy-v1",
    )
    state.action_journal["csrf-complete"] = {
        "module": "csrf_scanner",
        "status": "completed",
        "idempotent": False,
    }
    state.coverage.append(CoverageRecord(
        module="csrf_scanner",
        status=CoverageStatus.TESTED,
        reason="synthetic reversible local action completed",
    ))
    orchestrator._save_checkpoint(state)

    state.modules_run.append("transient-module")
    orchestrator._save_checkpoint(state)
    checkpoint = orchestrator.checkpoint_path_for(state.scan_id)
    checkpoint.write_text("{simulated crash", encoding="utf-8")

    resumed = orchestrator.resume(
        checkpoint,
        policy_hash="local-e2e-policy-v1",
    )
    assert resumed.checkpoint_generation == 1
    assert resumed.modules_run == ["csrf_scanner"]
    assert resumed.modules_pending == ["header_security"]
    assert resumed.action_journal["csrf-complete"]["status"] == "completed"
    assert not any(
        decision.outcome is DecisionOutcome.ESCALATE
        for decision in resumed.decisions
    )

    resumed.errors.append("password=foundation-secret")
    reporter = Reporter(str(tmp_path / "reports"))
    markdown = reporter.generate_markdown(resumed)
    html = reporter.generate_html(resumed)
    structured = json.dumps(reporter.generate_json(resumed))
    for report in (markdown, html, structured):
        assert "foundation-secret" not in report
        assert "[REDACTED]" in report
