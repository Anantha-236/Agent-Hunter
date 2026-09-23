import json

from core.models import (
    CoverageRecord,
    CoverageStatus,
    DecisionOutcome,
    DecisionRecord,
    EvidenceStatus,
    Finding,
    ScanState,
    Target,
)
from reporting.reporter import Reporter


def _state_with_every_status() -> ScanState:
    state = ScanState(
        target=Target(url="https://example.test/?token=query-secret"),
        policy_snapshot_hash="policy-hash-1",
    )
    for status in EvidenceStatus:
        state.findings.append(Finding(
            title=f"{status.value} finding",
            evidence_status=status,
            evidence="password=supersecret",
            request="Authorization: Bearer bearer-secret",
            url="https://example.test/?otp=123456",
        ))
    for status in CoverageStatus:
        state.coverage.append(CoverageRecord(
            module=f"module-{status.value}",
            status=status,
            reason="token=coverage-secret",
        ))
    state.decisions.append(DecisionRecord(
        outcome=DecisionOutcome.DEFER,
        reason="password=decision-secret",
        policy_snapshot_hash="policy-hash-1",
    ))
    state.errors.append("cookie=session-secret")
    state.agent_thoughts.append("api_key=thought-secret")
    return state


def test_json_report_separates_evidence_and_coverage_states(tmp_path):
    report = Reporter(str(tmp_path)).generate_json(_state_with_every_status())

    assert report["evidence_counts"] == {status.value: 1 for status in EvidenceStatus}
    assert report["coverage_counts"] == {status.value: 1 for status in CoverageStatus}
    assert set(report["findings_by_evidence_status"]) == {
        status.value for status in EvidenceStatus
    }
    assert report["policy_snapshot_hash"] == "policy-hash-1"
    assert report["decisions"][0]["reason"] == "password=[REDACTED]"


def test_all_report_formats_redact_secrets_and_show_separate_sections(tmp_path):
    state = _state_with_every_status()
    reporter = Reporter(str(tmp_path))
    markdown = reporter.generate_markdown(state, "token=summary-secret")
    html = reporter.generate_html(state, "token=summary-secret")
    serialized_json = json.dumps(reporter.generate_json(state, "token=summary-secret"))

    for rendered in (markdown, html, serialized_json):
        for secret in (
            "query-secret", "supersecret", "bearer-secret", "123456",
            "coverage-secret", "decision-secret", "session-secret",
            "thought-secret", "summary-secret",
        ):
            assert secret not in rendered

    for status in EvidenceStatus:
        assert status.value.replace("_", " ").title() in markdown
        assert status.value in html
    for status in CoverageStatus:
        assert status.value in serialized_json
