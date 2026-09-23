from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from core.models import ScanState, Target
from integrations.email.client import SmtpTransportError, TransportReceipt
from integrations.email.config import SecretStr, SmtpSettings
from integrations.email.outbox import (
    AttachmentRejected,
    DeliveryStatus,
    EmailOutbox,
)
from reporting.reporter import Reporter


class FakeTransport:
    def __init__(self, outcomes=None):
        self.outcomes = list(outcomes or ["accepted"])
        self.calls = []

    def send(self, message):
        self.calls.append(message)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return TransportReceipt(
            message_id=str(message["Message-ID"]),
            accepted_recipients=("owner@example.com",),
            accepted_at=datetime.now(UTC).isoformat(),
        )


def _settings(max_bytes=4096):
    return SmtpSettings(
        host="smtp.example.test",
        port=587,
        username="owner@example.com",
        password=SecretStr("synthetic-password"),
        starttls=True,
        report_from="owner@example.com",
        report_to=("owner@example.com",),
        recipient_allowlist=("owner@example.com",),
        max_attachment_bytes=max_bytes,
    )


@pytest.fixture
def report(tmp_path):
    path = tmp_path / "report.json"
    path.write_text('{"scan_id":"safe-scan","findings":[]}', encoding="utf-8")
    return path


def _outbox(tmp_path, transport=None, **kwargs):
    return EmailOutbox(
        tmp_path / "outbox",
        _settings(),
        transport or FakeTransport(),
        jitter=lambda: 0.0,
        **kwargs,
    )


def test_same_report_and_recipients_reuse_idempotency_key(tmp_path, report):
    outbox = _outbox(tmp_path)
    first = outbox.enqueue(report, ["owner@example.com"])
    second = outbox.enqueue(report, ["OWNER@example.com"])

    assert first.idempotency_key == second.idempotency_key
    assert outbox.pending_count == 1


def test_secret_bearing_attachment_is_rejected(tmp_path):
    report = tmp_path / "report.json"
    report.write_text('{"Authorization":"Bearer synthetic"}', encoding="utf-8")

    with pytest.raises(AttachmentRejected, match="redaction"):
        _outbox(tmp_path).enqueue(report, ["owner@example.com"])


def test_oversized_or_non_text_attachment_is_rejected(tmp_path):
    oversized = tmp_path / "large.json"
    oversized.write_text("x" * 20, encoding="utf-8")
    binary = tmp_path / "report.bin"
    binary.write_bytes(b"\xff\xfe")

    with pytest.raises(AttachmentRejected, match="size"):
        EmailOutbox(
            tmp_path / "size-outbox", _settings(max_bytes=10), FakeTransport()
        ).enqueue(oversized, ["owner@example.com"])
    with pytest.raises(AttachmentRejected, match="text"):
        _outbox(tmp_path).enqueue(binary, ["owner@example.com"])


def test_transport_failure_is_retryable_with_bounded_attempts(tmp_path, report):
    transport = FakeTransport([
        SmtpTransportError("first"),
        SmtpTransportError("second"),
        "accepted",
    ])
    outbox = _outbox(tmp_path, transport, max_attempts=2)
    item = outbox.enqueue(report, ["owner@example.com"])

    first = outbox.deliver(item.item_id)
    assert first.status is DeliveryStatus.RETRYABLE
    assert first.attempts == 1
    second = outbox.deliver(item.item_id)
    assert second.status is DeliveryStatus.FAILED
    assert second.attempts == 2
    third = outbox.deliver(item.item_id)
    assert third.status is DeliveryStatus.FAILED
    assert len(transport.calls) == 2


def test_crash_after_acceptance_is_delivery_unknown_and_not_retried(tmp_path, report):
    transport = FakeTransport()

    def crash_after_acceptance(_receipt):
        raise RuntimeError("simulated process crash")

    outbox = _outbox(
        tmp_path,
        transport,
        after_acceptance_hook=crash_after_acceptance,
    )
    item = outbox.enqueue(report, ["owner@example.com"])
    state = outbox.deliver(item.item_id)

    assert state.status is DeliveryStatus.DELIVERY_UNKNOWN
    assert len(transport.calls) == 1


def test_hard_crash_after_acceptance_is_reconciled_as_unknown(tmp_path, report):
    transport = FakeTransport()

    def hard_crash(_receipt):
        raise SystemExit("simulated hard crash before acknowledgement")

    outbox = _outbox(tmp_path, transport, after_acceptance_hook=hard_crash)
    item = outbox.enqueue(report, ["owner@example.com"])
    with pytest.raises(SystemExit):
        outbox.deliver(item.item_id)

    restarted = _outbox(tmp_path, transport)
    state = restarted.deliver(item.item_id)
    assert state.status is DeliveryStatus.DELIVERY_UNKNOWN
    assert len(transport.calls) == 1
    assert outbox.deliver(item.item_id).status is DeliveryStatus.DELIVERY_UNKNOWN
    assert outbox.retry_due(datetime.now(UTC) + timedelta(days=1)) == []
    assert len(transport.calls) == 1


def test_delivered_item_is_never_sent_twice(tmp_path, report):
    transport = FakeTransport()
    outbox = _outbox(tmp_path, transport)
    item = outbox.enqueue(report, ["owner@example.com"])

    delivered = outbox.deliver(item.item_id)
    repeated = outbox.deliver(item.item_id)

    assert delivered.status is DeliveryStatus.DELIVERED
    assert repeated.status is DeliveryStatus.DELIVERED
    assert len(transport.calls) == 1


def test_retry_due_sends_only_due_retryable_items(tmp_path, report):
    transport = FakeTransport([SmtpTransportError("retry"), "accepted"])
    outbox = _outbox(tmp_path, transport)
    item = outbox.enqueue(report, ["owner@example.com"])
    retryable = outbox.deliver(item.item_id)

    assert outbox.retry_due(datetime.now(UTC)) == []
    states = outbox.retry_due(datetime.fromisoformat(retryable.next_attempt_at) + timedelta(seconds=1))
    assert [state.status for state in states] == [DeliveryStatus.DELIVERED]


def test_reporter_prepares_redacted_immutable_artifact_and_manifest(tmp_path):
    reporter = Reporter(str(tmp_path / "reports"))
    state = ScanState(target=Target(url="https://example.test/?token=secret"))
    state.errors.append("password=synthetic")

    artifact = reporter.prepare_email_artifact(state)
    content = Path(artifact.path).read_text(encoding="utf-8")
    manifest = Path(artifact.manifest_path).read_text(encoding="utf-8")

    assert "secret" not in content
    assert "synthetic" not in content
    assert artifact.sha256 in manifest
    assert artifact.size_bytes == Path(artifact.path).stat().st_size
    assert reporter.prepare_email_artifact(state).path == artifact.path
