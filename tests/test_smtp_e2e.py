import logging
import smtplib
from datetime import UTC, datetime

from core.models import ScanState, Target
from integrations.email.client import SmtpClient
from integrations.email.config import SecretStr, SmtpSettings
from integrations.email.outbox import DeliveryStatus, EmailOutbox
from reporting.reporter import Reporter


class SyntheticSmtpServer:
    def __init__(self):
        self.connections = 0
        self.tls_negotiations = 0
        self.logins = 0
        self.send_attempts = 0
        self.accepted_messages = []
        self.events = []

    def factory(self, host, port, *, timeout):
        self.connections += 1
        self.events.append(("connect", host, port, timeout))
        return SyntheticSmtpConnection(self)


class SyntheticSmtpConnection:
    def __init__(self, server):
        self.server = server

    def ehlo(self):
        self.server.events.append(("ehlo",))

    def starttls(self, *, context):
        assert context.check_hostname is True
        assert context.verify_mode != 0
        self.server.tls_negotiations += 1
        self.server.events.append(("starttls",))

    def login(self, username, password):
        assert username == "owner@example.test"
        assert password == "smtp-synthetic-password"
        self.server.logins += 1
        self.server.events.append(("login",))

    def send_message(self, message, *, from_addr, to_addrs):
        self.server.send_attempts += 1
        self.server.events.append(("send_message",))
        if self.server.send_attempts == 1:
            raise smtplib.SMTPServerDisconnected("synthetic retry")
        self.server.accepted_messages.append(message)
        return {}

    def quit(self):
        self.server.events.append(("quit",))


def test_outbound_smtp_end_to_end_is_tls_redacted_and_idempotent(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    settings = SmtpSettings(
        host="smtp.example.test",
        port=587,
        username="owner@example.test",
        password=SecretStr("smtp-synthetic-password"),
        starttls=True,
        report_from="owner@example.test",
        report_to=("owner@example.test",),
        recipient_allowlist=("owner@example.test",),
        max_attachment_bytes=1024 * 1024,
    )
    server = SyntheticSmtpServer()
    transport = SmtpClient(settings, server.factory, timeout=5)
    outbox = EmailOutbox(
        tmp_path / "outbox",
        settings,
        transport,
        base_backoff_seconds=1,
        jitter=lambda: 0,
    )

    state = ScanState(
        target=Target(url="https://example.test/?token=url-synthetic-token")
    )
    state.errors.append("cookie=session-synthetic-cookie")
    artifact = Reporter(str(tmp_path / "reports")).prepare_email_artifact(state)
    first = outbox.enqueue(artifact.path, ["OWNER@example.test"])
    duplicate = outbox.enqueue(artifact.path, ["owner@example.test"])
    assert first.item_id == duplicate.item_id
    assert outbox.pending_count == 1

    retryable = outbox.deliver(first.item_id)
    assert retryable.status is DeliveryStatus.RETRYABLE
    delivered = outbox.deliver(first.item_id)
    assert delivered.status is DeliveryStatus.DELIVERED
    repeated = outbox.deliver(first.item_id)
    assert repeated.status is DeliveryStatus.DELIVERED

    assert server.connections == 2
    assert server.tls_negotiations == 2
    assert server.logins == 2
    assert server.send_attempts == 2
    assert len(server.accepted_messages) == 1

    captured = server.accepted_messages[0].as_string()
    logs = caplog.text
    for secret in (
        "smtp-synthetic-password",
        "url-synthetic-token",
        "session-synthetic-cookie",
    ):
        assert secret not in captured
        assert secret not in logs
    assert "owner@example.test" in captured
    assert "Agent-Hunter redacted scan report" in captured
