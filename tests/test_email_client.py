import smtplib
import ssl
from email.message import EmailMessage

import pytest

from integrations.email.client import (
    SmtpAuthenticationError,
    SmtpClient,
    SmtpRecipientError,
    SmtpTimeoutError,
    SmtpTlsError,
)
from integrations.email.config import SecretStr, SmtpSettings


def _settings():
    return SmtpSettings(
        host="smtp.example.test",
        port=587,
        username="owner@example.test",
        password=SecretStr("synthetic-password"),
        starttls=True,
        report_from="owner@example.test",
        report_to=("recipient@example.test",),
        recipient_allowlist=("recipient@example.test",),
        max_attachment_bytes=1024,
    )


def _message():
    message = EmailMessage()
    message["From"] = "owner@example.test"
    message["To"] = "recipient@example.test"
    message["Subject"] = "Synthetic report"
    message.set_content("No real secrets")
    return message


class FakeSmtp:
    def __init__(self, calls, *, tls_error=None, login_error=None, send_error=None):
        self.calls = calls
        self.tls_error = tls_error
        self.login_error = login_error
        self.send_error = send_error

    def ehlo(self):
        self.calls.append(("ehlo",))

    def starttls(self, *, context):
        self.calls.append(("starttls", context))
        if self.tls_error:
            raise self.tls_error

    def login(self, username, password):
        self.calls.append(("login", username, password))
        if self.login_error:
            raise self.login_error

    def send_message(self, message, *, from_addr, to_addrs):
        self.calls.append(("send_message", from_addr, tuple(to_addrs), message))
        if self.send_error:
            raise self.send_error
        return {}

    def quit(self):
        self.calls.append(("quit",))


def _factory(calls, **errors):
    def create(host, port, *, timeout):
        calls.append(("connect", host, port, timeout))
        return FakeSmtp(calls, **errors)

    return create


def test_exact_verified_tls_delivery_sequence(monkeypatch):
    calls = []
    context = object()
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)

    receipt = SmtpClient(_settings(), _factory(calls), timeout=12).send(_message())

    assert [call[0] for call in calls] == [
        "connect", "ehlo", "starttls", "ehlo", "login", "send_message", "quit"
    ]
    assert calls[0] == ("connect", "smtp.example.test", 587, 12)
    assert calls[2][1] is context
    assert calls[4][1:] == ("owner@example.test", "synthetic-password")
    assert receipt.accepted_recipients == ("recipient@example.test",)
    assert receipt.message_id


def test_tls_failure_never_logs_in_or_sends():
    calls = []
    client = SmtpClient(
        _settings(),
        _factory(calls, tls_error=ssl.SSLError("synthetic-password echoed")),
    )

    with pytest.raises(SmtpTlsError) as captured:
        client.send(_message())

    assert "synthetic-password" not in str(captured.value)
    assert "login" not in [call[0] for call in calls]
    assert "send_message" not in [call[0] for call in calls]
    assert calls[-1] == ("quit",)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (smtplib.SMTPAuthenticationError(535, b"synthetic-password"), SmtpAuthenticationError),
        (smtplib.SMTPRecipientsRefused({"recipient@example.test": (550, b"secret")}), SmtpRecipientError),
        (TimeoutError("synthetic-password"), SmtpTimeoutError),
    ],
)
def test_transport_errors_are_typed_and_sanitized(error, expected):
    calls = []
    error_slot = "login_error" if isinstance(error, smtplib.SMTPAuthenticationError) else "send_error"
    client = SmtpClient(_settings(), _factory(calls, **{error_slot: error}))

    with pytest.raises(expected) as captured:
        client.send(_message())

    assert "synthetic-password" not in str(captured.value)
    assert "secret" not in str(captured.value)


def test_message_recipient_must_be_allowlisted():
    message = _message()
    del message["To"]
    message["To"] = "outside@example.test"
    calls = []

    with pytest.raises(SmtpRecipientError, match="recipient policy"):
        SmtpClient(_settings(), _factory(calls)).send(message)

    assert calls == []
