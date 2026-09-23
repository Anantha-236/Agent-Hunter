import pytest

from integrations.email.config import (
    EmailConfigError,
    EmailPolicyError,
    SmtpSettings,
    normalize_mailbox,
    validate_recipients,
)


def _smtp_env(monkeypatch):
    values = {
        "SMTP_HOST": "smtp.example.test",
        "SMTP_PORT": "587",
        "SMTP_USERNAME": "Owner@example.test",
        "SMTP_PASSWORD": "synthetic-secret",
        "SMTP_STARTTLS": "true",
        "SMTP_REPORT_FROM": "Agent Hunter <OWNER@example.test>",
        "SMTP_REPORT_TO": "Owner@example.test, SECOND@example.test",
        "SMTP_RECIPIENT_ALLOWLIST": "owner@example.test,second@example.test",
        "SMTP_MAX_ATTACHMENT_BYTES": "1048576",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_password_never_appears_in_repr(monkeypatch):
    _smtp_env(monkeypatch)
    settings = SmtpSettings.from_env(required=True)

    assert "synthetic-secret" not in repr(settings)
    assert settings.password.get_secret_value() == "synthetic-secret"


def test_recipient_outside_allowlist_is_rejected():
    with pytest.raises(EmailPolicyError, match="not allowlisted"):
        validate_recipients(["other@example.com"], ["owner@example.com"])


@pytest.mark.parametrize(
    "mailbox",
    [
        "owner@example.com\r\nBcc: attacker@example.com",
        "missing-at.example.com",
        "@example.com",
        "owner@",
        "owner@@example.com",
        "owner@exa mple.com",
    ],
)
def test_malformed_or_injected_mailbox_is_rejected(mailbox):
    with pytest.raises(EmailPolicyError):
        normalize_mailbox(mailbox)


def test_mailboxes_are_case_and_idna_normalized_and_deduplicated():
    recipients = validate_recipients(
        ["Owner@EXAMPLE.com", "owner@example.com", "User@bücher.example"],
        ["OWNER@example.COM", "user@xn--bcher-kva.example"],
    )

    assert recipients == (
        "owner@example.com",
        "user@xn--bcher-kva.example",
    )


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("SMTP_HOST", "", "host"),
        ("SMTP_HOST", "smtp.example.test\nINJECTED", "host"),
        ("SMTP_PORT", "not-a-port", "port"),
        ("SMTP_PORT", "70000", "port"),
        ("SMTP_STARTTLS", "false", "STARTTLS"),
        ("SMTP_REPORT_TO", "outside@example.test", "not allowlisted"),
        ("SMTP_MAX_ATTACHMENT_BYTES", "0", "attachment"),
    ],
)
def test_insecure_or_invalid_environment_is_rejected(monkeypatch, key, value, message):
    _smtp_env(monkeypatch)
    monkeypatch.setenv(key, value)

    with pytest.raises(
        (EmailConfigError, EmailPolicyError), match=f"(?i){message}"
    ):
        SmtpSettings.from_env(required=True)


def test_optional_unconfigured_smtp_returns_none(monkeypatch):
    for key in SmtpSettings.environment_keys():
        monkeypatch.delenv(key, raising=False)

    assert SmtpSettings.from_env(required=False) is None


def test_required_unconfigured_smtp_fails(monkeypatch):
    for key in SmtpSettings.environment_keys():
        monkeypatch.delenv(key, raising=False)

    with pytest.raises(EmailConfigError, match="SMTP_HOST"):
        SmtpSettings.from_env(required=True)
