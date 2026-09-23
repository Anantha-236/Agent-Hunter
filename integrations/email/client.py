"""TLS-only, outbound SMTP transport with sanitized failure states."""
from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import getaddresses, make_msgid
from socket import timeout as SocketTimeout
from typing import Callable

from integrations.email.config import (
    EmailPolicyError,
    SmtpSettings,
    normalize_mailbox,
    validate_recipients,
)


class SmtpTransportError(RuntimeError):
    """Base class for sanitized SMTP transport errors."""


class SmtpTlsError(SmtpTransportError):
    pass


class SmtpAuthenticationError(SmtpTransportError):
    pass


class SmtpRecipientError(SmtpTransportError):
    pass


class SmtpTimeoutError(SmtpTransportError):
    pass


@dataclass(frozen=True)
class TransportReceipt:
    message_id: str
    accepted_recipients: tuple[str, ...]
    accepted_at: str


class SmtpClient:
    def __init__(
        self,
        settings: SmtpSettings,
        smtp_factory: Callable = smtplib.SMTP,
        *,
        timeout: float = 30.0,
    ):
        if not settings.starttls:
            raise SmtpTlsError("verified STARTTLS is mandatory")
        if timeout <= 0:
            raise ValueError("SMTP timeout must be positive")
        self.settings = settings
        self.smtp_factory = smtp_factory
        self.timeout = timeout

    def _message_recipients(self, message: EmailMessage) -> tuple[str, ...]:
        raw_headers = []
        for header in ("to", "cc", "bcc"):
            raw_headers.extend(message.get_all(header, []))
        parsed = [address for _name, address in getaddresses(raw_headers) if address]
        try:
            return validate_recipients(
                parsed,
                self.settings.recipient_allowlist,
            )
        except EmailPolicyError as exc:
            raise SmtpRecipientError(
                "message recipient policy validation failed"
            ) from exc

    def _validate_sender(self, message: EmailMessage) -> None:
        try:
            sender = normalize_mailbox(message.get("from", ""))
        except EmailPolicyError as exc:
            raise SmtpRecipientError("message sender policy validation failed") from exc
        if sender != self.settings.report_from:
            raise SmtpRecipientError("message sender policy validation failed")

    @staticmethod
    def _raise_sanitized(exc: Exception) -> None:
        if isinstance(exc, smtplib.SMTPAuthenticationError):
            raise SmtpAuthenticationError("SMTP authentication failed") from exc
        if isinstance(exc, smtplib.SMTPRecipientsRefused):
            raise SmtpRecipientError("SMTP server refused one or more recipients") from exc
        if isinstance(exc, (TimeoutError, SocketTimeout)):
            raise SmtpTimeoutError("SMTP operation timed out") from exc
        if isinstance(exc, (ssl.SSLError, smtplib.SMTPNotSupportedError)):
            raise SmtpTlsError("verified STARTTLS negotiation failed") from exc
        if isinstance(exc, SmtpTransportError):
            raise exc
        raise SmtpTransportError("SMTP delivery failed") from exc

    def send(self, message: EmailMessage) -> TransportReceipt:
        self._validate_sender(message)
        recipients = self._message_recipients(message)
        if "Message-ID" not in message:
            message["Message-ID"] = make_msgid(domain="agent-hunter.local")
        message_id = str(message["Message-ID"])

        smtp = None
        accepted = False
        try:
            smtp = self.smtp_factory(
                self.settings.host,
                self.settings.port,
                timeout=self.timeout,
            )
            smtp.ehlo()
            context = ssl.create_default_context()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(
                self.settings.username,
                self.settings.password.get_secret_value(),
            )
            refused = smtp.send_message(
                message,
                from_addr=self.settings.report_from,
                to_addrs=list(recipients),
            )
            if refused:
                raise smtplib.SMTPRecipientsRefused(refused)
            accepted = True
            return TransportReceipt(
                message_id=message_id,
                accepted_recipients=recipients,
                accepted_at=datetime.now(UTC).isoformat(),
            )
        except Exception as exc:
            self._raise_sanitized(exc)
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    # Acceptance already has a receipt. A QUIT failure must not
                    # turn an accepted delivery into an automatic retry.
                    if not accepted:
                        pass
