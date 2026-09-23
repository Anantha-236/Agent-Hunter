"""Outbound-only report email integration.

This package deliberately has no inbox, OTP, IMAP, or platform-login support.
"""

from integrations.email.config import SmtpSettings

__all__ = ["SmtpSettings"]
