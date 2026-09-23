"""Durable, content-addressed report email outbox."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from enum import Enum
from pathlib import Path
from typing import Callable

from core.evidence import Redactor
from core.recovery import AtomicJsonStore
from integrations.email.client import SmtpClient, SmtpTransportError, TransportReceipt
from integrations.email.config import SmtpSettings, validate_recipients


OUTBOX_SCHEMA = "agent-hunter.email-outbox.v1"
TEMPLATE_VERSION = "report-attachment-v1"


class AttachmentRejected(ValueError):
    pass


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    RETRYABLE = "retryable"
    DELIVERY_UNKNOWN = "delivery_unknown"
    DELIVERED = "delivered"
    FAILED = "failed"


@dataclass(frozen=True)
class OutboxItem:
    item_id: str
    idempotency_key: str
    report_path: str
    report_sha256: str
    recipients: tuple[str, ...]
    status: DeliveryStatus


@dataclass(frozen=True)
class DeliveryState:
    item_id: str
    status: DeliveryStatus
    attempts: int
    next_attempt_at: str | None = None
    message_id: str = ""
    reason: str = ""


class EmailOutbox:
    def __init__(
        self,
        root: str | Path,
        settings: SmtpSettings,
        transport: SmtpClient,
        *,
        max_attempts: int = 3,
        base_backoff_seconds: int = 60,
        jitter: Callable[[], float] | None = None,
        after_acceptance_hook: Callable[[TransportReceipt], None] | None = None,
    ):
        self.root = Path(root)
        self.items_dir = self.root / "items"
        self.attachments_dir = self.root / "attachments"
        self.settings = settings
        self.transport = transport
        self.max_attempts = max(1, int(max_attempts))
        self.base_backoff_seconds = max(1, int(base_backoff_seconds))
        self.jitter = jitter or (lambda: secrets.randbelow(1000) / 1000.0)
        self.after_acceptance_hook = after_acceptance_hook
        self.redactor = Redactor()

    def _path(self, item_id: str) -> Path:
        return self.items_dir / f"{item_id}.json"

    def _store(self, item_id: str) -> AtomicJsonStore:
        return AtomicJsonStore(self._path(item_id), OUTBOX_SCHEMA, retain=3)

    @staticmethod
    def _digest(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def _validate_attachment(self, path: Path) -> tuple[bytes, str]:
        if not path.is_file() or path.is_symlink():
            raise AttachmentRejected("attachment must be a regular report file")
        size = path.stat().st_size
        if size > self.settings.max_attachment_bytes:
            raise AttachmentRejected("attachment size exceeds configured limit")
        try:
            content = path.read_bytes()
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AttachmentRejected("attachment must be UTF-8 text") from exc

        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            if self.redactor.redact_text(text) != text:
                raise AttachmentRejected("attachment failed redaction validation")
        else:
            if self.redactor.redact(decoded) != decoded:
                raise AttachmentRejected("attachment failed redaction validation")
        return content, self._digest(content)

    def _payload_to_item(self, payload: dict) -> OutboxItem:
        return OutboxItem(
            item_id=payload["item_id"],
            idempotency_key=payload["idempotency_key"],
            report_path=payload["report_path"],
            report_sha256=payload["report_sha256"],
            recipients=tuple(payload["recipients"]),
            status=DeliveryStatus(payload["status"]),
        )

    def _payload_to_state(self, payload: dict) -> DeliveryState:
        return DeliveryState(
            item_id=payload["item_id"],
            status=DeliveryStatus(payload["status"]),
            attempts=int(payload.get("attempts", 0)),
            next_attempt_at=payload.get("next_attempt_at"),
            message_id=payload.get("message_id", ""),
            reason=payload.get("reason", ""),
        )

    def enqueue(self, report, recipients) -> OutboxItem:
        source = Path(report).resolve()
        content, report_digest = self._validate_attachment(source)
        normalized = tuple(sorted(validate_recipients(
            recipients, self.settings.recipient_allowlist
        )))
        identity = json.dumps(
            {
                "report_sha256": report_digest,
                "recipients": normalized,
                "template_version": TEMPLATE_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        key = hashlib.sha256(identity).hexdigest()
        store = self._store(key)
        if store.path.exists():
            return self._payload_to_item(store.read())

        self.attachments_dir.mkdir(parents=True, exist_ok=True)
        attachment = self.attachments_dir / f"{key}{source.suffix.lower()}"
        temporary = attachment.with_name(f"{attachment.name}.tmp.{secrets.token_hex(6)}")
        if not attachment.exists():
            try:
                with open(temporary, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, attachment)
            finally:
                temporary.unlink(missing_ok=True)

        now = datetime.now(UTC).isoformat()
        payload = {
            "item_id": key,
            "idempotency_key": key,
            "report_path": str(attachment),
            "report_sha256": report_digest,
            "recipients": list(normalized),
            "status": DeliveryStatus.PENDING.value,
            "attempts": 0,
            "next_attempt_at": None,
            "message_id": "",
            "reason": "queued",
            "created_at": now,
            "updated_at": now,
            "template_version": TEMPLATE_VERSION,
        }
        store.write(payload)
        return self._payload_to_item(payload)

    def _message(self, payload: dict) -> EmailMessage:
        path = Path(payload["report_path"])
        message = EmailMessage()
        message["From"] = self.settings.report_from
        message["To"] = ", ".join(payload["recipients"])
        message["Subject"] = "Agent-Hunter redacted scan report"
        message["Message-ID"] = f"<{payload['idempotency_key']}@agent-hunter.local>"
        message.set_content(
            "Agent-Hunter generated the attached redacted report. "
            "Review it manually before any disclosure or submission."
        )
        message.add_attachment(
            path.read_bytes(),
            maintype="application",
            subtype="octet-stream",
            filename=path.name,
        )
        return message

    def _write_state(self, store: AtomicJsonStore, payload: dict) -> DeliveryState:
        payload["updated_at"] = datetime.now(UTC).isoformat()
        store.write(payload)
        return self._payload_to_state(payload)

    def deliver(self, item_id: str) -> DeliveryState:
        store = self._store(item_id)
        payload = store.read()
        status = DeliveryStatus(payload["status"])
        if (
            status is DeliveryStatus.PENDING
            and int(payload.get("attempts", 0)) > 0
            and payload.get("reason") == "delivery_attempt_started"
        ):
            payload["status"] = DeliveryStatus.DELIVERY_UNKNOWN.value
            payload["next_attempt_at"] = None
            payload["reason"] = "prior_delivery_attempt_has_ambiguous_outcome"
            return self._write_state(store, payload)
        if status in {
            DeliveryStatus.DELIVERED,
            DeliveryStatus.DELIVERY_UNKNOWN,
            DeliveryStatus.FAILED,
        }:
            return self._payload_to_state(payload)

        payload["attempts"] = int(payload.get("attempts", 0)) + 1
        payload["status"] = DeliveryStatus.PENDING.value
        payload["reason"] = "delivery_attempt_started"
        self._write_state(store, payload)

        try:
            receipt = self.transport.send(self._message(payload))
        except SmtpTransportError:
            if payload["attempts"] >= self.max_attempts:
                payload["status"] = DeliveryStatus.FAILED.value
                payload["next_attempt_at"] = None
                payload["reason"] = "maximum_delivery_attempts_reached"
            else:
                delay = self.base_backoff_seconds * (2 ** (payload["attempts"] - 1))
                delay += delay * 0.1 * max(0.0, min(1.0, float(self.jitter())))
                payload["status"] = DeliveryStatus.RETRYABLE.value
                payload["next_attempt_at"] = (
                    datetime.now(UTC) + timedelta(seconds=delay)
                ).isoformat()
                payload["reason"] = "sanitized_transport_failure"
            return self._write_state(store, payload)

        try:
            if self.after_acceptance_hook:
                self.after_acceptance_hook(receipt)
        except Exception:
            payload["status"] = DeliveryStatus.DELIVERY_UNKNOWN.value
            payload["next_attempt_at"] = None
            payload["message_id"] = receipt.message_id
            payload["reason"] = "accepted_but_local_acknowledgement_uncertain"
            return self._write_state(store, payload)

        payload["status"] = DeliveryStatus.DELIVERED.value
        payload["next_attempt_at"] = None
        payload["message_id"] = receipt.message_id
        payload["reason"] = "transport_accepted_and_acknowledged"
        return self._write_state(store, payload)

    def retry_due(self, now: datetime) -> list[DeliveryState]:
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        results = []
        if not self.items_dir.exists():
            return results
        for path in sorted(self.items_dir.glob("*.json")):
            payload = AtomicJsonStore(path, OUTBOX_SCHEMA, retain=3).read()
            if payload.get("status") != DeliveryStatus.RETRYABLE.value:
                continue
            due = datetime.fromisoformat(payload["next_attempt_at"])
            if due <= now:
                results.append(self.deliver(payload["item_id"]))
        return results

    @property
    def pending_count(self) -> int:
        if not self.items_dir.exists():
            return 0
        count = 0
        for path in self.items_dir.glob("*.json"):
            payload = AtomicJsonStore(path, OUTBOX_SCHEMA, retain=3).read()
            if payload.get("status") in {
                DeliveryStatus.PENDING.value,
                DeliveryStatus.RETRYABLE.value,
            }:
                count += 1
        return count
