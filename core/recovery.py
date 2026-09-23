"""Atomic, checksummed JSON persistence with bounded recovery snapshots."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class RecoveryError(ValueError):
    """Raised when persisted state is invalid or cannot be recovered."""


@dataclass(frozen=True)
class StoredEnvelope:
    schema: str
    generation: int
    written_at: str
    payload: dict[str, Any]
    checksum: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "generation": self.generation,
            "written_at": self.written_at,
            "payload": self.payload,
            "checksum": self.checksum,
        }


class AtomicJsonStore:
    """Persist JSON without exposing a partially written active file."""

    def __init__(self, path: Path, schema: str, retain: int = 3):
        self.path = Path(path)
        self.schema = schema
        self.retain = max(0, int(retain))

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def _checksum(cls, value: dict[str, Any]) -> str:
        return hashlib.sha256(cls._canonical(value)).hexdigest()

    def _unsigned(self, envelope: StoredEnvelope) -> dict[str, Any]:
        return {
            "schema": envelope.schema,
            "generation": envelope.generation,
            "written_at": envelope.written_at,
            "payload": envelope.payload,
        }

    def _new_envelope(
        self,
        payload: dict[str, Any],
        generation: int,
    ) -> StoredEnvelope:
        unsigned = {
            "schema": self.schema,
            "generation": generation,
            "written_at": datetime.now(UTC).isoformat(),
            "payload": payload,
        }
        return StoredEnvelope(
            **unsigned,
            checksum=self._checksum(unsigned),
        )

    def _decode(self, path: Path) -> StoredEnvelope:
        try:
            with open(path, "r", encoding="utf-8") as stream:
                raw = json.load(stream)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise RecoveryError(f"invalid JSON state at {path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise RecoveryError(f"state envelope at {path} is not a dictionary")
        required = {"schema", "generation", "written_at", "payload", "checksum"}
        if not required.issubset(raw):
            missing = ", ".join(sorted(required.difference(raw)))
            raise RecoveryError(f"state envelope at {path} is missing: {missing}")
        if raw["schema"] != self.schema:
            raise RecoveryError(
                f"schema mismatch at {path}: {raw['schema']!r} != {self.schema!r}"
            )
        if not isinstance(raw["payload"], dict):
            raise RecoveryError(f"payload at {path} is not a dictionary")

        unsigned = {
            "schema": raw["schema"],
            "generation": raw["generation"],
            "written_at": raw["written_at"],
            "payload": raw["payload"],
        }
        expected = self._checksum(unsigned)
        if not hmac.compare_digest(str(raw["checksum"]), expected):
            raise RecoveryError(f"checksum mismatch at {path}")
        try:
            generation = int(raw["generation"])
        except (TypeError, ValueError) as exc:
            raise RecoveryError(f"invalid generation at {path}") from exc
        if generation < 1:
            raise RecoveryError(f"invalid generation at {path}")

        return StoredEnvelope(
            schema=raw["schema"],
            generation=generation,
            written_at=str(raw["written_at"]),
            payload=raw["payload"],
            checksum=str(raw["checksum"]),
        )

    def _backup_path(self, generation: int) -> Path:
        return self.path.with_name(f"{self.path.name}.bak.{generation:020d}")

    def _backups(self) -> list[Path]:
        return sorted(self.path.parent.glob(f"{self.path.name}.bak.*"))

    @staticmethod
    def _sync_file(path: Path) -> None:
        # Windows requires a write-capable descriptor for FlushFileBuffers.
        with open(path, "rb+") as stream:
            os.fsync(stream.fileno())

    def _sync_directory(self) -> None:
        if os.name == "nt":
            return
        try:
            descriptor = os.open(self.path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _prune(self) -> None:
        backups = self._backups()
        for stale in backups[: max(0, len(backups) - self.retain)]:
            try:
                stale.unlink()
            except FileNotFoundError:
                pass

    def write(self, payload: dict[str, Any]) -> StoredEnvelope:
        if not isinstance(payload, dict):
            raise TypeError("state payload must be a dictionary")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        current: StoredEnvelope | None = None
        if self.path.exists():
            current = self._decode(self.path)
        generation = (current.generation if current else 0) + 1
        envelope = self._new_envelope(payload, generation)
        temporary = self.path.with_name(
            f"{self.path.name}.tmp.{secrets.token_hex(8)}"
        )

        try:
            with open(temporary, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(
                    envelope.to_dict(),
                    stream,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                stream.flush()
                os.fsync(stream.fileno())
            self._decode(temporary)

            if current is not None and self.retain:
                backup = self._backup_path(current.generation)
                shutil.copy2(self.path, backup)
                self._sync_file(backup)

            os.replace(temporary, self.path)
            self._sync_directory()
            self._prune()
            return envelope
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def read(self) -> dict[str, Any]:
        return self._decode(self.path).payload

    def restore_last_known_good(self) -> dict[str, Any]:
        for backup in reversed(self._backups()):
            try:
                envelope = self._decode(backup)
            except RecoveryError:
                continue

            temporary = self.path.with_name(
                f"{self.path.name}.tmp.{secrets.token_hex(8)}"
            )
            try:
                shutil.copy2(backup, temporary)
                self._sync_file(temporary)
                self._decode(temporary)
                os.replace(temporary, self.path)
                self._sync_directory()
                return envelope.payload
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

        raise RecoveryError("no valid recovery snapshot is available")
