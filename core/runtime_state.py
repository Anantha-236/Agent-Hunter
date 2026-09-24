"""Durable, checksummed state for dashboard reconnaissance and scans."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from core.recovery import AtomicJsonStore, RecoveryError


class RuntimeStateStore:
    """Persist independent runtime records with bounded recovery generations."""

    _SAFE_ID = re.compile(r"^[A-Za-z0-9._-]+$")

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _store(self, kind: str, record_id: str) -> AtomicJsonStore:
        if kind not in {"scans", "recons"}:
            raise ValueError(f"unsupported runtime-state kind: {kind}")
        if not self._SAFE_ID.fullmatch(record_id or ""):
            raise ValueError("runtime-state id contains unsupported characters")
        return AtomicJsonStore(
            self.root / kind / f"{record_id}.json",
            f"agent-hunter.runtime.{kind}.v1",
            retain=3,
        )

    def write(self, kind: str, record_id: str, payload: dict[str, Any]) -> None:
        self._store(kind, record_id).write(dict(payload))

    def read_all(self, kind: str) -> dict[str, dict[str, Any]]:
        directory = self.root / kind
        if not directory.exists():
            return {}

        records: dict[str, dict[str, Any]] = {}
        for path in sorted(directory.glob("*.json")):
            record_id = path.stem
            try:
                store = self._store(kind, record_id)
                try:
                    payload = store.read()
                except RecoveryError:
                    payload = store.restore_last_known_good()
            except (OSError, RecoveryError, ValueError):
                continue
            records[record_id] = payload
        return records
