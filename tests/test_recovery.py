from __future__ import annotations

import json
import os
from unittest.mock import Mock

import pytest

from core.recovery import AtomicJsonStore, RecoveryError


def test_corrupt_active_restores_backup(tmp_path):
    store = AtomicJsonStore(tmp_path / "state.json", "hunter.test.v1")
    store.write({"generation": 1})
    store.write({"generation": 2})
    (tmp_path / "state.json").write_text("{broken", encoding="utf-8")

    restored = store.restore_last_known_good()

    assert restored["generation"] == 1
    assert store.read()["generation"] == 1


def test_failed_replace_preserves_old_valid_state(tmp_path, monkeypatch):
    store = AtomicJsonStore(tmp_path / "state.json", "hunter.test.v1")
    store.write({"generation": 1})
    monkeypatch.setattr(os, "replace", Mock(side_effect=OSError("injected")))

    with pytest.raises(OSError, match="injected"):
        store.write({"generation": 2})

    assert store.read()["generation"] == 1
    assert not list(tmp_path.glob("state.json.tmp.*"))


def test_checksum_tampering_is_rejected(tmp_path):
    store = AtomicJsonStore(tmp_path / "state.json", "hunter.test.v1")
    store.write({"value": "trusted"})
    raw = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    raw["payload"]["value"] = "tampered"
    (tmp_path / "state.json").write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(RecoveryError, match="checksum"):
        store.read()


def test_schema_mismatch_is_rejected(tmp_path):
    path = tmp_path / "state.json"
    AtomicJsonStore(path, "hunter.old.v1").write({"value": 1})

    with pytest.raises(RecoveryError, match="schema"):
        AtomicJsonStore(path, "hunter.new.v1").read()


def test_non_dictionary_payload_is_rejected(tmp_path):
    store = AtomicJsonStore(tmp_path / "state.json", "hunter.test.v1")

    with pytest.raises(TypeError, match="dictionary"):
        store.write(["not", "a", "mapping"])


def test_retention_keeps_only_requested_backup_count(tmp_path):
    store = AtomicJsonStore(
        tmp_path / "state.json",
        "hunter.test.v1",
        retain=2,
    )
    for value in range(5):
        store.write({"value": value})

    backups = sorted(tmp_path.glob("state.json.bak.*"))

    assert len(backups) == 2
    assert store.read()["value"] == 4


def test_partial_json_without_backup_cannot_be_restored(tmp_path):
    path = tmp_path / "state.json"
    path.write_text('{"schema":', encoding="utf-8")
    store = AtomicJsonStore(path, "hunter.test.v1")

    with pytest.raises(RecoveryError, match="no valid recovery snapshot"):
        store.restore_last_known_good()


def test_fsync_failure_removes_temporary_file(tmp_path, monkeypatch):
    store = AtomicJsonStore(tmp_path / "state.json", "hunter.test.v1")
    monkeypatch.setattr(os, "fsync", Mock(side_effect=OSError("disk full")))

    with pytest.raises(OSError, match="disk full"):
        store.write({"value": 1})

    assert not (tmp_path / "state.json").exists()
    assert not list(tmp_path.glob("state.json.tmp.*"))
