import asyncio
import json
import pytest

from fastapi.testclient import TestClient

import api_server
from core.runtime_state import RuntimeStateStore


@pytest.fixture(autouse=True)
def isolate_api_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(api_server, "_runtime_state", RuntimeStateStore(tmp_path / "runtime"))
    api_server._scans.clear()
    api_server._recons.clear()
    api_server._scan_tasks.clear()
    api_server._report_files.clear()
    yield
    api_server._scans.clear()
    api_server._recons.clear()
    api_server._scan_tasks.clear()
    api_server._report_files.clear()


def _discard_background(coro):
    coro.close()
    return object()


def test_scan_api_requires_explicit_authorization_acknowledgement(monkeypatch):
    monkeypatch.setattr(api_server.asyncio, "create_task", _discard_background)
    response = TestClient(api_server.app).post(
        "/api/scan",
        json={"url": "https://example.test", "modules": ["header_security"]},
    )
    assert response.status_code == 400
    assert "authorization" in response.json()["detail"].lower()


def test_scan_api_accepts_acknowledged_controlled_scan(monkeypatch):
    monkeypatch.setattr(api_server.asyncio, "create_task", _discard_background)
    response = TestClient(api_server.app).post(
        "/api/scan",
        json={
            "url": "https://example.test",
            "modules": ["header_security"],
            "authorization_acknowledged": True,
        },
    )
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]
    entry = api_server._scans[scan_id]
    assert len(entry["policy_snapshot_hash"]) == 64
    assert entry["policy_snapshot"]["authorization_acknowledged"] is True
    assert entry["policy_snapshot"]["target"] == "https://example.test"


def test_runtime_state_survives_store_recreation(tmp_path):
    store = RuntimeStateStore(tmp_path)
    store.write(
        "scans",
        "scan-1",
        {
            "scan_id": "scan-1",
            "status": "complete",
            "target": "https://example.test",
            "findings": [],
        },
    )

    reloaded = RuntimeStateStore(tmp_path).read_all("scans")

    assert reloaded["scan-1"]["status"] == "complete"
    assert reloaded["scan-1"]["target"] == "https://example.test"


def test_runtime_state_restores_last_good_generation(tmp_path):
    store = RuntimeStateStore(tmp_path)
    store.write("recons", "recon-1", {"recon_id": "recon-1", "status": "running"})
    store.write("recons", "recon-1", {"recon_id": "recon-1", "status": "complete"})
    (tmp_path / "recons" / "recon-1.json").write_text("{broken", encoding="utf-8")

    reloaded = RuntimeStateStore(tmp_path).read_all("recons")

    assert reloaded["recon-1"]["status"] in {"running", "complete"}


def test_report_index_is_rebuilt_from_saved_reports(tmp_path):
    report = tmp_path / "agent-hunter-report-scan-1-example.json"
    report.write_text(json.dumps({"scan_id": "scan-1", "target": "https://example.test"}), encoding="utf-8")
    (tmp_path / "not-a-report.json").write_text("{}", encoding="utf-8")

    assert api_server._discover_report_files(tmp_path) == {"scan-1": str(report)}


def test_abort_endpoint_cancels_registered_scan_task(monkeypatch):
    class FakeTask:
        def __init__(self):
            self.cancelled = False

        def done(self):
            return False

        def cancel(self):
            self.cancelled = True

    scan_id = "abort-me"
    fake = FakeTask()
    api_server._scans[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target": "https://example.test",
        "started_at": "2026-09-24T00:00:00",
        "ended_at": None,
        "findings": [],
        "logs": [],
        "errors": [],
        "phase": "scan",
        "stats": {},
    }
    api_server._scan_tasks[scan_id] = fake

    response = TestClient(api_server.app).post(f"/api/scan/{scan_id}/abort")

    assert response.status_code == 200
    assert fake.cancelled is True
    assert response.json()["status"] == "aborting"
    api_server._scans.pop(scan_id, None)
    api_server._scan_tasks.pop(scan_id, None)
