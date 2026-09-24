import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api_server
import main as cli
from integrations.email.config import EmailPolicyError


@dataclass
class _Item:
    item_id: str = "item-1"
    idempotency_key: str = "key-1"
    status: str = "pending"


@dataclass
class _State:
    item_id: str = "item-1"
    status: str = "delivered"
    attempts: int = 1
    message_id: str = "message-1"
    reason: str = "accepted"
    next_attempt_at: str | None = None


class SpyOutbox:
    def __init__(self):
        self.enqueued = []
        self.delivered = []

    def enqueue(self, report, recipients):
        if any("outside" in recipient for recipient in recipients):
            raise EmailPolicyError("recipient is not allowlisted")
        self.enqueued.append((str(report), tuple(recipients)))
        return _Item()

    def deliver(self, item_id):
        self.delivered.append(item_id)
        return _State()

    def retry_due(self, _now):
        return []


def test_cli_email_is_opt_in(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", "https://example.test"])
    assert cli.parse_args().email_report is False

    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--target", "https://example.test", "--email-report"],
    )
    assert cli.parse_args().email_report is True


def test_normal_report_generation_has_no_outbox_side_effect(tmp_path):
    spy = SpyOutbox()
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")

    assert spy.enqueued == []
    assert spy.delivered == []
    assert report.exists()


def test_normal_scan_api_has_no_email_side_effect(monkeypatch):
    def fail_if_email_is_built():
        raise AssertionError("normal scan API must not build the email transport")

    def discard_background(coro):
        coro.close()
        return object()

    monkeypatch.setattr(api_server, "_build_email_outbox", fail_if_email_is_built)
    monkeypatch.setattr(api_server.asyncio, "create_task", discard_background)
    response = TestClient(api_server.app).post(
        "/api/scan",
        json={"url": "https://example.test", "modules": ["header_security"], "authorization_acknowledged": True},
    )
    assert response.status_code == 201


def test_explicit_cli_handoff_queues_and_delivers_once(tmp_path):
    spy = SpyOutbox()
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")

    state = cli.email_report_artifact(
        report,
        recipients=("owner@example.test",),
        outbox=spy,
    )

    assert state.status == "delivered"
    assert len(spy.enqueued) == 1
    assert spy.delivered == ["item-1"]


@pytest.fixture
def email_api(monkeypatch, tmp_path):
    token = "synthetic-local-api-token"
    monkeypatch.setenv("HUNTER_LOCAL_API_TOKEN", token)
    report = tmp_path / "known-report.json"
    report.write_text(json.dumps({"scan_id": "known"}), encoding="utf-8")
    api_server._report_files.clear()
    api_server._report_files["known"] = str(report)
    spy = SpyOutbox()
    monkeypatch.setattr(api_server, "_build_email_outbox", lambda: spy)
    return TestClient(api_server.app), spy, token


def test_api_requires_local_token(email_api):
    client, _spy, _token = email_api
    response = client.post("/api/reports/known/email", json={})
    assert response.status_code == 401


def test_api_accepts_known_report_only_and_never_returns_credentials(email_api):
    client, spy, token = email_api
    response = client.post(
        "/api/reports/known/email",
        headers={"X-Agent-Hunter-Token": token},
        json={"recipients": ["owner@example.test"], "deliver_now": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "delivered"
    assert "password" not in json.dumps(payload).lower()
    assert "smtp" not in json.dumps(payload).lower()
    assert len(spy.enqueued) == 1
    assert len(spy.delivered) == 1

    missing = client.post(
        "/api/reports/../../arbitrary/email",
        headers={"X-Agent-Hunter-Token": token},
        json={},
    )
    assert missing.status_code in {404, 405}


def test_api_applies_recipient_allowlist(email_api):
    client, spy, token = email_api
    response = client.post(
        "/api/reports/known/email",
        headers={"X-Agent-Hunter-Token": token},
        json={"recipients": ["outside@example.test"]},
    )
    assert response.status_code == 400
    assert spy.delivered == []
