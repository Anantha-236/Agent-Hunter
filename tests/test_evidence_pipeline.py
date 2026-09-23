from __future__ import annotations

import asyncio
import json

import httpx

from core.base_scanner import BaseScanner
from core.evidence import (
    EvidenceManifest,
    EvidenceRule,
    EvidenceValidator,
    Redactor,
    ResponseFingerprint,
)
from core.models import EvidenceStatus, ScanState
from utils.http_client import HttpClient


def fingerprint(
    body: str,
    *,
    status: int = 200,
    content_type: str = "text/html",
) -> ResponseFingerprint:
    return ResponseFingerprint.from_values(
        status_code=status,
        headers={"content-type": content_type},
        body=body,
        elapsed_seconds=0.1,
    )


def test_redacts_nested_sensitive_values():
    value = {
        "headers": {"Authorization": "Bearer abc", "X-Test": "ok"},
        "cookies": {"session": "secret"},
        "body": "password=hunter2",
    }

    redacted = Redactor().redact(value)

    serialized = json.dumps(redacted)
    assert "abc" not in serialized
    assert "secret" not in serialized
    assert "hunter2" not in serialized
    assert redacted["headers"]["X-Test"] == "ok"


def test_response_fingerprint_retains_digest_not_body():
    value = fingerprint("private response text")

    data = value.to_dict()

    assert data["body_digest"]
    assert "private response text" not in json.dumps(data)


def test_length_change_with_equal_status_is_not_confirmed():
    result = EvidenceValidator().validate(
        baseline=fingerprint("short"),
        probe=fingerprint("a much longer response"),
        controls={},
        rule=EvidenceRule(name="length-change", decisive=False),
    )

    assert result.status is EvidenceStatus.SUSPECTED


def test_generic_500_is_not_confirmed():
    result = EvidenceValidator().validate(
        baseline=fingerprint("ok"),
        probe=fingerprint("internal server error", status=500),
        controls={},
        rule=EvidenceRule(name="generic-error", decisive=False),
    )

    assert result.status is EvidenceStatus.SUSPECTED


def test_reflection_without_decisive_control_is_not_confirmed():
    result = EvidenceValidator().validate(
        baseline=fingerprint("hello"),
        probe=fingerprint("hello <script>alert(1)</script>"),
        controls={"escaped-control": False},
        rule=EvidenceRule(
            name="reflection",
            decisive=False,
            required_controls=("escaped-control",),
        ),
    )

    assert result.status is EvidenceStatus.UNRESOLVED


def test_json_error_text_is_not_confirmed():
    result = EvidenceValidator().validate(
        baseline=fingerprint('{"ok":true}', content_type="application/json"),
        probe=fingerprint(
            '{"error":"sql syntax"}',
            status=500,
            content_type="application/json",
        ),
        controls={},
        rule=EvidenceRule(name="json-error", decisive=False),
    )

    assert result.status is EvidenceStatus.SUSPECTED


def test_vulnerability_specific_differential_with_control_is_confirmed():
    result = EvidenceValidator().validate(
        baseline=fingerprint('{"owner":"a"}', content_type="application/json"),
        probe=fingerprint('{"owner":"b"}', content_type="application/json"),
        controls={"alternate-principal-denied": True},
        rule=EvidenceRule(
            name="cross-principal-object-access",
            decisive=True,
            required_controls=("alternate-principal-denied",),
        ),
        validator_evidence_ids=("validator-1",),
    )

    assert result.status is EvidenceStatus.CONFIRMED
    assert result.validator_evidence_ids == ("validator-1",)


def test_manifest_redacts_before_storing_entry():
    manifest = EvidenceManifest()

    reference = manifest.add(
        kind="validator",
        value={"Authorization": "Bearer synthetic-token", "result": "denied"},
        summary="negative control",
    )

    serialized = json.dumps(manifest.to_dict())
    assert reference.kind == "validator"
    assert "synthetic-token" not in serialized
    assert "denied" in serialized


def test_http_client_manifest_never_receives_raw_auth_cookie_or_body():
    class LocalTransport:
        async def request(self, **_kwargs):
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                text='{"result":"ok","password":"server-secret"}',
            )

    async def exercise():
        manifest = EvidenceManifest()
        client = HttpClient(
            headers={"Authorization": "Bearer client-secret"},
            cookies={"session": "cookie-secret"},
            evidence_manifest=manifest,
            rate_limit=1000,
        )
        client._client = LocalTransport()
        response, persisted_request = await client.request(
            "POST",
            "https://example.test/api",
            json={"password": "body-secret"},
            retries=0,
        )
        return response, persisted_request, manifest.to_dict()

    response, persisted_request, manifest = asyncio.run(exercise())
    serialized = json.dumps(manifest)

    assert response.status_code == 200
    for secret in ("client-secret", "cookie-secret", "body-secret", "server-secret"):
        assert secret not in persisted_request
        assert secret not in serialized


def test_base_scanner_redacts_finding_fields_at_creation():
    class ExampleScanner(BaseScanner):
        name = "example"

        async def run(self, state: ScanState):
            return []

    finding = ExampleScanner(client=None).make_finding(
        request="Authorization: Bearer raw-token\r\n\r\npassword=raw-password",
        response='{"otp":"123456"}',
        evidence="cookie=session-secret",
    )

    serialized = json.dumps(finding.to_dict())
    for secret in ("raw-token", "raw-password", "123456", "session-secret"):
        assert secret not in serialized
