"""Explicitly gated, reversible synthetic mass-assignment validation."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Awaitable, Callable, Iterable

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import (
    CoverageRecord,
    CoverageStatus,
    DecisionOutcome,
    DecisionRecord,
    EvidenceRef,
    EvidenceStatus,
    Finding,
    ScanState,
)
from core.test_identities import TestIdentity


CleanupHandler = Callable[..., Awaitable[bool]]
UNSAFE_FIELD_PATTERN = re.compile(
    r"(^|_)(role|admin|privilege|permission|billing|balance|credit|plan|owner|tenant)(_|$)",
    re.IGNORECASE,
)


class MassAssignmentScanner(BaseScanner):
    name = "mass_assignment_scanner"
    description = "Tests one allowlisted reversible synthetic field with verified cleanup"
    tags = ["authz", "mass-assignment", "api", "state-changing"]

    def __init__(
        self,
        client,
        *,
        identities: Iterable[TestIdentity] = (),
        field_allowlist: Iterable[str] = (),
        cleanup_handler: CleanupHandler | None = None,
        enabled: bool = False,
        policy_permissions: set[str] | None = None,
        operator_confirmed: bool = False,
        idempotency_key: str = "",
    ):
        super().__init__(client)
        self.identities = tuple(identities)
        self.field_allowlist = tuple(dict.fromkeys(str(field).strip() for field in field_allowlist))
        for field in self.field_allowlist:
            if not field or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", field):
                raise ValueError("invalid mass-assignment field")
            if UNSAFE_FIELD_PATTERN.search(field):
                raise ValueError(f"unsafe mass-assignment field: {field}")
        self.cleanup_handler = cleanup_handler
        self.enabled = bool(enabled)
        self.policy_permissions = set(policy_permissions or set())
        self.operator_confirmed = bool(operator_confirmed)
        self.idempotency_key = str(idempotency_key)

    async def run(self, state: ScanState) -> list[Finding]:
        denial = self._gate_reason()
        if denial:
            self._defer(state, denial)
            return []

        candidate = self._candidate(state)
        if candidate is None:
            self._defer(state, "No explicit reversible PATCH/PUT OpenAPI candidate and object mapping.")
            return []

        identity = self.identities[0]
        template, url, method = candidate
        field = self.field_allowlist[0]
        headers = {**identity.headers(), "Idempotency-Key": self.idempotency_key}

        before_response, _ = await self.client.get(url, extra_headers=identity.headers())
        before = _json_object(before_response)
        if before_response is None or before_response.status_code != 200 or field not in before:
            self._defer(state, "Before-state could not be established for the allowlisted field.")
            return []
        before_value = before[field]
        probe_value = f"hunter_probe_{uuid.uuid4().hex[:12]}"

        write_response, _ = await self.client.request(
            method,
            url,
            json={field: probe_value},
            extra_headers=headers,
        )
        if write_response is None or write_response.status_code not in {200, 201, 202, 204}:
            state.coverage.append(CoverageRecord(
                module=self.name,
                status=CoverageStatus.TESTED,
                reason="Allowlisted synthetic field update was rejected.",
            ))
            return []

        after_response, _ = await self.client.get(url, extra_headers=identity.headers())
        after = _json_object(after_response)
        changed = after_response is not None and after_response.status_code == 200 and after.get(field) == probe_value
        if not changed:
            state.coverage.append(CoverageRecord(
                module=self.name,
                status=CoverageStatus.TESTED,
                reason="Write response did not produce the synthetic field state differential.",
            ))
            return []

        try:
            cleanup_ok = await self.cleanup_handler(
                self.client, url, identity, field, before_value, self.idempotency_key
            )
        except Exception:
            cleanup_ok = False
        try:
            restored_response, _ = await self.client.get(url, extra_headers=identity.headers())
        except Exception:
            restored_response = None
        restored = _json_object(restored_response)
        cleanup_verified = bool(
            cleanup_ok
            and restored_response is not None
            and restored_response.status_code == 200
            and restored.get(field) == before_value
        )
        if not cleanup_verified:
            self._escalate(state, template, field)
            return []

        proof = {
            "method": method,
            "url_template": template,
            "field": field,
            "before_fingerprint": _value_fingerprint(before_value),
            "after_fingerprint": _value_fingerprint(probe_value),
            "cleanup_fingerprint": _value_fingerprint(restored.get(field)),
        }
        finding = self.make_finding(
            title="Allowlisted field accepted through mass assignment",
            vuln_type="mass_assignment",
            severity=Severity.MEDIUM,
            url=template,
            parameter=field,
            method=method,
            evidence="Synthetic reversible field was accepted, observed, and restored.",
            description="The API accepted a field outside the intended update contract.",
            remediation="Bind update DTOs to an explicit server-side field allowlist.",
            cwe_id="CWE-915",
            owasp_category="API3:2023 - Broken Object Property Level Authorization",
            confirmed=True,
            confidence=0.98,
            evidence_status=EvidenceStatus.CONFIRMED,
            evidence_refs=[_validator_ref(proof)],
            validator_results={
                "before_after_differential": True,
                "cleanup_verified": True,
            },
            control_results={
                "vulnerability-specific differential": True,
                "safe baseline or negative control": True,
                "cleanup_verified": True,
                "allowlisted_synthetic_field": True,
            },
        )
        state.coverage.append(CoverageRecord(
            module=self.name,
            status=CoverageStatus.TESTED,
            reason="Before/after/cleanup controls all passed.",
        ))
        return [finding]

    def _gate_reason(self) -> str | None:
        if not self.enabled:
            return "Mass-assignment testing is disabled by default."
        if "mass_assignment_testing" not in self.policy_permissions:
            return "Explicit mass_assignment_testing policy permission is missing."
        if not self.operator_confirmed:
            return "Operator confirmation is required for a state-changing test."
        if len(self.identities) != 1:
            return "Exactly one synthetic test identity is required."
        if len(self.field_allowlist) != 1:
            return "Exactly one reversible synthetic field must be allowlisted."
        if self.cleanup_handler is None:
            return "A cleanup handler is required."
        if (
            not self.idempotency_key
            or len(self.idempotency_key) > 128
            or any(char in self.idempotency_key for char in ("\r", "\n", "\x00"))
        ):
            return "A bounded idempotency key is required."
        return None

    def _candidate(self, state: ScanState):
        ownership = state.target.metadata.get("authz_test_objects", {})
        for candidate in state.target.metadata.get("openapi_candidates", []):
            if not isinstance(candidate, dict):
                continue
            method = str(candidate.get("method", "")).upper()
            template = candidate.get("url")
            params = candidate.get("path_parameters") or []
            if method not in {"PATCH", "PUT"} or not isinstance(template, str) or len(params) != 1:
                continue
            owned = ownership.get(template, {}) if isinstance(ownership, dict) else {}
            identity = self.identities[0]
            if not isinstance(owned, dict) or identity.label not in owned:
                continue
            url = template.replace("{" + str(params[0]) + "}", str(owned[identity.label]))
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            return template, url, method
        return None

    def _defer(self, state: ScanState, reason: str):
        state.decisions.append(DecisionRecord(
            outcome=DecisionOutcome.DEFER,
            reason=reason,
            candidate_actions=[self.name],
            denied_actions={self.name: "state_change_gate_not_satisfied"},
            recovery_plan="Supply every state-changing permission, confirmation, and cleanup control.",
        ))
        state.coverage.append(CoverageRecord(
            module=self.name,
            status=CoverageStatus.NOT_TESTED,
            reason=reason,
        ))

    def _escalate(self, state: ScanState, template: str, field: str):
        reason = "Cleanup could not be verified after a synthetic field change."
        state.decisions.append(DecisionRecord(
            outcome=DecisionOutcome.ESCALATE,
            reason=reason,
            candidate_actions=[self.name],
            denied_actions={self.name: "cleanup_ambiguous"},
            risks=[f"field={field}", f"operation={template}"],
            recovery_plan="Stop all writes; inspect the synthetic object and restore it manually.",
        ))
        state.coverage.append(CoverageRecord(
            module=self.name,
            status=CoverageStatus.BLOCKED,
            reason=reason,
        ))


def _json_object(response) -> dict:
    if response is None:
        return {}
    try:
        value = response.json()
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _value_fingerprint(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _validator_ref(value: dict) -> EvidenceRef:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return EvidenceRef(
        evidence_id=str(uuid.uuid4()),
        kind="validator",
        captured_at=datetime.now(UTC),
        digest=hashlib.sha256(canonical).hexdigest(),
        redacted=True,
        summary="before/after/cleanup semantic differential",
    )
