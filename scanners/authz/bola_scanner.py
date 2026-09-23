"""Read-only, two-principal BOLA validation for explicit synthetic objects."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Iterable

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


DEFAULT_IDENTITY_FIELDS = ("id", "uuid", "object_id", "user_id", "account_id")


class BOLAScanner(BaseScanner):
    name = "bola_scanner"
    description = "Validates object access across two explicitly supplied test principals"
    tags = ["authz", "bola", "api", "owasp-a01"]

    def __init__(self, client, *, identities: Iterable[TestIdentity] = (), max_operations: int = 5):
        super().__init__(client)
        self.identities = tuple(identities)
        self.max_operations = max(1, min(int(max_operations), 10))

    async def run(self, state: ScanState) -> list[Finding]:
        if len(self.identities) != 2 or len({item.label for item in self.identities}) != 2:
            self._defer(state, "BOLA requires exactly two distinct synthetic test identities.")
            return []

        candidates = [
            item for item in state.target.metadata.get("openapi_candidates", [])
            if isinstance(item, dict) and str(item.get("method", "")).upper() == "GET"
        ][: self.max_operations]
        object_map = state.target.metadata.get("authz_test_objects", {})
        if not candidates or not isinstance(object_map, dict):
            self._defer(state, "No explicit OpenAPI object candidates/test-object ownership map.")
            return []

        findings: list[Finding] = []
        denial_count = 0
        unresolved_count = 0
        for candidate in candidates:
            template = candidate.get("url")
            owned = object_map.get(template, {}) if isinstance(template, str) else {}
            if not isinstance(owned, dict):
                continue
            left, right = self.identities
            if left.label not in owned or right.label not in owned:
                unresolved_count += 1
                continue
            finding, outcome = await self._compare(
                state, candidate, left, str(owned[left.label]), right, str(owned[right.label])
            )
            if finding:
                findings.append(finding)
                break
            if outcome == "denied":
                denial_count += 1
            else:
                unresolved_count += 1

        if findings:
            state.coverage.append(CoverageRecord(
                module=self.name,
                status=CoverageStatus.TESTED,
                reason="Semantic cross-principal object access was validated.",
            ))
        elif denial_count:
            state.coverage.append(CoverageRecord(
                module=self.name,
                status=CoverageStatus.TESTED,
                reason="Cross-principal requests were denied with 403/404 controls.",
            ))
        else:
            state.coverage.append(CoverageRecord(
                module=self.name,
                status=CoverageStatus.DEFERRED,
                reason=f"Object identity/access result remained unresolved ({unresolved_count}).",
            ))
        return findings

    async def _compare(self, state, candidate, left, left_id, right, right_id):
        template = candidate["url"]
        path_parameters = candidate.get("path_parameters") or []
        if len(path_parameters) != 1:
            return None, "unresolved"
        parameter = str(path_parameters[0])
        left_url = template.replace("{" + parameter + "}", left_id)
        right_url = template.replace("{" + parameter + "}", right_id)
        if state.target.scope and (
            not state.target.scope.is_in_scope(left_url)
            or not state.target.scope.is_in_scope(right_url)
        ):
            return None, "unresolved"

        left_own = await self._get(left_url, left)
        right_own = await self._get(right_url, right)
        if left_own[0] != 200 or right_own[0] != 200:
            return None, "unresolved"

        identity_fields = state.target.metadata.get("authz_identity_fields", {}).get(
            template, DEFAULT_IDENTITY_FIELDS
        )
        left_semantic = _semantic_identity(left_own[1], identity_fields)
        right_semantic = _semantic_identity(right_own[1], identity_fields)
        if left_semantic is None or right_semantic is None or left_semantic == right_semantic:
            return None, "unresolved"

        cross_left = await self._get(right_url, left)
        cross_right = await self._get(left_url, right)
        if cross_left[0] in {401, 403, 404} and cross_right[0] in {401, 403, 404}:
            return None, "denied"

        cross_controls = (
            (left.label, right.label, right_semantic, cross_left),
            (right.label, left.label, left_semantic, cross_right),
        )
        for requester, owner, expected_identity, (status, body) in cross_controls:
            actual_identity = _semantic_identity(body, identity_fields)
            if status == 200 and actual_identity == expected_identity:
                proof = {
                    "requester": requester,
                    "object_owner": owner,
                    "object_identity": actual_identity,
                    "status": status,
                }
                evidence_ref = _validator_ref(proof, "cross-principal object identity matched")
                return self.make_finding(
                    title="Broken Object Level Authorization (BOLA)",
                    vuln_type="bola",
                    severity=Severity.HIGH,
                    url=template,
                    parameter=parameter,
                    evidence=(
                        f"Synthetic principal {requester!r} read the stable object identity "
                        f"owned by {owner!r}."
                    ),
                    description="A test principal could read another test principal's object.",
                    remediation="Enforce object ownership/tenant authorization on every API object lookup.",
                    cwe_id="CWE-639",
                    owasp_category="API1:2023 - Broken Object Level Authorization",
                    confirmed=True,
                    confidence=0.99,
                    evidence_status=EvidenceStatus.CONFIRMED,
                    evidence_refs=[evidence_ref],
                    validator_results={"cross_principal_object_id": actual_identity},
                    control_results={
                        "vulnerability-specific differential": True,
                        "safe baseline or negative control": True,
                        "two_distinct_principals": True,
                        "own_object_identity_established": True,
                    },
                ), "confirmed"
        return None, "unresolved"

    async def _get(self, url: str, identity: TestIdentity):
        response, _ = await self.client.get(url, extra_headers=identity.headers())
        if response is None:
            return 0, None
        try:
            body = response.json()
        except Exception:
            body = None
        return response.status_code, body

    def _defer(self, state: ScanState, reason: str):
        state.decisions.append(DecisionRecord(
            outcome=DecisionOutcome.DEFER,
            reason=reason,
            candidate_actions=[self.name],
            denied_actions={self.name: "explicit_test_identities_or_objects_missing"},
            recovery_plan="Supply two synthetic identities and an explicit ownership map.",
        ))
        state.coverage.append(CoverageRecord(
            module=self.name,
            status=CoverageStatus.NOT_TESTED,
            reason=reason,
        ))


def _semantic_identity(body, fields) -> str | None:
    if not isinstance(body, dict):
        return None
    for field in fields:
        value = body.get(str(field))
        if isinstance(value, (str, int)) and str(value):
            return str(value)
    return None


def _validator_ref(value: dict, summary: str) -> EvidenceRef:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return EvidenceRef(
        evidence_id=str(uuid.uuid4()),
        kind="validator",
        captured_at=datetime.now(UTC),
        digest=hashlib.sha256(canonical).hexdigest(),
        redacted=True,
        summary=summary,
    )
