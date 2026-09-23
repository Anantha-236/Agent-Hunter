"""Bounded two-principal authenticated cache differential checks."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Iterable

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import CoverageRecord, CoverageStatus, EvidenceRef, EvidenceStatus, ScanState
from core.test_identities import TestIdentity


class CacheBehaviorScanner(BaseScanner):
    name = "cache_behavior_scanner"
    description = "Detects repeatable cross-principal authenticated cache leakage"
    tags = ["cache", "auth", "privacy", "safe-active"]

    def __init__(self, client, *, identities: Iterable[TestIdentity] = (), max_urls: int = 2):
        super().__init__(client)
        self.identities = tuple(identities)
        self.max_urls = max(1, min(int(max_urls), 3))

    async def run(self, state: ScanState):
        if len(self.identities) != 2 or len({item.label for item in self.identities}) != 2:
            state.coverage.append(CoverageRecord(
                module=self.name, status=CoverageStatus.NOT_TESTED,
                reason="Authenticated cache checks require two synthetic identities.",
            ))
            return []
        urls = state.target.metadata.get("cache_test_urls", [])
        if not isinstance(urls, list) or not urls:
            state.coverage.append(CoverageRecord(
                module=self.name, status=CoverageStatus.NOT_TESTED,
                reason="No explicit private cache test URLs were supplied.",
            ))
            return []

        for url in urls[: self.max_urls]:
            if not isinstance(url, str) or (state.target.scope and not state.target.scope.is_in_scope(url)):
                continue
            finding, status = await self._check_url(state, url)
            if status == "auth_ambiguous":
                state.coverage.append(CoverageRecord(
                    module=self.name, status=CoverageStatus.DEFERRED,
                    reason="Authentication expired or became ambiguous; cache checks stopped.",
                ))
                return []
            if finding:
                state.coverage.append(CoverageRecord(
                    module=self.name, status=CoverageStatus.TESTED,
                    reason="Repeatable cross-principal private response leakage was validated.",
                ))
                return [finding]
        state.coverage.append(CoverageRecord(
            module=self.name, status=CoverageStatus.TESTED,
            reason="No repeatable cross-principal private cache differential was observed.",
        ))
        return []

    async def _check_url(self, state: ScanState, url: str):
        left, right = self.identities
        control = await self._get(url, right, {"Cache-Control": "no-cache"})
        if _auth_ambiguous(control):
            return None, "auth_ambiguous"
        control_owner = _semantic_owner(control[1], state, url)
        if control[0] != 200 or control_owner is None:
            return None, "public_or_unresolved"

        sequence = []
        conditional_etag = ""
        for attempt in range(2):
            prime = await self._get(url, left)
            probe_headers = (
                {"If-None-Match": conditional_etag}
                if attempt and conditional_etag
                else None
            )
            probe = await self._get(url, right, probe_headers)
            if _auth_ambiguous(prime) or _auth_ambiguous(probe):
                return None, "auth_ambiguous"
            sequence.append((prime, probe))
            conditional_etag = prime[2].get("ETag", prime[2].get("etag", ""))

        left_owner = _semantic_owner(sequence[0][0][1], state, url)
        probe_owners = [_semantic_owner(item[1][1], state, url) for item in sequence]
        if (
            left_owner is not None
            and left_owner != control_owner
            and probe_owners == [left_owner, left_owner]
            and all(item[1][0] == 200 for item in sequence)
        ):
            proof = {
                "url": url,
                "control_owner": control_owner,
                "priming_owner": left_owner,
                "probe_owners": probe_owners,
                "response_fingerprints": [
                    _fingerprint(item[1][1]) for item in sequence
                ],
            }
            return self.make_finding(
                title="Authenticated private response leaked across principals via cache",
                vuln_type="authenticated_cache_leak",
                severity=Severity.HIGH,
                url=url,
                method="GET",
                evidence="Two repeat probes returned the other synthetic principal's semantic owner.",
                description="A shared cache served identity-specific content to another authenticated principal.",
                remediation="Mark private responses non-store/private and include authorization identity in cache keys.",
                cwe_id="CWE-525",
                confirmed=True,
                confidence=0.99,
                evidence_status=EvidenceStatus.CONFIRMED,
                evidence_refs=[_validator_ref(proof)],
                validator_results={"cross_principal_owner": left_owner, "repeatable": True},
                control_results={
                    "vulnerability-specific differential": True,
                    "safe baseline or negative control": True,
                    "uncached_identity_control": True,
                },
            ), "confirmed"
        return None, "refuted"

    async def _get(self, url: str, identity: TestIdentity, extra=None):
        headers = {**identity.headers(), **(extra or {})}
        response, _ = await self.client.get(url, extra_headers=headers)
        if response is None:
            return 0, None, {}
        try:
            body = response.json()
        except Exception:
            body = None
        return response.status_code, body, dict(response.headers)


def _semantic_owner(body, state: ScanState, url: str):
    if not isinstance(body, dict):
        return None
    configured = state.target.metadata.get("cache_identity_fields", {}).get(
        url, ("owner", "user_id", "account_id")
    )
    for field in configured:
        value = body.get(str(field))
        if isinstance(value, (str, int)) and str(value):
            return str(value)
    return None


def _auth_ambiguous(result) -> bool:
    return result[0] in {0, 401, 403} or (
        isinstance(result[1], dict)
        and any(word in str(result[1]).lower() for word in ("expired", "login", "unauthorized"))
    )


def _fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _validator_ref(proof: dict) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=str(uuid.uuid4()), kind="validator", captured_at=datetime.now(UTC),
        digest=_fingerprint(proof), redacted=True,
        summary="repeatable authenticated cache identity differential",
    )
