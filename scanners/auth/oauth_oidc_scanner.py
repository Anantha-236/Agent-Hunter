"""Passive-first OAuth 2.0/OpenID Connect configuration scanner."""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import parse_qs, urlparse, urlunparse

from config.settings import OAUTH_METADATA_MAX_BYTES, OAUTH_METADATA_PATHS
from core.base_scanner import BaseScanner
from core.models import DecisionOutcome, DecisionRecord, EvidenceStatus, Finding, ScanState
from scanners.auth.oauth_metadata import OAuthMetadata, OAuthMetadataError, OAuthObservation


@dataclass(frozen=True)
class SyntheticOAuthClient:
    client_id: str
    redirect_uri: str
    expected_issuer: str
    permitted: bool = False

    def __post_init__(self):
        if not self.permitted:
            raise ValueError("synthetic OAuth client must be explicitly permitted")
        if not self.client_id.strip() or len(self.client_id) > 256:
            raise ValueError("synthetic OAuth client_id is required")
        redirect = urlparse(self.redirect_uri)
        issuer = urlparse(self.expected_issuer)
        if (
            redirect.scheme not in {"http", "https"}
            or issuer.scheme not in {"http", "https"}
            or not redirect.hostname
            or not issuer.hostname
        ):
            raise ValueError("synthetic OAuth URLs must be absolute HTTP(S)")
        redirect_origin = (redirect.scheme, redirect.hostname, redirect.port or _default_port(redirect.scheme))
        issuer_origin = (issuer.scheme, issuer.hostname, issuer.port or _default_port(issuer.scheme))
        if redirect_origin != issuer_origin:
            raise ValueError("synthetic callback must use the same origin as the issuer")
        if redirect.username or redirect.password or redirect.query or redirect.fragment:
            raise ValueError("synthetic callback must not contain credentials, query, or fragment")


class OAuthOIDCScanner(BaseScanner):
    name = "oauth_oidc_scanner"
    description = "Validates bounded OAuth/OIDC metadata with opt-in local callback controls"
    tags = ["auth", "oauth", "oidc", "passive"]

    def __init__(
        self,
        client,
        *,
        metadata_paths: Iterable[str] = OAUTH_METADATA_PATHS,
        max_bytes: int = OAUTH_METADATA_MAX_BYTES,
        active_flow_enabled: bool = False,
        synthetic_client: SyntheticOAuthClient | None = None,
    ):
        super().__init__(client)
        self.metadata_paths = tuple(metadata_paths)
        self.max_bytes = max(1, int(max_bytes))
        self.active_flow_enabled = bool(active_flow_enabled)
        self.synthetic_client = synthetic_client

    async def run(self, state: ScanState) -> list[Finding]:
        documents: list[OAuthMetadata] = []
        findings: list[Finding] = []
        blocked: list[str] = []
        errors: list[dict[str, str]] = []

        for source_url in self._metadata_urls(state):
            try:
                response, _ = await self.client.get(source_url)
            except Exception as exc:
                errors.append({"source_url": source_url, "reason": type(exc).__name__})
                continue
            if response is None or response.status_code != 200:
                continue
            raw = getattr(response, "content", None)
            raw = raw if isinstance(raw, bytes) else response.text
            try:
                metadata = OAuthMetadata.parse(
                    raw,
                    source_url,
                    expected_issuer=state.target.url.rstrip("/"),
                    max_bytes=self.max_bytes,
                )
            except OAuthMetadataError as exc:
                errors.append({"source_url": source_url, "reason": str(exc)[:200]})
                continue
            documents.append(metadata)
            blocked.extend(metadata.blocked_endpoints)
            findings.extend(self._observation_findings(metadata))

        state.target.metadata["oauth_blocked_endpoints"] = list(dict.fromkeys(blocked))
        state.target.metadata["oauth_metadata_errors"] = errors
        state.target.metadata["oauth_metadata_sources"] = [document.source_url for document in documents]

        if self.active_flow_enabled:
            if self.synthetic_client is None:
                self._defer(state, "Active OAuth flow check requires an explicit synthetic client.")
            elif not state.target.scope or not state.target.scope.is_in_scope(
                self.synthetic_client.redirect_uri
            ):
                self._defer(state, "Synthetic OAuth callback is outside the current scope.")
            else:
                active_metadata = next(
                    (document for document in documents if document.authorization_endpoint),
                    None,
                )
                if active_metadata is None:
                    self._defer(state, "No in-scope authorization endpoint was discovered.")
                elif not state.target.scope.is_in_scope(active_metadata.authorization_endpoint):
                    self._defer(state, "Authorization endpoint is outside the current path scope.")
                else:
                    active_finding = await self._safe_active_check(state, active_metadata)
                    if active_finding:
                        findings.append(active_finding)
        return findings

    def _metadata_urls(self, state: ScanState) -> list[str]:
        parsed = urlparse(state.target.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return []
        origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        urls = []
        for path in self.metadata_paths[:2]:
            if not str(path).startswith("/"):
                continue
            url = f"{origin}{path}"
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            urls.append(url)
        return urls

    def _observation_findings(self, metadata: OAuthMetadata) -> list[Finding]:
        return [
            self.make_finding(
                title=f"OAuth/OIDC metadata observation: {observation.code}",
                vuln_type=f"oauth_metadata_{observation.code}",
                severity=observation.severity,
                url=metadata.source_url,
                evidence=observation.message,
                description=(
                    "Metadata differs from a recommended baseline. This is an observation, "
                    "not proof of an exploitable OAuth vulnerability."
                ),
                evidence_status=EvidenceStatus.OBSERVED,
                confirmed=False,
                confidence=0.6,
                validator_results={"metadata_only": True},
            )
            for observation in metadata.observations
        ]

    async def _safe_active_check(self, state: ScanState, metadata: OAuthMetadata) -> Finding | None:
        config = self.synthetic_client
        assert config is not None and metadata.authorization_endpoint is not None
        if config.expected_issuer.rstrip("/") != (metadata.issuer or "").rstrip("/"):
            return self.make_finding(
                title="Synthetic OAuth issuer does not match discovery metadata",
                vuln_type="oauth_active_issuer_mismatch",
                severity="medium",
                url=metadata.source_url,
                evidence="Configured synthetic issuer differs from the discovered issuer.",
                evidence_status=EvidenceStatus.OBSERVED,
                confirmed=False,
            )

        state_value = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        params = {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "scope": "openid",
            "state": state_value,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
        }
        response, _ = await self.client.get_no_redirect(
            metadata.authorization_endpoint,
            params=params,
        )
        if response is None or response.status_code not in {301, 302, 303, 307, 308}:
            return None
        location = response.headers.get("location", "")
        parsed = urlparse(location)
        callback = urlparse(config.redirect_uri)
        if (parsed.scheme, parsed.netloc, parsed.path) != (
            callback.scheme, callback.netloc, callback.path
        ):
            return self.make_finding(
                title="OAuth authorization response used an unexpected callback",
                vuln_type="oauth_unexpected_callback",
                severity="medium",
                url=metadata.authorization_endpoint,
                evidence="Authorization response Location did not match the permitted callback.",
                evidence_status=EvidenceStatus.OBSERVED,
                confirmed=False,
            )
        returned_state = parse_qs(parsed.query).get("state", [""])[0]
        if returned_state != state_value:
            return self.make_finding(
                title="OAuth authorization response did not preserve state",
                vuln_type="oauth_state_not_preserved",
                severity="medium",
                url=metadata.authorization_endpoint,
                evidence="Synthetic authorization response omitted or changed the state value.",
                evidence_status=EvidenceStatus.OBSERVED,
                confirmed=False,
                validator_results={"state_present": bool(returned_state), "state_match": False},
            )
        return None

    def _defer(self, state: ScanState, reason: str):
        state.decisions.append(DecisionRecord(
            outcome=DecisionOutcome.DEFER,
            reason=reason,
            candidate_actions=[self.name],
            denied_actions={self.name: "synthetic_oauth_client_missing_or_out_of_scope"},
            recovery_plan="Configure a permitted synthetic public client and in-scope callback.",
        ))


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80
