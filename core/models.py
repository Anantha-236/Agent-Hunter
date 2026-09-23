"""Core data models."""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from config.settings import Severity
import re


class EvidenceStatus(str, Enum):
    NOT_TESTED = "not_tested"
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    UNRESOLVED = "unresolved"


class CoverageStatus(str, Enum):
    TESTED = "tested"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"
    DEFERRED = "deferred"
    FAILED = "failed"
    NOT_TESTED = "not_tested"


class DecisionOutcome(str, Enum):
    CONTINUE = "continue"
    DEFER = "defer"
    STOP = "stop"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    kind: str
    captured_at: datetime
    digest: str
    redacted: bool
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "captured_at": self.captured_at.isoformat(),
            "digest": self.digest,
            "redacted": self.redacted,
            "summary": self.summary,
        }


@dataclass
class DecisionRecord:
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    outcome: DecisionOutcome = DecisionOutcome.DEFER
    reason: str = ""
    candidate_actions: List[str] = field(default_factory=list)
    allowed_actions: List[str] = field(default_factory=list)
    denied_actions: Dict[str, str] = field(default_factory=dict)
    chosen_action: Optional[str] = None
    expected_evidence: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    recovery_plan: str = ""
    uncertainty: float = 0.0
    policy_snapshot_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp.isoformat(),
            "outcome": self.outcome.value,
            "reason": self.reason,
            "candidate_actions": list(self.candidate_actions),
            "allowed_actions": list(self.allowed_actions),
            "denied_actions": dict(self.denied_actions),
            "chosen_action": self.chosen_action,
            "expected_evidence": list(self.expected_evidence),
            "risks": list(self.risks),
            "recovery_plan": self.recovery_plan,
            "uncertainty": self.uncertainty,
            "policy_snapshot_hash": self.policy_snapshot_hash,
        }


@dataclass
class CoverageRecord:
    module: str
    status: CoverageStatus
    reason: str = ""
    action_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status.value,
            "reason": self.reason,
            "action_id": self.action_id,
            "evidence_ids": list(self.evidence_ids),
            "updated_at": self.updated_at.isoformat(),
        }

@dataclass
class Scope:
    allowed_domains: List[str] = field(default_factory=list)
    allowed_urls: List[str] = field(default_factory=list)
    excluded_domains: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)

    @staticmethod
    def _normalize_host(host: str) -> str:
        candidate = (host or "").strip().rstrip(".").lower()
        if not candidate:
            return ""
        try:
            return candidate.encode("idna").decode("ascii")
        except UnicodeError:
            return ""

    @staticmethod
    def _matches_pattern(value: str, pattern: str) -> bool:
        if not pattern:
            return False
        candidate = Scope._normalize_host(value)
        rule = pattern.strip().lower().rstrip(".")
        if rule.startswith("re:"):
            return bool(re.fullmatch(rule[3:], candidate))
        if rule.startswith("*."):
            suffix = Scope._normalize_host(rule[2:])
            return bool(suffix) and candidate.endswith(f".{suffix}")
        normalized_rule = Scope._normalize_host(rule)
        return bool(normalized_rule) and candidate == normalized_rule

    @staticmethod
    def _normalize_url(url: str):
        candidate = url.strip()
        if "://" not in candidate:
            candidate = f"https://{candidate}"
        parsed = urlparse(candidate)
        scheme = parsed.scheme or "https"
        host = Scope._normalize_host(parsed.hostname or "")
        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port
        path = parsed.path or "/"
        return scheme, host, port, path, parsed

    def _allowed_url_matches(self, url: str, allowed_url: str) -> bool:
        if allowed_url.startswith("re:"):
            return self._matches_pattern(url, allowed_url)

        url_scheme, url_host, url_port, url_path, _ = self._normalize_url(url)
        allowed_scheme, allowed_host, allowed_port, allowed_path, _ = self._normalize_url(allowed_url)

        if url_host != allowed_host:
            return False
        if url_port != allowed_port:
            return False
        if allowed_scheme and url_scheme != allowed_scheme:
            return False
        if allowed_path in ("", "/"):
            return True
        if url_path == allowed_path:
            return True
        return url_path.startswith(f"{allowed_path.rstrip('/')}/")

    def _allowed_url_host_matches(self, host: str, allowed_url: str) -> bool:
        if allowed_url.startswith("re:"):
            return False
        _, allowed_host, _, _, _ = self._normalize_url(allowed_url)
        return host == allowed_host

    def is_host_in_scope(self, host: str) -> bool:
        candidate_host = self._normalize_host(host)
        if not candidate_host:
            return False

        if any(self._matches_pattern(candidate_host, pattern) for pattern in self.excluded_domains):
            return False

        if self.allowed_domains and not any(
            self._matches_pattern(candidate_host, pattern) for pattern in self.allowed_domains
        ):
            return False

        if self.allowed_urls and not any(
            self._allowed_url_host_matches(candidate_host, allowed_url)
            for allowed_url in self.allowed_urls
        ):
            return False

        return True

    def is_in_scope(self, url: str) -> bool:
        _, host, _, path, parsed = self._normalize_url(url)
        if not host:
            return False

        if not self.is_host_in_scope(host):
            return False

        for path in self.excluded_paths:
            if parsed.path.startswith(path):
                return False

        if self.allowed_urls and not any(
            self._allowed_url_matches(url, allowed_url)
            for allowed_url in self.allowed_urls
        ):
            return False

        return True

@dataclass
class Target:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    url: str = ""
    scope: Optional[Scope] = None
    selected_assets: List[str] = field(default_factory=list)
    in_scope: List[str] = field(default_factory=list)
    out_scope: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    discovered_urls: List[str] = field(default_factory=list)
    discovered_params: Dict[str, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    vuln_type: str = ""
    severity: str = Severity.INFO
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    owasp_category: str = ""
    request: str = ""
    response: str = ""
    poc_steps: List[str] = field(default_factory=list)
    confirmed: bool = False
    false_positive: bool = False
    confidence: float = 0.0       # 0.0–1.0 agent confidence in this finding
    ai_analysis: str = ""
    module: str = ""
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    extra: Dict[str, Any] = field(default_factory=dict)
    evidence_status: EvidenceStatus = EvidenceStatus.OBSERVED
    evidence_refs: List[EvidenceRef] = field(default_factory=list)
    confidence_reason: str = ""
    scanner_version: str = ""
    policy_snapshot_hash: str = ""
    validator_results: Dict[str, Any] = field(default_factory=dict)
    control_results: Dict[str, Any] = field(default_factory=dict)

    def normalize_legacy_status(self) -> None:
        """Map the legacy flags without allowing contradictory claims."""
        if self.confirmed and self.false_positive:
            self.evidence_status = EvidenceStatus.UNRESOLVED
        elif self.confirmed:
            self.evidence_status = EvidenceStatus.CONFIRMED
        elif self.false_positive:
            self.evidence_status = EvidenceStatus.REFUTED

    def validate_evidence_state(self) -> None:
        """Reject evidence states that lack their required proof."""
        if self.evidence_status is EvidenceStatus.CONFIRMED and not any(
            ref.kind == "validator" for ref in self.evidence_refs
        ):
            raise ValueError("confirmed findings require validator evidence")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "vuln_type": self.vuln_type,
            "severity": self.severity, "url": self.url, "parameter": self.parameter,
            "method": self.method, "payload": self.payload, "evidence": self.evidence,
            "description": self.description, "remediation": self.remediation,
            "cvss_score": self.cvss_score, "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category, "request": self.request,
            "response": self.response, "poc_steps": self.poc_steps,
            "confirmed": self.confirmed, "false_positive": self.false_positive,
            "confidence": self.confidence,
            "ai_analysis": self.ai_analysis, "module": self.module,
            "discovered_at": self.discovered_at.isoformat(),
            "extra": self.extra,
            "evidence_status": self.evidence_status.value,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "confidence_reason": self.confidence_reason,
            "scanner_version": self.scanner_version,
            "policy_snapshot_hash": self.policy_snapshot_hash,
            "validator_results": self.validator_results,
            "control_results": self.control_results,
        }

@dataclass
class ScanState:
    target: Target
    phase: str = "init"
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    modules_run: List[str] = field(default_factory=list)
    modules_pending: List[str] = field(default_factory=list)
    agent_thoughts: List[str] = field(default_factory=list)
    decisions: List[DecisionRecord] = field(default_factory=list)
    coverage: List[CoverageRecord] = field(default_factory=list)
    policy_snapshot_hash: str = ""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None
    thought_callback: Optional[Callable[[str], None]] = None
    phase_callback: Optional[Callable[[str], None]] = None
    finding_callback: Optional[Callable[[Finding], None]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "phase": self.phase,
            "target_url": self.target.url,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": list(self.errors),
            "modules_run": list(self.modules_run),
            "modules_pending": list(self.modules_pending),
            "agent_thoughts": list(self.agent_thoughts),
            "decisions": [decision.to_dict() for decision in self.decisions],
            "coverage": [record.to_dict() for record in self.coverage],
            "policy_snapshot_hash": self.policy_snapshot_hash,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
        }

    def set_phase(self, phase: str) -> None:
        """Update phase and notify listener (e.g. API SSE stream)."""
        self.phase = phase
        if self.phase_callback:
            try:
                self.phase_callback(phase)
            except Exception:
                pass

    def add_finding(self, finding: Finding) -> None:
        key = (finding.url, finding.parameter, finding.vuln_type,
               finding.payload, finding.evidence[:60])
        existing = {(f.url, f.parameter, f.vuln_type,
                     f.payload, f.evidence[:60]) for f in self.findings}
        if key not in existing:
            self.findings.append(finding)
            if self.finding_callback:
                try:
                    self.finding_callback(finding)
                except Exception:
                    pass

    def log_thought(self, thought: str) -> None:
        ts = datetime.now(UTC).strftime("%H:%M:%S")
        self.agent_thoughts.append(f"[{ts}] {thought}")
        if self.thought_callback:
            try:
                self.thought_callback(thought)
            except Exception:
                pass

    def stats(self) -> Dict[str, Any]:
        from collections import Counter
        sev_counts = Counter(f.severity for f in self.findings)
        return {
            "total_findings": len(self.findings),
            "confirmed": sum(1 for f in self.findings if f.confirmed),
            "by_severity": dict(sev_counts),
            "modules_run": len(self.modules_run),
            "urls_tested": len(self.target.discovered_urls),
        }
