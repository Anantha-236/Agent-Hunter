"""Core data models."""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from config.settings import Severity
import re

@dataclass
class Scope:
    allowed_domains: List[str]
    allowed_urls: List[str] = field(default_factory=list)
    excluded_domains: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)

    def is_in_scope(self, url: str) -> bool:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        for excl in self.excluded_domains:
            pattern = excl.replace(".", r"\.").replace("*", ".*")
            if re.fullmatch(pattern, host):
                return False
        for path in self.excluded_paths:
            if parsed.path.startswith(path):
                return False
        for allowed in self.allowed_domains:
            pattern = allowed.replace(".", r"\.").replace("*", ".*")
            if re.fullmatch(pattern, host):
                return True
        return False

@dataclass
class Target:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    url: str = ""
    scope: Optional[Scope] = None
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
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None
    thought_callback: Optional[Callable[[str], None]] = None

    def add_finding(self, finding: Finding) -> None:
        key = (finding.url, finding.parameter, finding.vuln_type, finding.payload)
        existing = {(f.url, f.parameter, f.vuln_type, f.payload) for f in self.findings}
        if key not in existing:
            self.findings.append(finding)

    def log_thought(self, thought: str) -> None:
        ts = datetime.utcnow().strftime("%H:%M:%S")
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
