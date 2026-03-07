"""
Consequence Analyzer — Hunter understands the real-world impact of what it finds.

For every vulnerability finding, this module reasons about:
  - Business impact: what data / functionality is at risk
  - Blast radius: who is affected (user, admin, the whole database, the whole network)
  - Exploitation likelihood: how easily can a real attacker use this
  - Attack chain potential: what other vulnerabilities this enables
  - Immediate action: what Hunter should do next

Hunter never reports a finding without understanding WHY it matters.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.models import Finding, Target

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
#  CONSEQUENCE KNOWLEDGE BASE
# ══════════════════════════════════════════════════════════════

# Business data assets typically at risk per vulnerability type
_BUSINESS_IMPACT: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "assets": ["database records", "user credentials", "PII", "financial data"],
        "blast_radius": "entire database",
        "exploitation_base": 0.85,
        "chain_enables": ["auth_bypass", "data_exfiltration", "privilege_escalation"],
        "owasp_risk": "A03:2021 – Injection",
        "cvss_base": 9.8,
        "urgency": "CRITICAL — Stop and report immediately",
    },
    "xss_scanner": {
        "assets": ["session cookies", "user credentials", "user actions", "page content"],
        "blast_radius": "all users visiting affected pages",
        "exploitation_base": 0.70,
        "chain_enables": ["session_hijacking", "credential_theft", "phishing", "keylogging"],
        "owasp_risk": "A03:2021 – Injection (XSS)",
        "cvss_base": 6.1,
        "urgency": "HIGH — Report before moving to next module",
    },
    "ssrf": {
        "assets": ["internal services", "cloud metadata", "internal APIs", "file system"],
        "blast_radius": "internal network / cloud infrastructure",
        "exploitation_base": 0.75,
        "chain_enables": ["cloud_credential_theft", "internal_service_access", "rce"],
        "owasp_risk": "A10:2021 – SSRF",
        "cvss_base": 8.6,
        "urgency": "CRITICAL — Cloud metadata exposure may allow full account takeover",
    },
    "ssti": {
        "assets": ["server file system", "environment variables", "application secrets"],
        "blast_radius": "full server compromise",
        "exploitation_base": 0.90,
        "chain_enables": ["rce", "data_exfiltration", "lateral_movement"],
        "owasp_risk": "A03:2021 – Injection",
        "cvss_base": 9.8,
        "urgency": "CRITICAL — RCE possible. Stop scanning and escalate immediately",
    },
    "command_injection": {
        "assets": ["OS", "file system", "running processes", "network"],
        "blast_radius": "full host compromise",
        "exploitation_base": 0.95,
        "chain_enables": ["full_rce", "lateral_movement", "persistence", "data_exfiltration"],
        "owasp_risk": "A03:2021 – Injection",
        "cvss_base": 10.0,
        "urgency": "CRITICAL — Full system compromise possible. Stop scanning, escalate NOW",
    },
    "path_traversal": {
        "assets": ["config files", "credentials", "source code", "private keys"],
        "blast_radius": "server file system (read access)",
        "exploitation_base": 0.80,
        "chain_enables": ["credential_exposure", "source_code_disclosure", "further_rce"],
        "owasp_risk": "A01:2021 – Broken Access Control",
        "cvss_base": 7.5,
        "urgency": "HIGH — Sensitive file exposure likely. Report before continuing",
    },
    "auth_scanner": {
        "assets": ["user accounts", "admin panel", "authentication tokens"],
        "blast_radius": "all user accounts",
        "exploitation_base": 0.70,
        "chain_enables": ["account_takeover", "privilege_escalation", "data_access"],
        "owasp_risk": "A07:2021 – Identification and Authentication Failures",
        "cvss_base": 8.0,
        "urgency": "HIGH — Authentication bypass allows full account access",
    },
    "idor_scanner": {
        "assets": ["user records", "private documents", "order data", "PII"],
        "blast_radius": "all user-owned resources",
        "exploitation_base": 0.65,
        "chain_enables": ["data_exfiltration", "unauthorized_modification", "privacy_violation"],
        "owasp_risk": "A01:2021 – Broken Access Control",
        "cvss_base": 7.5,
        "urgency": "HIGH — IDOR allows mass data enumeration of all user records",
    },
    "misconfig_scanner": {
        "assets": ["server configuration", "debug interfaces", "admin panels"],
        "blast_radius": "depends on exposed functionality",
        "exploitation_base": 0.60,
        "chain_enables": ["information_disclosure", "admin_access", "further_exploitation"],
        "owasp_risk": "A05:2021 – Security Misconfiguration",
        "cvss_base": 5.3,
        "urgency": "MEDIUM — Document and include in report",
    },
    "open_redirect": {
        "assets": ["user trust", "brand reputation", "session tokens via phishing"],
        "blast_radius": "all users who click phishing links",
        "exploitation_base": 0.50,
        "chain_enables": ["phishing", "token_theft", "oauth_bypass"],
        "owasp_risk": "A01:2021 – Broken Access Control",
        "cvss_base": 6.1,
        "urgency": "MEDIUM — High phishing potential. Continue scanning",
    },
    "subdomain_takeover": {
        "assets": ["subdomain control", "cookie scope", "user trust"],
        "blast_radius": "all users that trust this subdomain",
        "exploitation_base": 0.85,
        "chain_enables": ["session_hijacking", "phishing", "stored_xss"],
        "owasp_risk": "A05:2021 – Security Misconfiguration",
        "cvss_base": 8.1,
        "urgency": "HIGH — Attacker can serve malicious content from trusted domain",
    },
    "csrf_scanner": {
        "assets": ["user account actions", "state-changing operations"],
        "blast_radius": "all logged-in users",
        "exploitation_base": 0.55,
        "chain_enables": ["account_modification", "sensitive_action_execution"],
        "owasp_risk": "A01:2021 – Broken Access Control",
        "cvss_base": 6.5,
        "urgency": "MEDIUM — Social engineering required. Include in report",
    },
    "host_header": {
        "assets": ["password reset flow", "cache behavior", "redirect targets"],
        "blast_radius": "users who receive manipulated responses",
        "exploitation_base": 0.65,
        "chain_enables": ["password_reset_poisoning", "cache_poisoning", "ssrf"],
        "owasp_risk": "A03:2021 – Injection",
        "cvss_base": 7.5,
        "urgency": "HIGH — Password reset poisoning can lead to account takeover",
    },
    "xxe_scanner": {
        "assets": ["server file system", "internal network", "application secrets"],
        "blast_radius": "file read on server + SSRF to internal network",
        "exploitation_base": 0.75,
        "chain_enables": ["file_read", "ssrf", "rce"],
        "owasp_risk": "A05:2021 – Security Misconfiguration (XXE)",
        "cvss_base": 8.2,
        "urgency": "CRITICAL — File read and SSRF possible. Report immediately",
    },
    "race_condition": {
        "assets": ["financial transactions", "quota limits", "voting systems"],
        "blast_radius": "depends on the resource being raced",
        "exploitation_base": 0.50,
        "chain_enables": ["double_spend", "limit_bypass", "data_corruption"],
        "owasp_risk": "A04:2021 – Insecure Design",
        "cvss_base": 7.5,
        "urgency": "HIGH — Financial or integrity impact. Report before continuing",
    },
    "crlf_injection": {
        "assets": ["HTTP headers", "session cookies", "log injection target"],
        "blast_radius": "affected users and server logs",
        "exploitation_base": 0.60,
        "chain_enables": ["header_injection", "xss", "log_poisoning"],
        "owasp_risk": "A03:2021 – Injection",
        "cvss_base": 6.5,
        "urgency": "MEDIUM — Header injection can escalate to XSS",
    },
    "graphql_scanner": {
        "assets": ["data schema", "user records", "admin mutations"],
        "blast_radius": "depends on exposed queries/mutations",
        "exploitation_base": 0.65,
        "chain_enables": ["data_exfiltration", "idor", "bola"],
        "owasp_risk": "A01:2021 – Broken Access Control + A05 Misconfiguration",
        "cvss_base": 7.5,
        "urgency": "HIGH — Introspection + BOLA may expose all data types",
    },
}

# Severity → base urgency escalation level
_SEVERITY_ESCALATION = {
    "critical": 3,  # immediately stop additional testing on this endpoint
    "high": 2,      # report before continuing
    "medium": 1,    # document and continue
    "low": 0,       # note and continue
    "info": 0,
}

# Vulnerability types that should STOP the scan on the affected endpoint
_STOP_ON_FINDING = frozenset({
    "command_injection",
    "ssti",
    "sql_injection",
    "xxe_scanner",
})

# Vulnerability types that require immediate disclosure (skip remaining modules)
_DISCLOSE_IMMEDIATELY = frozenset({
    "command_injection",
    "ssti",
})


# ══════════════════════════════════════════════════════════════
#  DATA MODEL
# ══════════════════════════════════════════════════════════════

@dataclass
class ConsequenceReport:
    """The full consequence analysis for a single finding."""

    finding_id: str
    vuln_type: str
    severity: str

    # Impact dimensions
    business_impact: str = ""        # human-readable what is at risk
    blast_radius: str = ""           # who / what is affected
    assets_at_risk: List[str] = field(default_factory=list)
    exploitation_likelihood: float = 0.0   # 0.0 – 1.0

    # Chain analysis
    chain_enables: List[str] = field(default_factory=list)
    chain_description: str = ""

    # Responsibility
    immediate_action: str = ""       # what Hunter should do right now
    responsibility_level: str = ""   # 'disclose_immediately' | 'report' | 'continue'
    stop_endpoint_testing: bool = False
    escalation_score: int = 0        # 0-3

    # References
    owasp_risk: str = ""
    cvss_base: float = 0.0

    def to_thought(self) -> str:
        """Render as a Hunter internal thought log entry."""
        lines = [
            f"CONSEQUENCE [{self.vuln_type.upper()} / {self.severity.upper()}]",
            f"  Assets at risk  : {', '.join(self.assets_at_risk[:3])}",
            f"  Blast radius    : {self.blast_radius}",
            f"  Exploit chance  : {self.exploitation_likelihood:.0%}",
            f"  Chain potential : {', '.join(self.chain_enables[:3])}",
            f"  Action          : {self.immediate_action}",
            f"  Responsibility  : {self.responsibility_level}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "business_impact": self.business_impact,
            "blast_radius": self.blast_radius,
            "assets_at_risk": self.assets_at_risk,
            "exploitation_likelihood": self.exploitation_likelihood,
            "chain_enables": self.chain_enables,
            "chain_description": self.chain_description,
            "immediate_action": self.immediate_action,
            "responsibility_level": self.responsibility_level,
            "stop_endpoint_testing": self.stop_endpoint_testing,
            "escalation_score": self.escalation_score,
            "owasp_risk": self.owasp_risk,
            "cvss_base": self.cvss_base,
        }


# ══════════════════════════════════════════════════════════════
#  CONSEQUENCE ANALYZER
# ══════════════════════════════════════════════════════════════

class ConsequenceAnalyzer:
    """
    Analyzes the real-world consequences of a vulnerability finding.

    Hunter does not just detect vulnerabilities — it understands what they mean
    for the business, the users, and the attacker's potential next steps.

    This is the "understand the consequences" part of Hunter's responsibility framework.
    """

    def analyze(
        self,
        finding: Finding,
        target: Target,
        confirmed_findings_so_far: int = 0,
    ) -> ConsequenceReport:
        """
        Analyze the consequence of a finding.

        Args:
            finding: The vulnerability finding to analyze
            target: The scan target (for tech stack context)
            confirmed_findings_so_far: Number of confirmed findings already found

        Returns:
            ConsequenceReport with full consequence analysis
        """
        # Map finding to module name for knowledge base lookup
        module_key = self._resolve_module_key(finding.vuln_type, finding.title)
        kb = _BUSINESS_IMPACT.get(module_key, {})

        sev = (finding.severity or "info").lower()
        escalation = _SEVERITY_ESCALATION.get(sev, 0)

        # Base exploitation likelihood from knowledge base + confidence
        base_exploit = kb.get("exploitation_base", 0.5)
        exploit_likelihood = min(0.99, base_exploit * (0.5 + finding.confidence * 0.5))

        # Boost exploitation chance if finding was confirmed
        if finding.confirmed:
            exploit_likelihood = min(0.99, exploit_likelihood + 0.15)

        # Determine assets at risk
        assets = kb.get("assets", ["application data"])

        # Determine chain potential
        chains = kb.get("chain_enables", [])
        chain_desc = self._build_chain_description(chains, finding, target)

        # Business impact narrative
        impact = self._build_impact_narrative(finding, kb, target, exploit_likelihood)

        # Responsibility level
        responsibility, stop_testing, action = self._determine_responsibility(
            finding, module_key, escalation, exploit_likelihood
        )

        report = ConsequenceReport(
            finding_id=finding.id,
            vuln_type=finding.vuln_type or module_key,
            severity=sev,
            business_impact=impact,
            blast_radius=kb.get("blast_radius", "affected endpoint's users"),
            assets_at_risk=assets,
            exploitation_likelihood=exploit_likelihood,
            chain_enables=chains,
            chain_description=chain_desc,
            immediate_action=action,
            responsibility_level=responsibility,
            stop_endpoint_testing=stop_testing,
            escalation_score=escalation,
            owasp_risk=kb.get("owasp_risk", ""),
            cvss_base=kb.get("cvss_base", finding.cvss_score or 0.0),
        )

        logger.debug(f"Consequence analysis: {finding.vuln_type} → {responsibility}")
        return report

    def analyze_batch(
        self,
        findings: List[Finding],
        target: Target,
    ) -> Tuple[List[ConsequenceReport], str]:
        """
        Analyze all findings from a scan and produce a batch summary.

        Returns:
            (reports list, summary narrative string)
        """
        reports = []
        confirmed_count = 0
        for f in findings:
            report = self.analyze(f, target, confirmed_count)
            reports.append(report)
            if f.confirmed:
                confirmed_count += 1

        summary = self._build_batch_summary(reports, findings)
        return reports, summary

    # ── Private helpers ───────────────────────────────────────

    def _resolve_module_key(self, vuln_type: str, title: str) -> str:
        """Resolve a finding's vuln_type to a knowledge base key."""
        if not vuln_type:
            return "misconfig_scanner"
        vt = vuln_type.lower()

        # Direct match
        if vt in _BUSINESS_IMPACT:
            return vt

        # Prefix match
        for key in _BUSINESS_IMPACT:
            if vt.startswith(key) or key.startswith(vt.split("_")[0]):
                return key

        # Title-based fallback
        title_lower = (title or "").lower()
        if "sql" in title_lower:
            return "sql_injection"
        if "xss" in title_lower or "cross-site scripting" in title_lower:
            return "xss_scanner"
        if "ssrf" in title_lower:
            return "ssrf"
        if "command" in title_lower:
            return "command_injection"
        if "template" in title_lower:
            return "ssti"
        if "traversal" in title_lower or "lfi" in title_lower:
            return "path_traversal"
        if "idor" in title_lower or "object reference" in title_lower:
            return "idor_scanner"
        if "csrf" in title_lower:
            return "csrf_scanner"
        if "redirect" in title_lower:
            return "open_redirect"
        if "xxe" in title_lower:
            return "xxe_scanner"
        if "race" in title_lower:
            return "race_condition"

        return "misconfig_scanner"

    def _build_impact_narrative(
        self,
        finding: Finding,
        kb: Dict[str, Any],
        target: Target,
        exploit_likelihood: float,
    ) -> str:
        """Build a human-readable business impact statement."""
        assets = kb.get("assets", ["application data"])
        blast = kb.get("blast_radius", "affected users")
        tech = target.technologies[0] if target.technologies else "the application"

        parts = [
            f"An attacker exploiting this vulnerability on '{tech}' targeting "
            f"'{finding.url}' could access: {', '.join(assets[:3])}.",
            f"Blast radius: {blast}.",
            f"Estimated exploitation likelihood: {exploit_likelihood:.0%}.",
        ]

        if finding.confirmed:
            parts.append(
                "This finding has been CONFIRMED — exploitation is directly feasible."
            )
        elif finding.confidence > 0.7:
            parts.append(
                "This finding has HIGH confidence and likely represents a real vulnerability."
            )

        return " ".join(parts)

    def _build_chain_description(
        self,
        chains: List[str],
        finding: Finding,
        target: Target,
    ) -> str:
        """Describe the attack chain this vulnerability enables."""
        if not chains:
            return "No known escalation chains."
        chain_labels = [c.replace("_", " ") for c in chains[:3]]
        return (
            f"This vulnerability can be chained to achieve: "
            f"{', '.join(chain_labels)}. "
            "An attacker who confirms this finding will likely attempt these next steps."
        )

    def _determine_responsibility(
        self,
        finding: Finding,
        module_key: str,
        escalation: int,
        exploit_likelihood: float,
    ) -> Tuple[str, bool, str]:
        """
        Determine Hunter's responsibility level for this finding.

        Returns:
            (responsibility_level, stop_endpoint_testing, action_description)
        """
        if module_key in _DISCLOSE_IMMEDIATELY and finding.confirmed:
            return (
                "disclose_immediately",
                True,
                (
                    "CRITICAL finding confirmed. Stop all further testing on this endpoint. "
                    "Generate report and escalate to program owner immediately. "
                    "Do NOT attempt to chain further exploitation."
                ),
            )

        if module_key in _STOP_ON_FINDING and finding.confirmed:
            return (
                "report_priority",
                True,
                (
                    "High-impact finding confirmed. Complete current module then stop endpoint testing. "
                    "Prioritize this finding in the report with full PoC steps."
                ),
            )

        if escalation >= 2 and finding.confirmed:
            return (
                "report",
                False,
                (
                    "Confirmed high-severity vulnerability. "
                    "Record full evidence and continue scanning other modules. "
                    "Flag this endpoint for immediate remediation in the report."
                ),
            )

        if escalation >= 2 and exploit_likelihood > 0.6:
            return (
                "report",
                False,
                (
                    "Likely vulnerability with significant impact. "
                    "Mark for reporting and continue scanning. "
                    "Validate this finding with additional evidence."
                ),
            )

        return (
            "continue",
            False,
            (
                "Medium or low severity finding. "
                "Document evidence and continue scanning remaining modules. "
                "Include in final report."
            ),
        )

    def _build_batch_summary(
        self,
        reports: List[ConsequenceReport],
        findings: List[Finding],
    ) -> str:
        """Build a batch consequence summary for the whole scan."""
        if not reports:
            return "No findings to analyze."

        critical_count = sum(1 for r in reports if r.escalation_score >= 3)
        high_count = sum(1 for r in reports if r.escalation_score == 2)
        disclose_now = [r for r in reports if r.responsibility_level == "disclose_immediately"]
        all_chains = set()
        for r in reports:
            all_chains.update(r.chain_enables)

        lines = [
            f"== CONSEQUENCE SUMMARY ==",
            f"Total findings analyzed : {len(reports)}",
            f"Critical (stop-and-report): {critical_count}",
            f"High severity           : {high_count}",
            f"Disclose immediately    : {len(disclose_now)}",
            f"Attack chains identified: {', '.join(list(all_chains)[:6]) or 'none'}",
        ]
        if disclose_now:
            lines.append(
                f"URGENT: {len(disclose_now)} finding(s) require immediate disclosure: "
                + ", ".join(r.vuln_type for r in disclose_now)
            )
        return "\n".join(lines)
