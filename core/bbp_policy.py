"""
BBP Policy Engine — Enforces Bug Bounty Program rules before and during scanning.

SAFETY CRITICAL: This module ensures the agent ONLY tests what is explicitly
allowed by the BBP program. Violating program rules = unauthorized access = illegal.

Usage:
    1. Create a policy file (JSON) with program rules
    2. Pass it via --policy flag or embed it in a scope profile
    3. Agent will REFUSE to scan anything not explicitly in scope
"""
from __future__ import annotations
import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from core.pre_engagement import PreEngagementChecklist, PreEngagementGate, PreEngagementResult

logger = logging.getLogger(__name__)


@dataclass
class BBPPolicy:
    """Represents the complete rules of a Bug Bounty Program."""

    # ── Program Info ──
    program_name: str = ""
    platform: str = ""          # hackerone, bugcrowd, intigriti, etc.
    program_url: str = ""

    # ── In-Scope Assets ──
    in_scope_domains: List[str] = field(default_factory=list)
    in_scope_urls: List[str] = field(default_factory=list)
    in_scope_apps: List[str] = field(default_factory=list)  # mobile apps, etc.
    asset_types: List[str] = field(default_factory=list)     # web, api, mobile, etc.

    # ── Out-of-Scope Assets (CRITICAL) ──
    oos_domains: List[str] = field(default_factory=list)
    oos_urls: List[str] = field(default_factory=list)
    oos_paths: List[str] = field(default_factory=list)
    oos_ips: List[str] = field(default_factory=list)

    # ── Out-of-Scope Vulnerability Types ──
    oos_vuln_types: List[str] = field(default_factory=list)  # e.g., "self_xss", "logout_csrf"

    # ── Testing Restrictions ──
    no_dos: bool = True               # Never DoS/DDoS
    no_data_exfil: bool = True        # No extracting real user data
    no_data_modification: bool = True  # No modifying production data
    no_social_engineering: bool = True # No social engineering staff
    no_physical: bool = True          # No physical testing
    no_automated_mass_scan: bool = False  # Some programs ban automated scanners
    rate_limit_rps: float = 5.0       # Max requests per second
    testing_hours: str = ""           # e.g., "Only during business hours EST"
    require_2fa_test_account: bool = False

    # ── Specific Instructions ──
    special_instructions: List[str] = field(default_factory=list)
    safe_harbor: bool = False         # Does program offer safe harbor?
    disclosure_policy: str = ""       # coordinated, full, etc.
    min_severity: str = "low"         # Minimum severity they accept

    # ── Reward Info ──
    reward_range: Dict[str, str] = field(default_factory=dict)  # {"critical": "$1000-$5000", ...}

    # ── Pre-Engagement Checklist (embedded or path) ──
    pre_engagement_checklist: Optional[Dict] = None

    @classmethod
    def from_file(cls, path: str) -> "BBPPolicy":
        """Load policy from a JSON file."""
        with open(path, "r") as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BBPPolicy":
        policy = cls()
        for key, value in data.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        return policy

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_name": self.program_name,
            "platform": self.platform,
            "program_url": self.program_url,
            "in_scope_domains": self.in_scope_domains,
            "in_scope_urls": self.in_scope_urls,
            "in_scope_apps": self.in_scope_apps,
            "asset_types": self.asset_types,
            "oos_domains": self.oos_domains,
            "oos_urls": self.oos_urls,
            "oos_paths": self.oos_paths,
            "oos_ips": self.oos_ips,
            "oos_vuln_types": self.oos_vuln_types,
            "no_dos": self.no_dos,
            "no_data_exfil": self.no_data_exfil,
            "no_data_modification": self.no_data_modification,
            "no_social_engineering": self.no_social_engineering,
            "no_physical": self.no_physical,
            "no_automated_mass_scan": self.no_automated_mass_scan,
            "rate_limit_rps": self.rate_limit_rps,
            "testing_hours": self.testing_hours,
            "special_instructions": self.special_instructions,
            "safe_harbor": self.safe_harbor,
            "disclosure_policy": self.disclosure_policy,
            "min_severity": self.min_severity,
            "reward_range": self.reward_range,
        }

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def to_pre_engagement_checklist(self) -> PreEngagementChecklist:
        """Convert policy fields into a PreEngagementChecklist for gate enforcement."""
        if self.pre_engagement_checklist:
            return PreEngagementChecklist.from_dict(self.pre_engagement_checklist)

        # Build checklist from policy fields
        cl = PreEngagementChecklist()
        cl.in_scope_domains = list(self.in_scope_domains)
        cl.oos_domains = list(self.oos_domains)
        cl.safe_harbor_clause_present = self.safe_harbor
        cl.denial_of_service_excluded = self.no_dos
        cl.automated_scanning_restrictions = self.no_automated_mass_scan
        cl.mass_scanning_prohibited = self.no_automated_mass_scan
        cl.spam_or_bruteforce_excluded = False  # not in old policy model
        cl.no_data_destruction = self.no_data_modification
        cl.no_privacy_violation = self.no_data_exfil
        cl.cloud_metadata_access_allowed = True  # old policy doesn't restrict this
        cl.rate_limit_rps = self.rate_limit_rps
        cl.excluded_vuln_types = list(self.oos_vuln_types)
        cl.production_testing_allowed = True
        cl.automated_tools_allowed = not self.no_automated_mass_scan
        return cl

    def run_pre_engagement_gate(
        self,
        target_url: str,
        requested_modules: List[str] = None,
    ) -> PreEngagementResult:
        """Run the pre-engagement gate using this policy's settings."""
        checklist = self.to_pre_engagement_checklist()
        gate = PreEngagementGate(checklist)
        return gate.run_checks(
            target_url=target_url,
            in_scope_domains=self.in_scope_domains,
            oos_domains=self.oos_domains,
            requested_modules=requested_modules,
        )


class PolicyEnforcer:
    """
    Enforces BBP policy throughout the scan lifecycle.
    
    Called at every stage:
    - BEFORE scan starts (pre-flight check)
    - BEFORE each request (URL check)
    - BEFORE each scanner module (vuln type check)
    - DURING payload generation (restrict dangerous payloads)
    """

    def __init__(self, policy: BBPPolicy):
        self.policy = policy
        self.violations: List[str] = []
        self.blocked_requests: int = 0
        self.blocked_modules: List[str] = []
        self._pre_engagement_result: Optional[PreEngagementResult] = None
        self._pre_engagement_gate: Optional[PreEngagementGate] = None

        # Build gate from policy
        checklist = policy.to_pre_engagement_checklist()
        self._pre_engagement_gate = PreEngagementGate(checklist)

    # ── Pre-Flight Check ──────────────────────────────────────

    def pre_scan_check(self, target_url: str, requested_modules: List[str] = None) -> List[str]:
        """
        Run before ANY scanning begins. Returns list of issues.
        If any critical issues found, scan should NOT proceed.

        Now delegates to the PreEngagementGate for comprehensive checking.
        """
        # Run the full pre-engagement gate
        self._pre_engagement_result = self.policy.run_pre_engagement_gate(
            target_url=target_url,
            requested_modules=requested_modules,
        )

        # Convert gate results to legacy issue strings
        issues = []

        for check in self._pre_engagement_result.checks:
            if not check.passed:
                prefix = {
                    "critical": "CRITICAL",
                    "warning": "WARNING",
                    "info": "NOTE",
                }.get(check.severity, "NOTE")
                issues.append(f"{prefix}: {check.message}")

        # Append legacy checks not covered by gate
        if self.policy.testing_hours:
            issues.append(f"NOTE: Testing hours restriction: {self.policy.testing_hours}")

        for instruction in self.policy.special_instructions:
            issues.append(f"INSTRUCTION: {instruction}")

        # Store disabled modules from gate
        self.blocked_modules = list(self._pre_engagement_result.disabled_modules)

        return issues

    @property
    def pre_engagement_result(self) -> Optional[PreEngagementResult]:
        """Get the result of the last pre-engagement gate run."""
        return self._pre_engagement_result

    def should_abort(self) -> bool:
        """Whether the pre-engagement gate says to abort the scan."""
        if self._pre_engagement_result:
            return not self._pre_engagement_result.passed
        return False

    def get_disabled_modules(self) -> List[str]:
        """Get modules disabled by the pre-engagement gate."""
        if self._pre_engagement_result:
            return list(self._pre_engagement_result.disabled_modules)
        return []

    def get_enforced_rate_limit(self) -> Optional[float]:
        """Get the rate limit enforced by the pre-engagement gate."""
        if self._pre_engagement_result and self._pre_engagement_result.enforced_rate_limit:
            return self._pre_engagement_result.enforced_rate_limit
        return None

    def should_filter_cloud_payloads(self) -> bool:
        """Whether cloud metadata payloads should be stripped."""
        if self._pre_engagement_gate:
            return self._pre_engagement_gate.should_filter_cloud_payloads()
        return False

    def should_disable_bruteforce(self) -> bool:
        """Whether brute-force attacks should be disabled."""
        if self._pre_engagement_gate:
            return self._pre_engagement_gate.should_disable_bruteforce()
        return False

    # ── URL Check (called before every request) ───────────────

    def is_url_allowed(self, url: str) -> tuple[bool, str]:
        """Check if a URL is allowed to be tested. Called before every request."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"

        # Check OOS domains
        if self._domain_matches_any(host, self.policy.oos_domains):
            reason = f"Domain '{host}' is out-of-scope"
            self._record_violation(reason)
            return False, reason

        # Check OOS URLs
        for oos_url in self.policy.oos_urls:
            if url.startswith(oos_url) or oos_url in url:
                reason = f"URL matches out-of-scope pattern: {oos_url}"
                self._record_violation(reason)
                return False, reason

        # Check OOS paths
        for oos_path in self.policy.oos_paths:
            if path.startswith(oos_path):
                reason = f"Path '{path}' matches out-of-scope path: {oos_path}"
                self._record_violation(reason)
                return False, reason

        # Check OOS IPs (if URL uses an IP — supports CIDR ranges)
        try:
            host_ip = ipaddress.ip_address(host)
            for oos_entry in self.policy.oos_ips:
                try:
                    if '/' in oos_entry:
                        if host_ip in ipaddress.ip_network(oos_entry, strict=False):
                            reason = f"IP '{host}' is in out-of-scope range: {oos_entry}"
                            self._record_violation(reason)
                            return False, reason
                    else:
                        if host_ip == ipaddress.ip_address(oos_entry):
                            reason = f"IP '{host}' is out-of-scope"
                            self._record_violation(reason)
                            return False, reason
                except ValueError:
                    # oos_entry is not a valid IP/CIDR — skip
                    continue
        except ValueError:
            # host is not an IP (it's a hostname) — skip IP check
            pass

        # If in_scope_domains specified, check target is in scope
        if self.policy.in_scope_domains:
            if not self._domain_matches_any(host, self.policy.in_scope_domains):
                reason = f"Domain '{host}' is NOT in in-scope list"
                self._record_violation(reason)
                return False, reason

        return True, "OK"

    # ── Module Check (called before each scanner) ─────────────

    def is_module_allowed(self, module_name: str) -> tuple[bool, str]:
        """Check if a scanner module is allowed by the program rules."""

        # Block DoS-related scanners
        if self.policy.no_dos and module_name in ("race_condition",):
            # Race condition scanner sends concurrent requests — borderline DoS
            # We allow it but log a warning
            logger.warning(
                f"Module '{module_name}' sends concurrent requests. "
                f"Program has no_dos=True. Running with reduced concurrency."
            )

        return True, "OK"

    # ── Vuln Type Check ───────────────────────────────────────

    def is_vuln_type_allowed(self, vuln_type: str) -> bool:
        """Check if a vulnerability type is in scope for the program."""
        vuln_lower = vuln_type.lower()

        # Skip OOS vuln types
        for oos in self.policy.oos_vuln_types:
            if oos.lower() in vuln_lower or vuln_lower in oos.lower():
                return False

        return True

    # ── Payload Check ─────────────────────────────────────────

    def sanitize_payload(self, payload: str, vuln_type: str) -> Optional[str]:
        """
        Check payload safety. Block payloads that violate program rules.
        Returns sanitized payload or None if blocked.
        """
        payload_lower = payload.lower()

        # Block data exfiltration payloads
        if self.policy.no_data_exfil:
            exfil_patterns = [
                "curl ", "wget ", "nc ", "ncat ",  # network exfil
                ".burpcollaborator.", ".oast.",     # external interaction
                "ngrok.", "requestbin.",            # external callbacks
            ]
            for pattern in exfil_patterns:
                if pattern in payload_lower:
                    logger.debug(f"Blocked exfil payload: {payload[:50]}...")
                    return None

        # Block data modification payloads
        if self.policy.no_data_modification:
            modify_patterns = [
                "drop table", "delete from", "truncate ",
                "update ", "insert into", "alter table",
            ]
            for pattern in modify_patterns:
                if pattern in payload_lower:
                    logger.debug(f"Blocked data modification payload: {payload[:50]}...")
                    return None

        # Block DoS payloads
        if self.policy.no_dos:
            dos_patterns = [
                "sleep(999", "sleep(60", "benchmark(",
                "pg_sleep(60", "waitfor delay '0:1:",
            ]
            for pattern in dos_patterns:
                if pattern in payload_lower:
                    logger.debug(f"Blocked DoS payload: {payload[:50]}...")
                    return None

        return payload

    # ── Rate Limiting ─────────────────────────────────────────

    def get_rate_limit(self) -> float:
        """Get the delay between requests to respect rate limits."""
        if self.policy.rate_limit_rps <= 0:
            return 0.5  # Safe default
        return 1.0 / self.policy.rate_limit_rps

    # ── Finding Filter ────────────────────────────────────────

    def filter_findings(self, findings: list) -> list:
        """Remove findings for OOS vuln types before reporting."""
        filtered = []
        for f in findings:
            if self.is_vuln_type_allowed(f.vuln_type):
                filtered.append(f)
            else:
                logger.info(f"Filtered OOS finding: {f.vuln_type} at {f.url}")
        return filtered

    # ── Summary ───────────────────────────────────────────────

    def summary(self) -> Dict:
        return {
            "program": self.policy.program_name,
            "platform": self.policy.platform,
            "violations_caught": len(self.violations),
            "blocked_requests": self.blocked_requests,
            "blocked_modules": self.blocked_modules,
        }

    def print_policy_banner(self):
        """Print policy summary before scan starts."""
        p = self.policy
        lines = [
            "",
            "=" * 60,
            f"  BBP POLICY: {p.program_name or 'Custom Program'}",
            f"  Platform: {p.platform or 'N/A'}",
            "=" * 60,
            f"  In-Scope:  {', '.join(p.in_scope_domains[:5]) or 'Not specified'}",
            f"  OOS:       {', '.join(p.oos_domains[:5]) or 'None'}",
            f"  OOS Paths: {', '.join(p.oos_paths[:5]) or 'None'}",
            f"  OOS Vulns: {', '.join(p.oos_vuln_types[:5]) or 'None'}",
            "-" * 60,
            "  Restrictions:",
            f"    No DoS:            {p.no_dos}",
            f"    No Data Exfil:     {p.no_data_exfil}",
            f"    No Data Modify:    {p.no_data_modification}",
            f"    Rate Limit:        {p.rate_limit_rps} req/sec",
            f"    Safe Harbor:       {p.safe_harbor}",
        ]
        if p.special_instructions:
            lines.append("  Special Instructions:")
            for inst in p.special_instructions:
                lines.append(f"    - {inst}")
        lines.append("=" * 60)
        lines.append("")

        print("\n".join(lines))

    # ── Helpers ───────────────────────────────────────────────

    def _domain_matches_any(self, host: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            regex = pattern.replace(".", r"\.").replace("*", ".*")
            if re.fullmatch(regex, host):
                return True
        return False

    def _record_violation(self, reason: str):
        self.violations.append(reason)
        self.blocked_requests += 1
        logger.warning(f"POLICY VIOLATION BLOCKED: {reason}")


# ── Template Policies ─────────────────────────────────────────

def create_example_policy(program_name: str = "Example Program") -> BBPPolicy:
    """Create an example policy that users can edit."""
    return BBPPolicy(
        program_name=program_name,
        platform="generic",
        program_url="https://example.com/security",
        in_scope_domains=["example.com", "*.example.com", "api.example.com"],
        in_scope_urls=[],
        asset_types=["web", "api"],
        oos_domains=["blog.example.com", "status.example.com", "*.staging.example.com"],
        oos_urls=["https://example.com/admin"],
        oos_paths=["/careers", "/about", "/blog", "/static"],
        oos_ips=["10.0.0.0/8", "192.168.0.0/16"],
        oos_vuln_types=[
            "self_xss", "logout_csrf", "missing_best_practices",
            "clickjacking_no_sensitive_action", "content_spoofing",
            "email_enumeration", "host_header_without_impact",
            "software_version_disclosure", "stack_trace_without_sensitive_info",
            "tab_nabbing", "text_injection", "username_enumeration",
            "rate_limiting_non_critical", "missing_cookie_flags",
            "missing_security_headers_non_sensitive",
        ],
        no_dos=True,
        no_data_exfil=True,
        no_data_modification=True,
        no_social_engineering=True,
        no_physical=True,
        no_automated_mass_scan=False,
        rate_limit_rps=5.0,
        special_instructions=[
            "Do NOT test on production accounts with real user data",
            "Create your own test accounts for testing",
            "Do NOT access other users' data",
            "Report vulnerabilities immediately, do not chain exploits",
        ],
        safe_harbor=True,
        disclosure_policy="coordinated",
        min_severity="low",
        reward_range={
            "critical": "$1000 - $5000",
            "high": "$500 - $1000",
            "medium": "$100 - $500",
            "low": "$50 - $100",
        },
    )


def save_example_policy(path: str = "policy_example.json"):
    """Save an example policy file for reference."""
    policy = create_example_policy()
    policy.save(path)
    return path
