"""
Pre-Engagement Checklist Engine — validates ALL program constraints before scanning.

SAFETY CRITICAL: This module runs BEFORE any network traffic is sent.
If any mandatory check fails, the scan is ABORTED to prevent:
  - Testing out-of-scope assets (illegal)
  - Violating program rules (account ban, legal action)
  - Triggering exclusion conditions (DoS, mass scan, etc.)

Flow:
    1. Load pre-engagement checklist (JSON)
    2. Validate every mandatory_check section
    3. Apply enforcement rules:
       - IF target NOT in_scope_assets → Abort
       - IF vulnerability_type IN scope_exclusions → Abort
       - IF automated_scanning_restrictions == true → Disable mass scan module
       - IF safe_harbor_clause_present == false → Flag high legal risk
    4. Return PreEngagementResult with pass/fail + gate decisions
"""
from __future__ import annotations
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
#  DATA MODELS
# ══════════════════════════════════════════════════════════════

@dataclass
class CheckResult:
    """Result of a single checklist item."""
    section: str
    check_name: str
    passed: bool
    severity: str = "info"        # critical, warning, info
    message: str = ""
    action: str = ""              # abort, disable_module, flag, none

    def __str__(self) -> str:
        icon = "✅" if self.passed else ("🚫" if self.severity == "critical" else "⚠️")
        return f"{icon} [{self.section}] {self.check_name}: {self.message}"


@dataclass
class PreEngagementResult:
    """Aggregated result of the full pre-engagement checklist."""
    passed: bool = True
    checks: List[CheckResult] = field(default_factory=list)
    abort_reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    disabled_modules: List[str] = field(default_factory=list)
    enforced_rate_limit: Optional[float] = None
    legal_risk: str = "low"       # low, medium, high
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def add(self, result: CheckResult) -> None:
        self.checks.append(result)
        if not result.passed:
            if result.severity == "critical":
                self.passed = False
                self.abort_reasons.append(result.message)
            elif result.severity == "warning":
                self.warnings.append(result.message)
        if result.action == "abort":
            self.passed = False
        elif result.action.startswith("disable_module:"):
            mod = result.action.split(":", 1)[1]
            if mod not in self.disabled_modules:
                self.disabled_modules.append(mod)

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed and c.severity == "critical")

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed and c.severity == "warning")

    def summary(self) -> str:
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c.passed)
        lines = [
            f"Pre-Engagement Check: {'PASSED ✅' if self.passed else 'FAILED 🚫'}",
            f"  Checks: {passed}/{total} passed",
            f"  Critical failures: {self.critical_count}",
            f"  Warnings: {self.warning_count}",
            f"  Legal risk: {self.legal_risk.upper()}",
        ]
        if self.disabled_modules:
            lines.append(f"  Disabled modules: {', '.join(self.disabled_modules)}")
        if self.enforced_rate_limit:
            lines.append(f"  Rate limit enforced: {self.enforced_rate_limit} req/s")
        if self.abort_reasons:
            lines.append("  Abort reasons:")
            for r in self.abort_reasons:
                lines.append(f"    🚫 {r}")
        if self.warnings:
            lines.append("  Warnings:")
            for w in self.warnings:
                lines.append(f"    ⚠️ {w}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "critical_failures": self.critical_count,
            "warnings": self.warning_count,
            "abort_reasons": self.abort_reasons,
            "disabled_modules": self.disabled_modules,
            "enforced_rate_limit": self.enforced_rate_limit,
            "legal_risk": self.legal_risk,
            "checks": [
                {
                    "section": c.section,
                    "name": c.check_name,
                    "passed": c.passed,
                    "severity": c.severity,
                    "message": c.message,
                }
                for c in self.checks
            ],
            "timestamp": self.timestamp,
        }


# ══════════════════════════════════════════════════════════════
#  PRE-ENGAGEMENT CHECKLIST
# ══════════════════════════════════════════════════════════════

@dataclass
class PreEngagementChecklist:
    """
    Full pre-engagement checklist loaded from JSON.
    Maps directly to the schema the user provides.
    """
    # ── Program Metadata ──
    program_overview: str = ""
    bounty_model: List[str] = field(default_factory=lambda: ["vdp"])
    severity_mapping_required: bool = True
    custom_rules_override_platform: bool = True

    # ── Legal & Compliance ──
    jurisdiction_defined: bool = True
    safe_harbor_clause_present: bool = False
    coordinated_disclosure_required: bool = True
    embargo_period_specified: bool = True

    # ── Scope ──
    in_scope_domains: List[str] = field(default_factory=list)
    in_scope_urls: List[str] = field(default_factory=list)
    in_scope_api_endpoints: List[str] = field(default_factory=list)
    in_scope_mobile_apps: List[str] = field(default_factory=list)
    in_scope_cloud_assets: List[str] = field(default_factory=list)
    wildcard_domains_allowed: bool = False

    # ── Out-of-Scope Assets ──
    oos_domains: List[str] = field(default_factory=list)
    oos_urls: List[str] = field(default_factory=list)
    oos_paths: List[str] = field(default_factory=list)
    third_party_services_excluded: bool = True
    internal_tools_excluded: bool = True
    employee_accounts_excluded: bool = True

    # ── Scope Exclusions (vulnerability types / attack methods) ──
    denial_of_service_excluded: bool = True
    social_engineering_excluded: bool = True
    physical_attacks_excluded: bool = True
    automated_scanning_restrictions: bool = True
    rate_limit_abuse_excluded: bool = True
    spam_or_bruteforce_excluded: bool = True
    excluded_vuln_types: List[str] = field(default_factory=list)

    # ── Known Issues ──
    known_issues_are_duplicates: bool = True
    publicly_disclosed_excluded: bool = True

    # ── Program Rules ──
    account_creation_required: bool = True
    separate_testing_account_required: bool = True
    data_exfiltration_limits_defined: bool = True
    no_data_destruction: bool = True
    no_privacy_violation: bool = True

    # ── Report Eligibility ──
    poc_required: bool = True
    reproducibility_required: bool = True
    impact_demonstration_required: bool = True
    duplicate_policy_defined: bool = True
    minimum_severity_threshold: str = "low"

    # ── Test Plan & Credentials ──
    sandbox_available: bool = False
    test_accounts_provided: bool = False
    custom_test_credentials_required: bool = False
    production_testing_allowed: bool = True
    rate_limit_rps: float = 5.0

    # ── Operational Safety ──
    logging_enabled: bool = True
    traffic_recording_enabled: bool = True
    vpn_usage_allowed: bool = True
    tor_usage_allowed: bool = False
    automated_tools_allowed: bool = False
    api_rate_limit_threshold: float = 10.0

    # ── Risk Control ──
    exploit_chain_restrictions: bool = True
    privilege_escalation_allowed: bool = True
    cloud_metadata_access_allowed: bool = False
    mass_scanning_prohibited: bool = True

    @classmethod
    def from_file(cls, path: str) -> "PreEngagementChecklist":
        """Load checklist from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PreEngagementChecklist":
        """
        Parse the pre-engagement checklist JSON into a flat checklist.

        Supports TWO formats:
          1. Internal (verbose) — keys like program_metadata, scope_validation, ...
          2. User-facing (simple) — keys like target_information, scope_and_exclusions, ...
        Auto-detects based on which keys are present.
        """
        checklist = cls()

        # Support both nested and flat formats
        root = data.get("pre_engagement_checklist", data)

        # Auto-detect format
        is_user_format = "target_information" in root or "scope_and_exclusions" in root

        if is_user_format:
            return cls._parse_user_format(root)
        else:
            return cls._parse_internal_format(root)

    @classmethod
    def _parse_user_format(cls, root: Dict[str, Any]) -> "PreEngagementChecklist":
        """Parse the user-facing, simple JSON format (example_pre_engagement.json)."""
        checklist = cls()

        # ── Target Information ──
        target_info = root.get("target_information", {})
        checklist.program_overview = target_info.get("target_name", "")

        # Extract scope domains / OOS from target_information
        in_scope = target_info.get("in_scope_assets", [])
        if isinstance(in_scope, list):
            checklist.in_scope_domains = in_scope
            checklist.wildcard_domains_allowed = any("*" in d for d in in_scope)
        oos = target_info.get("out_of_scope_assets", [])
        if isinstance(oos, list):
            checklist.oos_domains = oos

        # ── Legal & Authorization ──
        legal = root.get("legal_and_authorization", {})
        checklist.safe_harbor_clause_present = legal.get("safe_harbor_clause_present", False)
        checklist.jurisdiction_defined = bool(legal.get("legal_jurisdiction"))
        checklist.coordinated_disclosure_required = (
            legal.get("authorization_type", "") == "bug_bounty_program"
        )

        # ── Scope & Exclusions ──
        scope_excl = root.get("scope_and_exclusions", {})

        # Excluded vulnerability types
        excluded_types = scope_excl.get("vulnerability_types_excluded", [])
        checklist.excluded_vuln_types = excluded_types

        # Map common exclusion names to flags
        excl_lower = {v.lower() for v in excluded_types}
        checklist.denial_of_service_excluded = any(
            x in excl_lower for x in ("dos", "denial_of_service", "ddos")
        )
        checklist.social_engineering_excluded = any(
            x in excl_lower for x in ("social_engineering", "social engineering")
        )
        checklist.physical_attacks_excluded = any(
            x in excl_lower for x in ("physical_access", "physical_attacks", "physical")
        )

        # Rate limit from string like "Max 10 requests per second"
        rate_str = scope_excl.get("rate_limiting_requirements", "")
        rps = cls._parse_rate_limit_string(rate_str)
        if rps:
            checklist.rate_limit_rps = rps

        # ── Operational Safety ──
        ops = root.get("operational_safety", {})
        checklist.automated_tools_allowed = ops.get("automated_scanning_allowed", False)
        checklist.automated_scanning_restrictions = ops.get(
            "automated_scanning_restrictions", False
        )
        checklist.cloud_metadata_access_allowed = ops.get(
            "cloud_metadata_testing_allowed", False
        )
        checklist.spam_or_bruteforce_excluded = not ops.get("bruteforce_allowed", True)
        checklist.mass_scanning_prohibited = not ops.get(
            "mass_assignment_testing_allowed", True
        )

        # Rate limit from operational safety (prefer explicit number)
        max_rps = ops.get("max_requests_per_second")
        if max_rps and isinstance(max_rps, (int, float)):
            checklist.rate_limit_rps = float(max_rps)
            checklist.api_rate_limit_threshold = float(max_rps)

        # ── Program Rules ──
        rules = root.get("program_rules", {})
        disclosure = rules.get("disclosure_policy", "")
        checklist.coordinated_disclosure_required = disclosure == "coordinated"
        checklist.embargo_period_specified = bool(rules.get("min_disclosure_days"))

        # ── Reporting Requirements ──
        reporting = root.get("reporting_requirements", {})
        checklist.poc_required = reporting.get("poc_required", True)
        checklist.impact_demonstration_required = True
        min_sev = reporting.get("minimum_severity", "low")
        checklist.minimum_severity_threshold = min_sev

        # ── Risk Control ──
        risk = root.get("risk_control", {})
        checklist.production_testing_allowed = True  # default for user format
        max_sev = risk.get("max_severity_to_test", "critical")
        checklist.exploit_chain_restrictions = max_sev != "critical"
        checklist.privilege_escalation_allowed = True
        if risk.get("avoid_production_impact", False):
            checklist.no_data_destruction = True
            checklist.no_privacy_violation = True
        checklist.sandbox_available = risk.get("staging_environment_available", False)
        checklist.test_accounts_provided = risk.get("test_accounts_provided", False)

        return checklist

    @classmethod
    def _parse_internal_format(cls, root: Dict[str, Any]) -> "PreEngagementChecklist":
        """Parse the internal/verbose JSON format used by to_dict()."""
        checklist = cls()

        # ── Program Metadata ──
        meta = root.get("program_metadata", {})
        overview = meta.get("overview", {})
        checklist.program_overview = overview.get("description", "")

        rewards = meta.get("rewards_summary", {})
        checklist.bounty_model = rewards.get("bounty_model", ["vdp"])
        checklist.severity_mapping_required = rewards.get("severity_mapping_required", True)

        platform_std = meta.get("platform_standards_deviations", {})
        checklist.custom_rules_override_platform = platform_std.get(
            "custom_rules_override_platform_defaults", True
        )

        # ── Legal & Compliance ──
        legal = root.get("legal_and_compliance", {})
        compliance = legal.get("compliance_and_governing_law", {})
        checklist.jurisdiction_defined = compliance.get("jurisdiction_defined", True)
        checklist.safe_harbor_clause_present = compliance.get("safe_harbor_clause_present", False)

        disclosure = legal.get("disclosure_policy", {})
        checklist.coordinated_disclosure_required = disclosure.get(
            "coordinated_disclosure_required", True
        )
        checklist.embargo_period_specified = disclosure.get("embargo_period_specified", True)

        # ── Scope Validation ──
        scope_val = root.get("scope_validation", {})

        in_scope = scope_val.get("in_scope_assets", {})
        if isinstance(in_scope, dict):
            checklist.wildcard_domains_allowed = not in_scope.get("wildcard_domains_allowed", True)
        elif isinstance(in_scope, list):
            checklist.in_scope_domains = in_scope

        oos = scope_val.get("out_of_scope_assets", {})
        if isinstance(oos, dict):
            checklist.third_party_services_excluded = oos.get("third_party_services_excluded", True)
            checklist.internal_tools_excluded = oos.get("internal_tools_excluded", True)
            checklist.employee_accounts_excluded = oos.get("employee_accounts_excluded", True)
        elif isinstance(oos, list):
            checklist.oos_domains = oos

        excl = scope_val.get("scope_exclusions", {})
        checklist.denial_of_service_excluded = excl.get("denial_of_service", True)
        checklist.social_engineering_excluded = excl.get("social_engineering", True)
        checklist.physical_attacks_excluded = excl.get("physical_attacks", True)
        checklist.automated_scanning_restrictions = excl.get("automated_scanning_restrictions", True)
        checklist.rate_limit_abuse_excluded = excl.get("rate_limit_abuse", True)
        checklist.spam_or_bruteforce_excluded = excl.get("spam_or_bruteforce", True)

        # ── Known Issues ──
        known = root.get("known_issues_handling", {})
        checklist.known_issues_are_duplicates = known.get(
            "known_issues_will_be_closed_as_duplicates", True
        )
        checklist.publicly_disclosed_excluded = known.get(
            "publicly_disclosed_vulnerabilities_excluded", True
        )

        # ── Program Rules ──
        rules = root.get("program_rules", {})
        checklist.account_creation_required = rules.get("account_creation_required", True)
        checklist.separate_testing_account_required = rules.get(
            "separate_testing_account_required", True
        )
        checklist.data_exfiltration_limits_defined = rules.get(
            "data_exfiltration_limits_defined", True
        )
        checklist.no_data_destruction = rules.get("no_data_destruction_allowed", True)
        checklist.no_privacy_violation = rules.get("no_privacy_violation_allowed", True)

        # ── Report Eligibility ──
        report = root.get("report_eligibility", {})
        checklist.poc_required = report.get("proof_of_concept_required", True)
        checklist.reproducibility_required = report.get("reproducibility_required", True)
        checklist.impact_demonstration_required = report.get(
            "impact_demonstration_required", True
        )
        checklist.duplicate_policy_defined = report.get("duplicate_policy_defined", True)

        # ── Test Plan ──
        test_plan = root.get("test_plan_and_credentials", {})
        checklist.sandbox_available = test_plan.get("sandbox_environment_available", False)
        checklist.test_accounts_provided = test_plan.get("test_accounts_provided", False)
        checklist.custom_test_credentials_required = test_plan.get(
            "custom_test_credentials_required", False
        )
        checklist.production_testing_allowed = test_plan.get("production_testing_allowed", True)
        rate_val = test_plan.get("rate_limit_policy_defined", 5.0)
        if isinstance(rate_val, (int, float)):
            checklist.rate_limit_rps = float(rate_val)

        # ── Operational Safety ──
        ops = root.get("operational_safety", {})
        checklist.logging_enabled = ops.get("logging_enabled", True)
        checklist.traffic_recording_enabled = ops.get("traffic_recording_enabled", True)
        checklist.vpn_usage_allowed = ops.get("vpn_usage_allowed", True)
        checklist.tor_usage_allowed = ops.get("tor_usage_allowed", False)
        checklist.automated_tools_allowed = ops.get("automated_tools_allowed", False)

        # ── Risk Control ──
        risk = root.get("risk_control", {})
        checklist.exploit_chain_restrictions = risk.get(
            "exploit_chain_restrictions_defined", True
        )
        checklist.privilege_escalation_allowed = risk.get(
            "privilege_escalation_testing_allowed", True
        )
        checklist.cloud_metadata_access_allowed = risk.get(
            "cloud_metadata_access_allowed", False
        )
        checklist.mass_scanning_prohibited = risk.get("mass_scanning_prohibited", True)

        return checklist

    @staticmethod
    def _parse_rate_limit_string(s: str) -> Optional[float]:
        """Extract a numeric rate limit from strings like 'Max 10 requests per second'."""
        if not s:
            return None
        import re as _re
        m = _re.search(r'(\d+(?:\.\d+)?)\s*(?:req|request)', s, _re.IGNORECASE)
        if m:
            return float(m.group(1))
        m = _re.search(r'(\d+(?:\.\d+)?)', s)
        if m:
            return float(m.group(1))
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize back to the nested JSON schema."""
        return {
            "pre_engagement_checklist": {
                "program_metadata": {
                    "overview": {"description": self.program_overview, "mandatory_check": True},
                    "rewards_summary": {
                        "bounty_model": self.bounty_model,
                        "severity_mapping_required": self.severity_mapping_required,
                        "mandatory_check": True,
                    },
                    "platform_standards_deviations": {
                        "custom_rules_override_platform_defaults": self.custom_rules_override_platform,
                        "mandatory_check": True,
                    },
                },
                "legal_and_compliance": {
                    "compliance_and_governing_law": {
                        "jurisdiction_defined": self.jurisdiction_defined,
                        "safe_harbor_clause_present": self.safe_harbor_clause_present,
                        "mandatory_check": True,
                    },
                    "disclosure_policy": {
                        "coordinated_disclosure_required": self.coordinated_disclosure_required,
                        "embargo_period_specified": self.embargo_period_specified,
                        "mandatory_check": True,
                    },
                },
                "scope_validation": {
                    "in_scope_assets": {
                        "explicit_asset_list_provided": bool(self.in_scope_domains),
                        "wildcard_domains_allowed": self.wildcard_domains_allowed,
                        "api_endpoints_listed": bool(self.in_scope_api_endpoints),
                        "mobile_apps_listed": bool(self.in_scope_mobile_apps),
                        "cloud_assets_listed": bool(self.in_scope_cloud_assets),
                        "mandatory_check": True,
                    },
                    "out_of_scope_assets": {
                        "third_party_services_excluded": self.third_party_services_excluded,
                        "internal_tools_excluded": self.internal_tools_excluded,
                        "employee_accounts_excluded": self.employee_accounts_excluded,
                        "mandatory_check": True,
                    },
                    "scope_exclusions": {
                        "denial_of_service": self.denial_of_service_excluded,
                        "social_engineering": self.social_engineering_excluded,
                        "physical_attacks": self.physical_attacks_excluded,
                        "automated_scanning_restrictions": self.automated_scanning_restrictions,
                        "rate_limit_abuse": self.rate_limit_abuse_excluded,
                        "spam_or_bruteforce": self.spam_or_bruteforce_excluded,
                        "mandatory_check": True,
                    },
                },
                "known_issues_handling": {
                    "known_issues_will_be_closed_as_duplicates": self.known_issues_are_duplicates,
                    "publicly_disclosed_vulnerabilities_excluded": self.publicly_disclosed_excluded,
                    "mandatory_check": True,
                },
                "program_rules": {
                    "account_creation_required": self.account_creation_required,
                    "separate_testing_account_required": self.separate_testing_account_required,
                    "data_exfiltration_limits_defined": self.data_exfiltration_limits_defined,
                    "no_data_destruction_allowed": self.no_data_destruction,
                    "no_privacy_violation_allowed": self.no_privacy_violation,
                    "mandatory_check": True,
                },
                "report_eligibility": {
                    "proof_of_concept_required": self.poc_required,
                    "reproducibility_required": self.reproducibility_required,
                    "impact_demonstration_required": self.impact_demonstration_required,
                    "duplicate_policy_defined": self.duplicate_policy_defined,
                    "minimum_severity_threshold_defined": True,
                    "mandatory_check": True,
                },
                "test_plan_and_credentials": {
                    "sandbox_environment_available": self.sandbox_available,
                    "test_accounts_provided": self.test_accounts_provided,
                    "custom_test_credentials_required": self.custom_test_credentials_required,
                    "production_testing_allowed": self.production_testing_allowed,
                    "rate_limit_policy_defined": True,
                    "mandatory_check": True,
                },
                "operational_safety": {
                    "logging_enabled": self.logging_enabled,
                    "traffic_recording_enabled": self.traffic_recording_enabled,
                    "vpn_usage_allowed": self.vpn_usage_allowed,
                    "tor_usage_allowed": self.tor_usage_allowed,
                    "automated_tools_allowed": self.automated_tools_allowed,
                    "api_rate_limit_threshold_defined": True,
                    "mandatory_check": True,
                },
                "risk_control": {
                    "exploit_chain_restrictions_defined": self.exploit_chain_restrictions,
                    "privilege_escalation_testing_allowed": self.privilege_escalation_allowed,
                    "cloud_metadata_access_allowed": self.cloud_metadata_access_allowed,
                    "mass_scanning_prohibited": self.mass_scanning_prohibited,
                    "mandatory_check": True,
                },
            }
        }

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)


# ══════════════════════════════════════════════════════════════
#  PRE-ENGAGEMENT GATE — ENFORCEMENT ENGINE
# ══════════════════════════════════════════════════════════════

# Modules that constitute "mass scanning" / DoS-like behaviour
MASS_SCAN_MODULES = {
    "subdomain_takeover",   # enumerates subdomains
    "race_condition",       # concurrent request floods
}

# Modules that test cloud metadata (SSRF to 169.254.x)
CLOUD_METADATA_MODULES = {
    "ssrf",
}

# Modules involving brute-force / spray attacks
BRUTEFORCE_MODULES = {
    "auth_scanner",  # default credential checks
}

# Vuln types excluded when DoS testing is banned
DOS_EXCLUDED_VULN_TYPES = {
    "race_condition", "dos", "denial_of_service", "resource_exhaustion",
}

# Vuln types excluded when social engineering is banned
SOCIAL_EXCLUDED_VULN_TYPES = {
    "phishing", "social_engineering", "pretexting",
}


class PreEngagementGate:
    """
    Runs the full pre-engagement checklist against the target and program config.
    Returns a PreEngagementResult that the orchestrator uses to gate the scan.

    Enforcement rules:
      IF target NOT in_scope_assets → Abort
      IF vulnerability_type IN scope_exclusions → Abort
      IF automated_scanning_restrictions == true → Disable mass scan modules
      IF safe_harbor_clause_present == false → Flag high legal risk
    """

    def __init__(self, checklist: PreEngagementChecklist):
        self.checklist = checklist

    def run_checks(
        self,
        target_url: str,
        in_scope_domains: List[str],
        oos_domains: List[str] = None,
        requested_modules: List[str] = None,
    ) -> PreEngagementResult:
        """
        Execute the full pre-engagement gate.
        Returns PreEngagementResult with pass/fail and enforcement decisions.
        """
        result = PreEngagementResult()
        cl = self.checklist
        oos_domains = oos_domains or []
        requested_modules = requested_modules or []

        # ═══════════════════════════════════════════════════════
        #  SECTION 1: SCOPE VALIDATION (CRITICAL — can abort)
        # ═══════════════════════════════════════════════════════

        parsed = urlparse(target_url)
        target_host = parsed.hostname or ""

        # CHECK: Target must be in scope
        if in_scope_domains:
            in_scope = self._domain_matches_any(target_host, in_scope_domains)
            result.add(CheckResult(
                section="scope_validation",
                check_name="target_in_scope",
                passed=in_scope,
                severity="critical" if not in_scope else "info",
                message=(
                    f"Target '{target_host}' is in scope"
                    if in_scope
                    else f"ABORT: Target '{target_host}' is NOT in in-scope assets: {in_scope_domains}"
                ),
                action="abort" if not in_scope else "none",
            ))
        else:
            result.add(CheckResult(
                section="scope_validation",
                check_name="target_in_scope",
                passed=False,
                severity="critical",
                message="ABORT: No in-scope assets defined — cannot verify target is allowed",
                action="abort",
            ))

        # CHECK: Target must NOT be out-of-scope
        if oos_domains:
            is_oos = self._domain_matches_any(target_host, oos_domains)
            result.add(CheckResult(
                section="scope_validation",
                check_name="target_not_oos",
                passed=not is_oos,
                severity="critical" if is_oos else "info",
                message=(
                    f"ABORT: Target '{target_host}' is in OUT-OF-SCOPE list!"
                    if is_oos
                    else f"Target '{target_host}' is not in exclusion list"
                ),
                action="abort" if is_oos else "none",
            ))

        # CHECK: Wildcard domain restriction
        has_wildcard = any("*" in d for d in in_scope_domains)
        if has_wildcard and not cl.wildcard_domains_allowed:
            result.add(CheckResult(
                section="scope_validation",
                check_name="wildcard_restriction",
                passed=False,
                severity="warning",
                message="Wildcard domains in scope but policy disallows wildcards — verify exact subdomains",
            ))

        # ═══════════════════════════════════════════════════════
        #  SECTION 2: LEGAL & COMPLIANCE
        # ═══════════════════════════════════════════════════════

        # CHECK: Safe harbor
        if not cl.safe_harbor_clause_present:
            result.add(CheckResult(
                section="legal_compliance",
                check_name="safe_harbor",
                passed=False,
                severity="warning",
                message="No safe harbor clause — HIGH legal risk. Proceed with extreme caution.",
                action="none",
            ))
            result.legal_risk = "high"
        else:
            result.add(CheckResult(
                section="legal_compliance",
                check_name="safe_harbor",
                passed=True,
                severity="info",
                message="Safe harbor clause present — legal protection active",
            ))
            result.legal_risk = "low"

        # CHECK: Jurisdiction
        result.add(CheckResult(
            section="legal_compliance",
            check_name="jurisdiction",
            passed=cl.jurisdiction_defined,
            severity="warning" if not cl.jurisdiction_defined else "info",
            message=(
                "Jurisdiction defined" if cl.jurisdiction_defined
                else "No jurisdiction defined — legal ambiguity risk"
            ),
        ))

        # CHECK: Coordinated disclosure
        result.add(CheckResult(
            section="legal_compliance",
            check_name="disclosure_policy",
            passed=cl.coordinated_disclosure_required,
            severity="info",
            message=(
                "Coordinated disclosure required — respect embargo"
                if cl.coordinated_disclosure_required
                else "No coordinated disclosure requirement"
            ),
        ))

        # ═══════════════════════════════════════════════════════
        #  SECTION 3: SCOPE EXCLUSIONS (vuln types & attack methods)
        # ═══════════════════════════════════════════════════════

        # CHECK: Automated scanning restrictions
        if cl.automated_scanning_restrictions:
            result.add(CheckResult(
                section="scope_exclusions",
                check_name="automated_scanning",
                passed=False,
                severity="warning",
                message="Automated scanning restricted — disabling mass scan modules",
                action="none",  # handled below via module disabling
            ))
            # Disable mass scan modules
            for mod in MASS_SCAN_MODULES:
                if not requested_modules or mod in requested_modules:
                    result.disabled_modules.append(mod)

        # CHECK: Mass scanning prohibition
        if cl.mass_scanning_prohibited:
            result.add(CheckResult(
                section="risk_control",
                check_name="mass_scanning",
                passed=False,
                severity="warning",
                message="Mass scanning prohibited — subdomain/bulk modules disabled",
            ))
            for mod in MASS_SCAN_MODULES:
                if mod not in result.disabled_modules:
                    result.disabled_modules.append(mod)

        # CHECK: DoS exclusion
        if cl.denial_of_service_excluded:
            result.add(CheckResult(
                section="scope_exclusions",
                check_name="dos_excluded",
                passed=True,
                severity="info",
                message="DoS testing excluded — race condition module will use reduced concurrency",
            ))
            if "race_condition" not in result.disabled_modules:
                result.disabled_modules.append("race_condition")

        # CHECK: Brute-force / spam exclusion
        if cl.spam_or_bruteforce_excluded:
            result.add(CheckResult(
                section="scope_exclusions",
                check_name="bruteforce_excluded",
                passed=True,
                severity="info",
                message="Brute-force/spam excluded — credential spraying disabled in auth_scanner",
            ))
            # We don't fully disable auth_scanner, but flag it for reduced mode
            # The auth_scanner will check this flag

        # CHECK: Cloud metadata access
        if not cl.cloud_metadata_access_allowed:
            result.add(CheckResult(
                section="risk_control",
                check_name="cloud_metadata",
                passed=True,
                severity="info",
                message="Cloud metadata access disallowed — SSRF cloud payloads will be filtered",
            ))
            # SSRF scanner will filter 169.254.x payloads based on this

        # CHECK: Automated tools
        if not cl.automated_tools_allowed:
            result.add(CheckResult(
                section="operational_safety",
                check_name="automated_tools",
                passed=False,
                severity="warning",
                message=(
                    "Program does NOT allow automated tools. "
                    "This agent IS an automated tool — risk of program violation."
                ),
            ))
            if result.legal_risk != "high":
                result.legal_risk = "medium"

        # ═══════════════════════════════════════════════════════
        #  SECTION 4: OPERATIONAL SAFETY
        # ═══════════════════════════════════════════════════════

        # CHECK: Rate limiting
        if cl.rate_limit_rps and isinstance(cl.rate_limit_rps, (int, float)):
            rps = float(cl.rate_limit_rps)
            if rps > 0:
                result.enforced_rate_limit = rps
                result.add(CheckResult(
                    section="operational_safety",
                    check_name="rate_limit",
                    passed=True,
                    severity="info",
                    message=f"Rate limit enforced: {rps} req/s",
                ))

        # CHECK: Logging
        if cl.logging_enabled:
            result.add(CheckResult(
                section="operational_safety",
                check_name="logging",
                passed=True,
                severity="info",
                message="Logging enabled — all requests will be recorded",
            ))

        # CHECK: Production testing
        if cl.production_testing_allowed:
            result.add(CheckResult(
                section="test_plan",
                check_name="production_testing",
                passed=True,
                severity="info",
                message="Production testing allowed — proceed with caution on data-modifying tests",
            ))
        else:
            result.add(CheckResult(
                section="test_plan",
                check_name="production_testing",
                passed=False,
                severity="critical",
                message="ABORT: Production testing NOT allowed and no sandbox configured",
                action="abort" if not cl.sandbox_available else "none",
            ))

        # ═══════════════════════════════════════════════════════
        #  SECTION 5: PROGRAM RULES
        # ═══════════════════════════════════════════════════════

        # CHECK: Data destruction
        if cl.no_data_destruction:
            result.add(CheckResult(
                section="program_rules",
                check_name="no_data_destruction",
                passed=True,
                severity="info",
                message="Data destruction prohibited — destructive payloads (DROP, DELETE) will be blocked",
            ))

        # CHECK: Privacy
        if cl.no_privacy_violation:
            result.add(CheckResult(
                section="program_rules",
                check_name="no_privacy_violation",
                passed=True,
                severity="info",
                message="Privacy violations prohibited — no exfiltration of real user data",
            ))

        # CHECK: Data exfiltration limits
        if cl.data_exfiltration_limits_defined:
            result.add(CheckResult(
                section="program_rules",
                check_name="data_exfil_limits",
                passed=True,
                severity="info",
                message="Data exfiltration limits defined — agent will limit extraction in PoC",
            ))

        # ═══════════════════════════════════════════════════════
        #  SECTION 6: REPORT ELIGIBILITY
        # ═══════════════════════════════════════════════════════

        if cl.poc_required:
            result.add(CheckResult(
                section="report_eligibility",
                check_name="poc_required",
                passed=True,
                severity="info",
                message="PoC required — agent will generate reproduction steps for all findings",
            ))

        if cl.impact_demonstration_required:
            result.add(CheckResult(
                section="report_eligibility",
                check_name="impact_required",
                passed=True,
                severity="info",
                message="Impact demonstration required — findings must include impact assessment",
            ))

        # ═══════════════════════════════════════════════════════
        #  SECTION 7: PRIVILEGE ESCALATION & EXPLOIT CHAINS
        # ═══════════════════════════════════════════════════════

        if cl.exploit_chain_restrictions:
            result.add(CheckResult(
                section="risk_control",
                check_name="exploit_chains",
                passed=True,
                severity="info",
                message="Exploit chain restrictions defined — agent will not chain vulnerabilities",
            ))

        if not cl.privilege_escalation_allowed:
            result.add(CheckResult(
                section="risk_control",
                check_name="privesc",
                passed=True,
                severity="info",
                message="Privilege escalation testing disabled",
            ))

        return result

    def get_excluded_vuln_types(self) -> Set[str]:
        """Return the set of vulnerability types that must be excluded per policy."""
        excluded = set(self.checklist.excluded_vuln_types)

        if self.checklist.denial_of_service_excluded:
            excluded.update(DOS_EXCLUDED_VULN_TYPES)

        if self.checklist.social_engineering_excluded:
            excluded.update(SOCIAL_EXCLUDED_VULN_TYPES)

        return excluded

    def is_vuln_type_allowed(self, vuln_type: str) -> bool:
        """Check if a vulnerability type is allowed by the checklist."""
        excluded = self.get_excluded_vuln_types()
        vuln_lower = vuln_type.lower()
        for excl in excluded:
            if excl.lower() in vuln_lower or vuln_lower in excl.lower():
                return False
        return True

    def should_filter_cloud_payloads(self) -> bool:
        """Whether to strip cloud metadata payloads from SSRF scanner."""
        return not self.checklist.cloud_metadata_access_allowed

    def should_disable_bruteforce(self) -> bool:
        """Whether to disable credential brute-forcing in auth scanner."""
        return self.checklist.spam_or_bruteforce_excluded

    def get_enforced_rate_limit(self) -> Optional[float]:
        """Get the rate limit to enforce, if any."""
        rps = self.checklist.rate_limit_rps
        if isinstance(rps, (int, float)) and rps > 0:
            return float(rps)
        return None

    # ── Helpers ───────────────────────────────────────────────

    def _domain_matches_any(self, host: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            regex = pattern.replace(".", r"\.").replace("*", ".*")
            if re.fullmatch(regex, host, re.IGNORECASE):
                return True
        return False


# ══════════════════════════════════════════════════════════════
#  CONSOLE OUTPUT
# ══════════════════════════════════════════════════════════════

def print_pre_engagement_banner(result: PreEngagementResult) -> None:
    """Print the pre-engagement check results to console."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich import box

        console = Console()
        console.print()

        # Header
        status = "[bold green]PASSED ✅[/]" if result.passed else "[bold red]FAILED 🚫[/]"
        risk_color = {"low": "green", "medium": "yellow", "high": "red"}.get(result.legal_risk, "white")

        console.print(Panel.fit(
            f"[bold white]📋 Pre-Engagement Checklist[/]  │  Status: {status}  │  "
            f"Legal Risk: [{risk_color}]{result.legal_risk.upper()}[/]",
            title="[bold blue]Gate Check[/]",
            border_style="blue" if result.passed else "red",
        ))

        # Results table
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_lines=False)
        table.add_column("#", width=3, style="dim")
        table.add_column("Section", width=20)
        table.add_column("Check", width=24)
        table.add_column("Result", width=8)
        table.add_column("Details", ratio=1)

        for i, check in enumerate(result.checks, 1):
            icon = "✅" if check.passed else ("🚫" if check.severity == "critical" else "⚠️")
            sev_color = {
                "critical": "bold red",
                "warning": "yellow",
                "info": "dim white",
            }.get(check.severity, "white")
            table.add_row(
                str(i),
                check.section,
                check.check_name,
                icon,
                f"[{sev_color}]{check.message}[/]",
            )

        console.print(table)

        # Disabled modules
        if result.disabled_modules:
            console.print(
                f"\n[yellow]⚠️  Disabled modules: {', '.join(result.disabled_modules)}[/]"
            )

        # Rate limit
        if result.enforced_rate_limit:
            console.print(
                f"[cyan]🔒 Enforced rate limit: {result.enforced_rate_limit} req/s[/]"
            )

        # Abort reasons
        if result.abort_reasons:
            console.print("\n[bold red]🚫 SCAN ABORTED — Critical failures:[/]")
            for reason in result.abort_reasons:
                console.print(f"   [red]• {reason}[/]")

        console.print()

    except ImportError:
        # Fallback without rich
        print(result.summary())
