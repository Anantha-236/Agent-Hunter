"""
HackerOne Auto-Submitter
Reads confirmed findings from ScanState and submits them to HackerOne,
with duplicate detection, scope mapping, and CWE -> weakness_id resolution.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from integrations.hackerone.client import HackerOneClient, HackerOneError

# Import ScanState/Finding from your agent
try:
    from core.models import Finding, ScanState
except ImportError:
    pass   # standalone usage without the full agent

logger = logging.getLogger(__name__)

# ── Severity mapping  (agent severity -> H1 severity) ────────────────────────
SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "none",
}

# ── Minimum severity to auto-submit (skip info/low by default) ──────────────
SUBMIT_MINIMUM_SEVERITY = {"medium", "high", "critical"}


@dataclass
class SubmissionResult:
    finding_id:  str
    report_id:   Optional[int]  = None
    report_url:  Optional[str]  = None
    skipped:     bool           = False
    skip_reason: str            = ""
    error:       Optional[str]  = None

    @property
    def success(self) -> bool:
        return self.report_id is not None and not self.error


class H1Submitter:
    """
    Bridges your agent's findings with HackerOne's report submission API.

    Usage:
        submitter = H1Submitter(
            client=HackerOneClient(...),
            team_handle="target-program-handle",
        )
        results = submitter.submit_findings(state)
        for r in results:
            print(r.finding_id, r.report_url, r.error)
    """

    def __init__(
        self,
        client: HackerOneClient,
        team_handle: str,
        dry_run: bool = False,
        min_severity: Optional[set] = None,
        skip_unconfirmed: bool = True,
    ):
        self.client           = client
        self.team_handle      = team_handle
        self.dry_run          = dry_run
        self.min_severity     = min_severity or SUBMIT_MINIMUM_SEVERITY
        self.skip_unconfirmed = skip_unconfirmed

        # Cache scope and weakness IDs to avoid repeated API calls
        self._scope_cache: Optional[List[Dict]] = None
        self._weakness_cache: Dict[str, Optional[int]] = {}

    # ── Public interface ──────────────────────────────────────────────────────

    def submit_findings(self, state) -> List[SubmissionResult]:
        """Submit all eligible findings from a completed ScanState."""
        results: List[SubmissionResult] = []
        for finding in state.findings:
            result = self._submit_one(finding)
            results.append(result)
        return results

    def submit_finding(self, finding) -> SubmissionResult:
        """Submit a single Finding object."""
        return self._submit_one(finding)

    # ── Internal logic ────────────────────────────────────────────────────────

    def _submit_one(self, finding) -> SubmissionResult:
        result = SubmissionResult(finding_id=finding.id)

        # ── Eligibility checks ────────────────────────────────────────────────
        if self.skip_unconfirmed and not finding.confirmed:
            result.skipped = True
            result.skip_reason = "Not confirmed by AI validation"
            return result

        if finding.severity not in self.min_severity:
            result.skipped = True
            result.skip_reason = f"Severity '{finding.severity}' below threshold"
            return result

        if finding.false_positive:
            result.skipped = True
            result.skip_reason = "Marked as false positive"
            return result

        # ── Build report body ─────────────────────────────────────────────────
        vuln_info   = self._build_vulnerability_information(finding)
        impact      = self._build_impact(finding)
        severity    = SEVERITY_MAP.get(finding.severity, "medium")
        weakness_id = self._resolve_weakness_id(finding.cwe_id)
        scope_id    = self._resolve_scope_id(finding.url)

        logger.info(
            f"[H1] Submitting: {finding.title} | "
            f"severity={severity} | weakness_id={weakness_id} | "
            f"scope_id={scope_id} | dry_run={self.dry_run}"
        )

        if self.dry_run:
            result.skipped = True
            result.skip_reason = "Dry run — no actual submission"
            logger.info(f"[H1] DRY RUN — would submit:\n{finding.title}\n{vuln_info[:200]}")
            return result

        # ── Submit ────────────────────────────────────────────────────────────
        try:
            resp = self.client.submit_report(
                team_handle=self.team_handle,
                title=finding.title,
                vulnerability_information=vuln_info,
                impact=impact,
                severity_rating=severity,
                structured_scope_id=scope_id,
                weakness_id=weakness_id,
            )
            report_data = resp.get("data", {})
            report_id   = int(report_data.get("id", 0))
            result.report_id  = report_id
            result.report_url = f"https://hackerone.com/reports/{report_id}"
            logger.info(f"[H1] Report submitted: {result.report_url}")

        except HackerOneError as exc:
            result.error = str(exc)
            logger.error(f"[H1] Submission failed for {finding.title}: {exc}")

        return result

    # ── Report formatting ─────────────────────────────────────────────────────

    def _build_vulnerability_information(self, finding) -> str:
        """Format the main body of the H1 report in Markdown."""
        sections = [
            f"## Summary\n{finding.description or 'No description provided.'}",
            f"## Vulnerability Details\n"
            f"- **Type:** {finding.vuln_type}\n"
            f"- **URL:** `{finding.url}`\n"
            f"- **Parameter:** `{finding.parameter}`\n"
            f"- **Method:** {finding.method}\n"
            f"- **CWE:** {finding.cwe_id}\n"
            f"- **OWASP:** {finding.owasp_category}",
        ]

        if finding.payload:
            sections.append(f"## Payload\n```\n{finding.payload}\n```")

        if finding.evidence:
            sections.append(f"## Evidence\n```\n{finding.evidence}\n```")

        if finding.request:
            sections.append(
                f"## HTTP Request\n```http\n{finding.request[:1500]}\n```"
            )

        if finding.response:
            sections.append(
                f"## HTTP Response (snippet)\n```\n{finding.response[:800]}\n```"
            )

        if finding.poc_steps:
            steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(finding.poc_steps))
            sections.append(f"## Steps to Reproduce\n{steps_md}")

        if finding.ai_analysis:
            sections.append(f"## Additional Analysis\n{finding.ai_analysis}")

        return "\n\n".join(sections)

    def _build_impact(self, finding) -> str:
        if finding.remediation:
            return (
                f"{finding.description or 'This vulnerability allows an attacker to...'}\n\n"
                f"**CVSS Score:** {finding.cvss_score}\n\n"
                f"**Remediation:**\n{finding.remediation}"
            )
        return finding.description or f"Impact of {finding.vuln_type} vulnerability at {finding.url}"

    # ── Scope resolution ──────────────────────────────────────────────────────

    def _get_scope(self) -> List[Dict]:
        """Lazy-load the program's structured scopes."""
        if self._scope_cache is None:
            try:
                self._scope_cache = self.client.get_program_scope(self.team_handle)
            except Exception as exc:
                logger.warning(f"Could not fetch program scope: {exc}")
                self._scope_cache = []
        return self._scope_cache

    def _resolve_scope_id(self, url: str) -> Optional[int]:
        """
        Find the matching structured scope ID for a given URL.
        Returns None if not found (still submittable without scope ID).
        """
        host = urlparse(url).hostname or ""
        for scope in self._get_scope():
            attrs = scope.get("attributes", {})
            asset_type       = attrs.get("asset_type", "")
            asset_identifier = attrs.get("asset_identifier", "")
            eligible         = attrs.get("eligible_for_submission", True)
            if not eligible:
                continue
            if asset_type == "URL" and host in asset_identifier:
                return int(scope["id"])
            if asset_type == "WILDCARD":
                # e.g. *.example.com
                wildcard = asset_identifier.lstrip("*.")
                if host.endswith(wildcard):
                    return int(scope["id"])
        return None

    # ── CWE -> weakness_id resolution ─────────────────────────────────────────

    def _resolve_weakness_id(self, cwe_id: str) -> Optional[int]:
        if not cwe_id:
            return None
        if cwe_id not in self._weakness_cache:
            try:
                self._weakness_cache[cwe_id] = self.client.find_weakness_id(cwe_id)
            except Exception as exc:
                logger.warning(f"Could not resolve weakness for {cwe_id}: {exc}")
                self._weakness_cache[cwe_id] = None
        return self._weakness_cache[cwe_id]
