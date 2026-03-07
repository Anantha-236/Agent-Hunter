"""
Responsibility Engine — Hunter's ethical and operational decision framework.

Hunter is not just a scanner. It is a responsible security researcher.
This module defines what Hunter SHOULD and SHOULD NOT do at each phase of a scan,
based on:

  - What has been found (consequence analysis)
  - What scope permits (BBP policy)
  - What the scan state implies (confirmed criticals, legal risk)
  - What past experience teaches (HunterMind mistake + learning memory)

Hunter's responsibilities:
  1. Stay in scope — never probe what wasn't authorized
  2. Understand what you found — never report without knowing the impact
  3. Know when to stop — escalate critical findings, don't keep probing
  4. Learn from every scan — record what worked and what failed
  5. Never repeat the same mistake twice

This engine is the link between raw capability (scanners) and
accountable behavior (a trusted security agent).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.consequence_analyzer import ConsequenceReport
from core.models import Finding, ScanState, Target

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
#  DECISION RECORDS
# ══════════════════════════════════════════════════════════════

@dataclass
class ResponsibilityDecision:
    """A single responsibility decision made by Hunter during a scan."""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    trigger: str = ""           # what triggered this decision
    decision: str = ""          # what Hunter decided to do
    reasoning: str = ""         # why Hunter made this decision
    consequence_ref: Optional[str] = None   # related ConsequenceReport.finding_id
    severity: str = "info"      # info | warning | critical

    def to_thought(self) -> str:
        return (
            f"RESPONSIBILITY [{self.decision.upper()}] "
            f"Trigger: {self.trigger} | Reason: {self.reasoning}"
        )


@dataclass
class ScanResponsibilityReport:
    """Aggregate responsibility report for a full scan."""
    scan_id: str = ""
    decisions: List[ResponsibilityDecision] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)
    mistakes_recorded: List[str] = field(default_factory=list)
    stopped_early: bool = False
    stop_reason: str = ""
    ethical_score: float = 1.0   # 0.0 = violated many rules, 1.0 = fully responsible

    def summary(self) -> str:
        lines = [
            f"== RESPONSIBILITY REPORT (scan: {self.scan_id}) ==",
            f"Decisions made    : {len(self.decisions)}",
            f"Lessons learned   : {len(self.lessons_learned)}",
            f"Mistakes recorded : {len(self.mistakes_recorded)}",
            f"Stopped early     : {self.stopped_early}",
            f"Ethical score     : {self.ethical_score:.0%}",
        ]
        if self.stopped_early:
            lines.append(f"Stop reason: {self.stop_reason}")
        if self.lessons_learned:
            lines.append("Key lessons:")
            for l in self.lessons_learned[:3]:
                lines.append(f"  + {l}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  RESPONSIBILITY ENGINE
# ══════════════════════════════════════════════════════════════

class ResponsibilityEngine:
    """
    Hunter's ethical and operational decision-making engine.

    This is the "understand the actual responsibilities" part.
    It answers: "Given what Hunter found, what SHOULD it do next?"

    It also drives the self-learning loop:
    - Records lessons after each module
    - Records mistakes when findings are false positives
    - Closes the loop by feeding outcomes back into HunterMind
    """

    def __init__(self, hunter_mind=None):
        """
        Args:
            hunter_mind: Optional HunterMind instance for persistent learning.
                         If None, decisions are made but not persisted.
        """
        self.mind = hunter_mind
        self._report = ScanResponsibilityReport()
        self._disclose_triggered = False

    def start_scan(self, scan_id: str) -> None:
        """Initialize responsibility tracking for a scan."""
        self._report = ScanResponsibilityReport(scan_id=scan_id)
        self._disclose_triggered = False
        logger.debug(f"Responsibility engine started for scan {scan_id[:8]}")

    # ══════════════════════════════════════════════════════════
    #  PRE-SCAN RESPONSIBILITY CHECKS
    # ══════════════════════════════════════════════════════════

    def pre_scan_check(
        self,
        target_url: str,
        in_scope: List[str],
        instructions: str = "",
    ) -> List[str]:
        """
        Check responsibilities before starting a scan.

        Returns a list of responsibility notes (warnings, constraints, reminders).
        These are logged as Hunter's thoughts at scan start.
        """
        notes = []

        if not in_scope:
            notes.append(
                "WARNING: No in-scope assets defined. "
                "Hunter will scan the provided URL only. "
                "Responsibility: Do not enumerate outside the target domain."
            )
        else:
            notes.append(
                f"Scope defined: {len(in_scope)} in-scope asset(s). "
                "Hunter will respect these boundaries throughout the scan."
            )

        if instructions:
            notes.append(
                f"Operator instructions received ({len(instructions)} chars). "
                "Hunter will prioritize these constraints above default behavior."
            )

        notes.append(
            "Responsibility framework active: "
            "Hunter will (1) stay in scope, (2) understand what it finds, "
            "(3) escalate criticals immediately, (4) learn from results."
        )

        # Check HunterMind for past lessons on this target or similar
        if self.mind:
            try:
                learnings = self.mind.mistake_memory.get_relevant_learnings(
                    "cybersecurity", topic="scan"
                )
                if learnings:
                    notes.append(
                        f"Applying {len(learnings)} prior lesson(s) from past scans."
                    )
                    for l in learnings[:2]:
                        notes.append(f"  Past lesson: {l['insight'][:120]}")
            except Exception as exc:
                logger.debug(f"Could not query HunterMind learnings: {exc}")

        return notes

    # ══════════════════════════════════════════════════════════
    #  PER-FINDING DECISIONS
    # ══════════════════════════════════════════════════════════

    def on_finding(
        self,
        finding: Finding,
        consequence: ConsequenceReport,
        state: ScanState,
    ) -> ResponsibilityDecision:
        """
        Evaluate Hunter's responsibility when a new finding is produced.

        Returns a ResponsibilityDecision that the orchestrator can act on.
        """
        # Determine decision
        if consequence.responsibility_level == "disclose_immediately":
            decision = "DISCLOSE_IMMEDIATELY"
            reasoning = (
                f"Confirmed {finding.severity.upper()} finding '{finding.title}' "
                f"at {finding.url}. "
                f"This enables: {', '.join(consequence.chain_enables[:2])}. "
                "Immediate disclosure is required by responsible disclosure principles."
            )
            self._disclose_triggered = True
            sev = "critical"
        elif consequence.responsibility_level == "report_priority":
            decision = "PRIORITY_REPORT"
            reasoning = (
                f"Confirmed {finding.severity.upper()} finding '{finding.title}'. "
                f"Blast radius: {consequence.blast_radius}. Stop endpoint probing."
            )
            sev = "critical"
        elif consequence.responsibility_level == "report":
            decision = "DOCUMENT_AND_REPORT"
            reasoning = (
                f"Significant finding '{finding.title}' ({finding.severity}). "
                "Record full evidence and flag for the report."
            )
            sev = "warning"
        else:
            decision = "CONTINUE"
            reasoning = (
                f"Low-impact finding '{finding.title}'. "
                "Include in report and continue scanning."
            )
            sev = "info"

        record = ResponsibilityDecision(
            trigger=f"finding:{finding.vuln_type}",
            decision=decision,
            reasoning=reasoning,
            consequence_ref=finding.id,
            severity=sev,
        )
        self._report.decisions.append(record)
        return record

    def should_stop_scanning(self) -> Tuple[bool, str]:
        """
        Check if Hunter should stop all further scanning.

        Returns:
            (should_stop, reason)
        """
        if self._disclose_triggered:
            return True, (
                "Immediate-disclose vulnerability confirmed. "
                "Further scanning risks overstepping responsible behavior."
            )
        return False, ""

    def on_module_complete(
        self,
        module_name: str,
        findings: List[Finding],
        false_positives: int,
        target: Target,
        elapsed_seconds: float = 0.0,
    ) -> None:
        """
        Called after each scanner module completes.
        Records lessons and mistakes into HunterMind for future scans.
        """
        if not self.mind:
            return

        tech_stack = ", ".join(target.technologies[:3]) or "unknown"
        confirmed = [f for f in findings if f.confirmed]
        fps = false_positives

        # --- Record what WORKED ---
        if confirmed:
            vuln_types = list({f.vuln_type for f in confirmed})
            insight = (
                f"Module '{module_name}' found {len(confirmed)} confirmed "
                f"finding(s) of type [{', '.join(vuln_types)}] "
                f"on tech stack [{tech_stack}]. This module is effective here."
            )
            try:
                self.mind.record_learning(
                    domain="cybersecurity",
                    insight=insight,
                    topic=f"module_effectiveness:{module_name}",
                    source="scan_result",
                    confidence=min(0.95, 0.6 + 0.1 * len(confirmed)),
                )
                self._report.lessons_learned.append(insight)
                logger.debug(f"Learned: {insight[:80]}")
            except Exception as exc:
                logger.debug(f"Could not record learning: {exc}")

        # --- Record FALSE POSITIVES as mistakes ---
        if fps > 0:
            mistake = (
                f"Module '{module_name}' produced {fps} false positive(s) "
                f"on tech stack [{tech_stack}]."
            )
            correct = (
                f"When using '{module_name}' on [{tech_stack}], "
                "verify evidence with at least 2 independent indicators before reporting."
            )
            try:
                self.mind.record_mistake(
                    domain="cybersecurity",
                    mistake=mistake,
                    correct=correct,
                    topic=f"false_positive:{module_name}",
                    severity="medium",
                )
                self._report.mistakes_recorded.append(mistake)
                logger.debug(f"Recorded mistake: {mistake[:80]}")
            except Exception as exc:
                logger.debug(f"Could not record mistake: {exc}")

        # --- Record ZERO-RESULT modules on this tech stack ---
        if not findings and elapsed_seconds > 5:
            insight = (
                f"Module '{module_name}' found nothing on tech stack [{tech_stack}] "
                f"(ran for {elapsed_seconds:.0f}s). "
                "Consider deprioritizing this module for this tech combination."
            )
            try:
                self.mind.record_learning(
                    domain="cybersecurity",
                    insight=insight,
                    topic=f"module_null:{module_name}",
                    source="scan_result",
                    confidence=0.5,
                )
            except Exception as exc:
                logger.debug(f"Could not record null-result learning: {exc}")

    # ══════════════════════════════════════════════════════════
    #  POST-SCAN LEARNING LOOP
    # ══════════════════════════════════════════════════════════

    def close_learning_loop(
        self,
        state: ScanState,
        consequence_reports: List[ConsequenceReport],
    ) -> ScanResponsibilityReport:
        """
        Called at the end of a scan to close the self-learning loop.

        Extracts aggregate lessons from the scan and stores them in HunterMind:
          - What tech + module combinations were effective
          - What the overall consequence profile was
          - Any new vulnerability patterns encountered

        Returns the final ScanResponsibilityReport.
        """
        if self.mind:
            self._extract_aggregate_lessons(state, consequence_reports)

        self._report.stopped_early = self._disclose_triggered
        if self._disclose_triggered:
            self._report.stop_reason = "Immediate-disclose vulnerability confirmed"

        # Compute ethical score: reduce for each violation
        score = 1.0
        violations = [d for d in self._report.decisions if d.severity == "critical" and "DISCLOSE" not in d.decision]
        if violations:
            score -= 0.1 * len(violations)
        self._report.ethical_score = max(0.0, score)

        logger.info(
            f"Learning loop closed: {len(self._report.lessons_learned)} lessons, "
            f"{len(self._report.mistakes_recorded)} mistakes recorded"
        )
        return self._report

    def _extract_aggregate_lessons(
        self,
        state: ScanState,
        consequence_reports: List[ConsequenceReport],
    ) -> None:
        """Extract and persist aggregate lessons from a completed scan."""
        try:
            # Lesson: attack chains discovered
            all_chains = set()
            for r in consequence_reports:
                all_chains.update(r.chain_enables)
            if all_chains:
                insight = (
                    f"Scan of '{state.target.url}' revealed the following "
                    f"attack chains: {', '.join(list(all_chains)[:5])}. "
                    "These chains should be considered when scanning similar targets."
                )
                self.mind.record_learning(
                    domain="cybersecurity",
                    insight=insight,
                    topic="attack_chains",
                    source="consequence_analysis",
                    confidence=0.8,
                )
                self._report.lessons_learned.append(insight)

            # Lesson: effective tech → module combinations
            confirmed_findings = [f for f in state.findings if f.confirmed]
            if confirmed_findings and state.target.technologies:
                tech = state.target.technologies[0]
                effective_modules = list({f.module for f in confirmed_findings if f.module})
                if effective_modules:
                    insight = (
                        f"For '{tech}' tech stack, the most effective modules were: "
                        f"{', '.join(effective_modules[:5])}."
                    )
                    self.mind.record_learning(
                        domain="cybersecurity",
                        insight=insight,
                        topic=f"effective_modules:{tech}",
                        source="scan_result",
                        confidence=0.85,
                    )
                    self._report.lessons_learned.append(insight)

            # Lesson: false positive patterns
            fp_findings = [f for f in state.findings if f.false_positive]
            if fp_findings:
                fp_modules = list({f.module for f in fp_findings if f.module})
                if fp_modules:
                    mistake = (
                        f"Modules {fp_modules} produced false positives on "
                        f"'{state.target.url}'. Review their detection logic."
                    )
                    self.mind.record_mistake(
                        domain="cybersecurity",
                        mistake=mistake,
                        correct="Cross-verify findings with multiple evidence sources.",
                        topic="false_positive_module",
                        severity="low",
                    )
                    self._report.mistakes_recorded.append(mistake)

        except Exception as exc:
            logger.warning(f"Aggregate lesson extraction error: {exc}")

    def get_report(self) -> ScanResponsibilityReport:
        """Return the current responsibility report."""
        return self._report
