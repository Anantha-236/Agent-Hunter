"""Deterministic safety decisions made before RL action ranking."""
from __future__ import annotations

from dataclasses import dataclass, field

from core.models import DecisionOutcome, DecisionRecord, Target
from core.scanner_capabilities import (
    CapabilityError,
    CapabilityRegistry,
    ScannerCapability,
    TrafficClass,
)


_RISK_COST = {
    TrafficClass.PASSIVE: 0,
    TrafficClass.SAFE_ACTIVE: 1,
    TrafficClass.STATE_CHANGING: 5,
    TrafficClass.DISRUPTIVE: 10,
}


@dataclass
class DecisionContext:
    target: Target
    candidate_actions: list[str]
    policy_snapshot_hash: str
    policy_fresh: bool
    allowed_traffic_classes: set[TrafficClass]
    granted_permissions: set[str]
    remaining_request_budget: int
    remaining_risk_budget: int
    ambiguous_state: bool = False
    failure_counts: dict[str, int] = field(default_factory=dict)
    max_consecutive_failures: int = 3
    expected_evidence_value: dict[str, float] = field(default_factory=dict)


class DecisionEngine:
    def __init__(self, registry: CapabilityRegistry):
        self.registry = registry

    def _base_record(self, context: DecisionContext) -> DecisionRecord:
        return DecisionRecord(
            candidate_actions=list(context.candidate_actions),
            policy_snapshot_hash=context.policy_snapshot_hash,
        )

    def _global_denial(
        self,
        context: DecisionContext,
        outcome: DecisionOutcome,
        reason: str,
        rule: str,
    ) -> DecisionRecord:
        record = self._base_record(context)
        record.outcome = outcome
        record.reason = reason
        record.denied_actions = {
            action: rule for action in context.candidate_actions
        }
        record.recovery_plan = "Refresh authorization and obtain human review."
        return record

    def _action_denial(
        self,
        capability: ScannerCapability,
        context: DecisionContext,
    ) -> str | None:
        if capability.traffic_class not in context.allowed_traffic_classes:
            return "traffic_class_not_allowed"
        if not set(capability.required_permissions).issubset(
            context.granted_permissions
        ):
            return "required_permission_missing"
        if capability.request_cost > context.remaining_request_budget:
            return "request_budget_exceeded"
        if _RISK_COST[capability.traffic_class] > context.remaining_risk_budget:
            return "risk_budget_exceeded"
        if context.failure_counts.get(capability.module, 0) >= context.max_consecutive_failures:
            return "module_quarantined_after_failures"
        if context.expected_evidence_value.get(capability.module, 1.0) <= 0:
            return "no_expected_evidence_value"
        if context.ambiguous_state and not capability.idempotent:
            return "ambiguous_non_idempotent_state"
        return None

    def evaluate(self, context: DecisionContext) -> DecisionRecord:
        if not context.policy_fresh or not context.policy_snapshot_hash:
            return self._global_denial(
                context,
                DecisionOutcome.STOP,
                "Policy snapshot is missing or stale.",
                "policy_not_current",
            )
        if context.target.scope is None or not context.target.scope.is_in_scope(
            context.target.url
        ):
            return self._global_denial(
                context,
                DecisionOutcome.STOP,
                "Target is outside the explicitly approved scope.",
                "target_out_of_scope",
            )

        record = self._base_record(context)
        capabilities: dict[str, ScannerCapability] = {}
        for action in context.candidate_actions:
            try:
                capabilities[action] = self.registry.require(action)
            except CapabilityError:
                record.denied_actions[action] = "capability_metadata_missing"
                continue
            denial = self._action_denial(capabilities[action], context)
            if denial:
                record.denied_actions[action] = denial
            else:
                record.allowed_actions.append(action)

        ambiguous = any(
            reason == "ambiguous_non_idempotent_state"
            for reason in record.denied_actions.values()
        )
        if ambiguous:
            record.outcome = DecisionOutcome.ESCALATE
            record.reason = "An unfinished non-idempotent action has an ambiguous outcome."
            record.recovery_plan = "Inspect target state and obtain human approval before retrying."
            record.allowed_actions = []
            return record

        if not record.allowed_actions:
            record.outcome = DecisionOutcome.DEFER
            record.reason = "No candidate action passed deterministic safety gates."
            record.recovery_plan = "Resolve denied rules or record the coverage as not tested."
            return record

        record.outcome = DecisionOutcome.CONTINUE
        record.chosen_action = record.allowed_actions[0]
        chosen = capabilities[record.chosen_action]
        record.expected_evidence = list(
            chosen.positive_controls + chosen.negative_controls
        )
        record.risks = [
            f"traffic_class={chosen.traffic_class.value}",
            f"request_cost={chosen.request_cost}",
        ]
        record.recovery_plan = (
            "Stop the action, preserve evidence, and use the declared fallback."
            if chosen.fallback_module
            else "Stop the action and preserve the current checkpoint."
        )
        record.reason = "Action passed scope, policy, budget, and recovery gates."
        return record
