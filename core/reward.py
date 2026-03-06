"""
RL Reward Engine — scores agent actions to guide autonomous decision-making.
Integrates with the orchestrator, AI brain, and memory system.
"""
from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Default reward scheme ─────────────────────────────────────
DEFAULT_REWARDS: Dict[str, float] = {
    "successful_exploit":             1.0,
    "correct_service_identification": 0.5,
    "correct_vulnerability_mapping":  0.5,
    "valid_payload_construction":     0.5,
    "privilege_escalation_success":   1.0,
    "incorrect_exploit_attempt":     -1.0,
    "crashed_service":               -0.5,
    "redundant_scan":                -0.2,
    "no_progress_action":             0.0,
    "root_shell_obtained":            2.0,
}


@dataclass
class ActionRecord:
    """Single recorded agent action with its reward."""
    action_type: str
    reward: float
    module: str = ""
    target_url: str = ""
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class RewardEngine:
    """
    Tracks agent actions, assigns rewards, and provides scoring context
    to the AI brain for strategy decisions.
    """

    def __init__(self, reward_scheme: Optional[Dict[str, float]] = None):
        self.rewards = {**DEFAULT_REWARDS, **(reward_scheme or {})}
        self.history: List[ActionRecord] = []
        self._episode_start = time.monotonic()

    # ── Core API ──────────────────────────────────────────────

    def record(self, action_type: str, module: str = "",
               target_url: str = "", detail: str = "") -> float:
        """Record an action and return its reward value."""
        reward = self.rewards.get(action_type, 0.0)
        record = ActionRecord(
            action_type=action_type,
            reward=reward,
            module=module,
            target_url=target_url,
            detail=detail,
        )
        self.history.append(record)
        logger.debug(f"Reward: {action_type} → {reward:+.1f}  (total: {self.total_score:.1f})")
        return reward

    # ── Convenience scorers ───────────────────────────────────

    def score_scanner_results(self, module_name: str, findings: list,
                              previously_known: set = None) -> float:
        """Score a scanner module's results after execution."""
        previously_known = previously_known or set()
        episode_reward = 0.0

        if not findings:
            episode_reward += self.record("no_progress_action", module=module_name)
            return episode_reward

        for f in findings:
            key = (f.url, f.parameter, f.vuln_type)

            if key in previously_known:
                episode_reward += self.record("redundant_scan", module=module_name,
                                             target_url=f.url, detail=f.title)
                continue

            if f.confirmed:
                episode_reward += self.record("successful_exploit", module=module_name,
                                             target_url=f.url, detail=f.title)
            else:
                episode_reward += self.record("valid_payload_construction", module=module_name,
                                             target_url=f.url, detail=f.title)

        return episode_reward

    def score_recon(self, technologies: list, urls_found: int) -> float:
        """Score reconnaissance results."""
        reward = 0.0
        if technologies:
            reward += self.record("correct_service_identification",
                                 detail=f"Identified {len(technologies)} technologies")
        if urls_found > 0:
            reward += self.record("correct_vulnerability_mapping",
                                 detail=f"Discovered {urls_found} URLs")
        return reward

    # ── Properties ────────────────────────────────────────────

    @property
    def total_score(self) -> float:
        return sum(r.reward for r in self.history)

    @property
    def action_count(self) -> int:
        return len(self.history)

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._episode_start

    # ── AI Context Export ─────────────────────────────────────

    def to_ai_context(self, last_n: int = 20) -> str:
        """
        Format reward history as context for the AI brain.
        Helps Claude make better strategy decisions.
        """
        recent = self.history[-last_n:]
        lines = [
            f"Current Score: {self.total_score:+.1f} ({self.action_count} actions)",
            f"Elapsed: {self.elapsed_seconds:.0f}s",
            "",
            "Recent actions:",
        ]
        for r in recent:
            lines.append(f"  [{r.reward:+.1f}] {r.action_type}"
                         f"{f' ({r.module})' if r.module else ''}"
                         f"{f' — {r.detail}' if r.detail else ''}")

        # Summary stats
        action_counts: Dict[str, int] = {}
        action_totals: Dict[str, float] = {}
        for r in self.history:
            action_counts[r.action_type] = action_counts.get(r.action_type, 0) + 1
            action_totals[r.action_type] = action_totals.get(r.action_type, 0.0) + r.reward

        lines += ["", "Action breakdown:"]
        for act in sorted(action_counts, key=lambda a: action_totals.get(a, 0), reverse=True):
            lines.append(f"  {act}: {action_counts[act]}x = {action_totals[act]:+.1f}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for persistence / JSON export."""
        return {
            "total_score": self.total_score,
            "action_count": self.action_count,
            "reward_scheme": self.rewards,
            "history": [
                {
                    "action": r.action_type,
                    "reward": r.reward,
                    "module": r.module,
                    "url": r.target_url,
                    "detail": r.detail,
                    "ts": r.timestamp,
                }
                for r in self.history
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RewardEngine":
        """Restore from serialized state."""
        engine = cls(reward_scheme=data.get("reward_scheme"))
        for item in data.get("history", []):
            engine.history.append(ActionRecord(
                action_type=item["action"],
                reward=item["reward"],
                module=item.get("module", ""),
                target_url=item.get("url", ""),
                detail=item.get("detail", ""),
                timestamp=item.get("ts", ""),
            ))
        return engine
