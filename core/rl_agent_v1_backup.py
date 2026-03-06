"""
Autonomous RL Policy Agent for scan-module selection.

Implements an online epsilon-greedy contextual bandit over scanner modules.
The policy learns Q-values per module from observed rewards and persists state
across runs so Hunter improves module ordering autonomously over time.
"""
from __future__ import annotations

import json
import logging
import os
import random
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ModulePolicyState:
    pulls: int = 0
    q_value: float = 0.0
    total_reward: float = 0.0
    successes: int = 0
    failures: int = 0


class RLPolicyAgent:
    """
    Lightweight autonomous RL policy for scanner selection.

    Learning rule:
      Q(a) <- Q(a) + alpha * (r - Q(a))

    Action selection:
      epsilon-greedy over available modules.

    Context:
      Keeps a small per-technology bias table to adapt module ordering for
      different tech stacks.
    """

    def __init__(
        self,
        modules: List[str],
        state_file: str = "rl_policy_state.json",
        alpha: float = 0.2,
        epsilon: float = 0.2,
        min_epsilon: float = 0.05,
        epsilon_decay: float = 0.995,
    ):
        self.state_file = state_file
        self.alpha = alpha
        self.epsilon = epsilon
        self.min_epsilon = min_epsilon
        self.epsilon_decay = epsilon_decay

        self.module_states: Dict[str, ModulePolicyState] = {
            name: ModulePolicyState() for name in modules
        }
        self.tech_bias: Dict[str, Dict[str, float]] = {}

        self._load()
        self._ensure_modules(modules)

    def _ensure_modules(self, modules: List[str]) -> None:
        """Make sure newly added scanner modules are tracked."""
        for name in modules:
            if name not in self.module_states:
                self.module_states[name] = ModulePolicyState()

    def rank_modules(
        self,
        modules: List[str],
        technologies: Optional[List[str]] = None,
        preferred_order: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Rank modules by current RL policy score.

        `preferred_order` can be passed from AI strategy; RL still re-ranks
        but keeps a small tie-break preference to preserve AI intent.
        """
        technologies = technologies or []
        preferred_index = {name: i for i, name in enumerate(preferred_order or [])}

        scored = []
        for name in modules:
            base_q = self.module_states.get(name, ModulePolicyState()).q_value
            tech_boost = self._context_bias(name, technologies)
            ai_tie_break = -0.01 * preferred_index.get(name, 999)
            score = base_q + tech_boost + ai_tie_break
            scored.append((name, score))

        ranked = [name for name, _ in sorted(scored, key=lambda x: x[1], reverse=True)]
        return ranked

    def choose_action(
        self,
        available_modules: List[str],
        technologies: Optional[List[str]] = None,
    ) -> str:
        """Choose the next module autonomously via epsilon-greedy selection."""
        if not available_modules:
            raise ValueError("No modules available for RL action selection")

        technologies = technologies or []
        explore = random.random() < self.epsilon

        if explore:
            choice = random.choice(available_modules)
            logger.debug(f"RL explore (epsilon={self.epsilon:.3f}) -> {choice}")
            return choice

        ranked = self.rank_modules(available_modules, technologies=technologies)
        choice = ranked[0]
        logger.debug(f"RL exploit (epsilon={self.epsilon:.3f}) -> {choice}")
        return choice

    def observe(
        self,
        module: str,
        reward: float,
        technologies: Optional[List[str]] = None,
    ) -> None:
        """Update policy from one observed (action, reward) outcome."""
        technologies = technologies or []
        state = self.module_states.setdefault(module, ModulePolicyState())

        # Q-learning style incremental update
        state.pulls += 1
        state.total_reward += reward
        state.q_value = state.q_value + self.alpha * (reward - state.q_value)

        if reward > 0:
            state.successes += 1
        elif reward < 0:
            state.failures += 1

        # Contextual bias update (tech stack -> module value)
        for tech in technologies[:8]:
            bucket = self.tech_bias.setdefault(tech, {})
            prev = bucket.get(module, 0.0)
            bucket[module] = prev + self.alpha * (reward - prev)

        # Anneal exploration
        self.epsilon = max(self.min_epsilon, self.epsilon * self.epsilon_decay)

        self.save()

    def _context_bias(self, module: str, technologies: List[str]) -> float:
        if not technologies:
            return 0.0
        vals = []
        for tech in technologies[:8]:
            vals.append(self.tech_bias.get(tech, {}).get(module, 0.0))
        if not vals:
            return 0.0
        return sum(vals) / len(vals)

    def save(self) -> None:
        """Persist policy state to disk."""
        data = {
            "alpha": self.alpha,
            "epsilon": self.epsilon,
            "min_epsilon": self.min_epsilon,
            "epsilon_decay": self.epsilon_decay,
            "module_states": {
                k: asdict(v) for k, v in self.module_states.items()
            },
            "tech_bias": self.tech_bias,
        }
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.debug(f"Failed to save RL policy state: {exc}")

    def _load(self) -> None:
        """Load policy state from disk if present."""
        if not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.alpha = float(data.get("alpha", self.alpha))
            self.epsilon = float(data.get("epsilon", self.epsilon))
            self.min_epsilon = float(data.get("min_epsilon", self.min_epsilon))
            self.epsilon_decay = float(data.get("epsilon_decay", self.epsilon_decay))

            loaded_states = data.get("module_states", {})
            for name, raw in loaded_states.items():
                self.module_states[name] = ModulePolicyState(
                    pulls=int(raw.get("pulls", 0)),
                    q_value=float(raw.get("q_value", 0.0)),
                    total_reward=float(raw.get("total_reward", 0.0)),
                    successes=int(raw.get("successes", 0)),
                    failures=int(raw.get("failures", 0)),
                )

            self.tech_bias = data.get("tech_bias", {}) or {}
        except Exception as exc:
            logger.debug(f"Failed to load RL policy state: {exc}")

    def summary(self, top_n: int = 5) -> str:
        """Human-readable policy summary for logs/TUI."""
        ranked = sorted(
            self.module_states.items(),
            key=lambda x: x[1].q_value,
            reverse=True,
        )
        top = ranked[:top_n]
        parts = [
            f"epsilon={self.epsilon:.3f}",
            "top=" + ", ".join(
                f"{name}:{st.q_value:+.2f}" for name, st in top
            ),
        ]
        return " | ".join(parts)
