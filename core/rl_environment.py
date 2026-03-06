"""
RL Environment — State Perception, Action Space, and Observation Encoding.

Provides the formal RL environment interface that the agent interacts with:
  - EnvironmentState: rich representation of the current scan context
  - ActionSpace: the set of possible actions (scanner modules)
  - StateEncoder: converts raw observations into fixed-length feature vectors
    for function approximation / generalization

Design notes:
  - Pure Python (no numpy/torch dependency) for portability
  - Feature vectors are plain lists of floats
  - State captures both fully-observable and partially-observable elements
  - Supports incremental observation updates during a scan episode
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple


# ══════════════════════════════════════════════════════════════
#  STATE PERCEPTION
# ══════════════════════════════════════════════════════════════

# Canonical technology categories for state encoding
TECH_CATEGORIES = [
    "php", "python", "java", "node", "ruby", "dotnet", "go", "rust",
    "wordpress", "drupal", "joomla", "django", "flask", "rails",
    "spring", "express", "laravel", "react", "angular", "vue",
    "nginx", "apache", "iis", "cloudflare", "aws", "azure", "gcp",
    "mysql", "postgres", "mongodb", "redis", "graphql", "rest",
    "docker", "kubernetes",
]

# Severity numeric encoding
SEVERITY_SCORES = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}


@dataclass
class EnvironmentState:
    """
    Rich representation of the current scan environment at a point in time.

    This captures everything the agent can perceive about its world:
    partially observable (we don't know all vulns, all endpoints, etc.)
    but comprehensive enough for learning.
    """

    # ── Target context ────────────────────────────────────────
    target_url: str = ""
    technologies: List[str] = field(default_factory=list)
    waf_detected: bool = False
    waf_name: str = ""
    discovered_urls_count: int = 0
    discovered_params_count: int = 0
    ssl_present: bool = False

    # ── Scan progress ─────────────────────────────────────────
    modules_run: List[str] = field(default_factory=list)
    modules_remaining: List[str] = field(default_factory=list)
    total_modules: int = 0
    scan_progress: float = 0.0  # 0.0 to 1.0

    # ── Findings so far ───────────────────────────────────────
    findings_count: int = 0
    confirmed_count: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    unique_vuln_types: Set[str] = field(default_factory=set)
    duplicate_count: int = 0

    # ── Confidence metadata (for enhanced reward function) ────
    avg_confidence: float = 0.0            # mean confidence across findings
    confident_correct_count: int = 0       # confirmed & confidence >= threshold
    confident_wrong_count: int = 0         # false_positive & confidence >= threshold
    uncertain_correct_count: int = 0       # confirmed & confidence < threshold
    uncertain_wrong_count: int = 0         # false_positive & confidence < threshold
    abstain_count: int = 0                 # module reported "I don't know"
    asked_to_learn_count: int = 0          # module asked for AI help
    taught_topic_correct_count: int = 0    # correct on previously-taught topic

    # ── Reward history ────────────────────────────────────────
    cumulative_reward: float = 0.0
    last_reward: float = 0.0
    reward_trend: float = 0.0  # moving average direction
    rewards_history: List[float] = field(default_factory=list)

    # ── Time context (partially observable) ───────────────────
    elapsed_seconds: float = 0.0
    avg_module_time: float = 0.0

    # ── Module performance history (partial observability) ────
    module_last_reward: Dict[str, float] = field(default_factory=dict)
    module_last_finding_count: Dict[str, int] = field(default_factory=dict)

    # ── Episode metadata ──────────────────────────────────────
    episode_id: str = ""
    step: int = 0
    timestamp: float = field(default_factory=time.time)

    def update_progress(self) -> None:
        """Recalculate derived fields."""
        run_count = len(self.modules_run)
        self.total_modules = run_count + len(self.modules_remaining)
        self.scan_progress = run_count / max(self.total_modules, 1)

        if len(self.rewards_history) >= 3:
            recent = self.rewards_history[-3:]
            older = self.rewards_history[-6:-3] if len(self.rewards_history) >= 6 else self.rewards_history[:3]
            self.reward_trend = (sum(recent) / len(recent)) - (sum(older) / len(older))

    def snapshot(self) -> Dict[str, Any]:
        """Serializable snapshot for experience replay storage."""
        return {
            "step": self.step,
            "target_url": self.target_url,
            "tech_count": len(self.technologies),
            "waf": self.waf_detected,
            "urls": self.discovered_urls_count,
            "params": self.discovered_params_count,
            "progress": self.scan_progress,
            "findings": self.findings_count,
            "confirmed": self.confirmed_count,
            "cum_reward": self.cumulative_reward,
            "last_reward": self.last_reward,
            "trend": self.reward_trend,
            "elapsed": self.elapsed_seconds,
            "modules_run": list(self.modules_run),
            "episode_id": self.episode_id,
            "timestamp": self.timestamp,
        }


# ══════════════════════════════════════════════════════════════
#  ACTION SPACE
# ══════════════════════════════════════════════════════════════

@dataclass
class Action:
    """An action the agent can take."""
    module_name: str
    index: int = 0  # position in action space
    metadata: Dict[str, Any] = field(default_factory=dict)


class ActionSpace:
    """
    Formal action space for module selection.

    Maintains a mapping between module names and integer indices,
    which is required for Q-table and function approximation lookups.
    """

    def __init__(self, module_names: List[str]):
        self._modules = list(module_names)
        self._name_to_idx = {name: i for i, name in enumerate(self._modules)}

    @property
    def n(self) -> int:
        """Number of possible actions."""
        return len(self._modules)

    @property
    def modules(self) -> List[str]:
        return list(self._modules)

    def action(self, name: str) -> Action:
        """Create an Action from a module name."""
        return Action(module_name=name, index=self._name_to_idx.get(name, -1))

    def index_of(self, name: str) -> int:
        return self._name_to_idx.get(name, -1)

    def name_of(self, index: int) -> str:
        if 0 <= index < len(self._modules):
            return self._modules[index]
        raise IndexError(f"Action index {index} out of range [0, {self.n})")

    def mask(self, available: List[str]) -> List[bool]:
        """Boolean mask: True for available actions."""
        avail_set = set(available)
        return [name in avail_set for name in self._modules]

    def available_indices(self, available: List[str]) -> List[int]:
        avail_set = set(available)
        return [i for i, name in enumerate(self._modules) if name in avail_set]

    def add_module(self, name: str) -> None:
        if name not in self._name_to_idx:
            self._name_to_idx[name] = len(self._modules)
            self._modules.append(name)


# ══════════════════════════════════════════════════════════════
#  STATE ENCODER — Feature Vector for Generalization
# ══════════════════════════════════════════════════════════════

class StateEncoder:
    """
    Encodes an EnvironmentState into a fixed-length float vector
    suitable for linear function approximation or neural network input.

    Feature groups:
      1. Technology one-hot (len = len(TECH_CATEGORIES))
      2. Target features (urls, params, waf, ssl)
      3. Progress features (scan %, modules run ratio)
      4. Finding features (count, confirmed ratio, severity distribution)
      5. Reward features (cumulative, last, trend, running stats)
      6. Time features (elapsed normalized, avg module time)
      7. Per-action context (last reward for candidate action)

    Total features ≈ len(TECH_CATEGORIES) + 20 + n_actions
    """

    def __init__(self, action_space: ActionSpace):
        self.action_space = action_space
        self._tech_to_idx = {t: i for i, t in enumerate(TECH_CATEGORIES)}
        # Feature dimension = tech_encoding + global_features + per_action_features
        self._n_tech = len(TECH_CATEGORIES)
        self._n_global = 20  # fixed global features
        self._n_actions = action_space.n
        self.dim = self._n_tech + self._n_global + self._n_actions

    def encode(self, state: EnvironmentState) -> List[float]:
        """Encode full state into a feature vector."""
        features: List[float] = []

        # ── 1. Technology one-hot encoding ────────────────────
        tech_vec = [0.0] * self._n_tech
        for tech in state.technologies:
            t_lower = tech.lower()
            for cat, idx in self._tech_to_idx.items():
                if cat in t_lower:
                    tech_vec[idx] = 1.0
        features.extend(tech_vec)

        # ── 2. Target features (5) ───────────────────────────
        features.append(_log_scale(state.discovered_urls_count))
        features.append(_log_scale(state.discovered_params_count))
        features.append(1.0 if state.waf_detected else 0.0)
        features.append(1.0 if state.ssl_present else 0.0)
        features.append(min(len(state.technologies) / 10.0, 1.0))

        # ── 3. Progress features (4) ─────────────────────────
        features.append(state.scan_progress)
        features.append(len(state.modules_run) / max(state.total_modules, 1))
        features.append(min(len(state.modules_remaining) / max(state.total_modules, 1), 1.0))
        features.append(min(state.step / 50.0, 1.0))

        # ── 4. Finding features (5) ──────────────────────────
        features.append(_log_scale(state.findings_count))
        features.append(state.confirmed_count / max(state.findings_count, 1))
        features.append(state.severity_counts.get("critical", 0) / max(state.findings_count, 1))
        features.append(state.severity_counts.get("high", 0) / max(state.findings_count, 1))
        features.append(min(len(state.unique_vuln_types) / 10.0, 1.0))

        # ── 5. Reward features (4) ───────────────────────────
        features.append(_tanh(state.cumulative_reward / 10.0))
        features.append(_tanh(state.last_reward))
        features.append(_tanh(state.reward_trend))
        reward_var = _variance(state.rewards_history[-20:]) if state.rewards_history else 0.0
        features.append(min(reward_var, 1.0))

        # ── 6. Time features (2) ─────────────────────────────
        features.append(min(state.elapsed_seconds / 3600.0, 1.0))  # normalize to 1 hour
        features.append(min(state.avg_module_time / 300.0, 1.0))    # normalize to 5 min

        # ── 7. Per-action last reward (n_actions) ────────────
        for mod in self.action_space.modules:
            features.append(_tanh(state.module_last_reward.get(mod, 0.0)))

        return features

    def encode_state_action(self, state: EnvironmentState, action_idx: int) -> List[float]:
        """
        Encode (state, action) pair for Q(s,a) approximation.
        Appends a one-hot action indicator to the state features.
        """
        base = self.encode(state)
        action_onehot = [0.0] * self.action_space.n
        if 0 <= action_idx < self.action_space.n:
            action_onehot[action_idx] = 1.0
        return base + action_onehot

    @property
    def state_action_dim(self) -> int:
        return self.dim + self.action_space.n


# ══════════════════════════════════════════════════════════════
#  EXPERIENCE TUPLE
# ══════════════════════════════════════════════════════════════

@dataclass
class Experience:
    """Single (s, a, r, s', done) transition for replay."""
    state_features: List[float]
    action_idx: int
    reward: float
    next_state_features: List[float]
    done: bool
    info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "s": self.state_features,
            "a": self.action_idx,
            "r": self.reward,
            "s_next": self.next_state_features,
            "done": self.done,
            "info": self.info,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Experience":
        return cls(
            state_features=data["s"],
            action_idx=data["a"],
            reward=data["r"],
            next_state_features=data["s_next"],
            done=data["done"],
            info=data.get("info", {}),
        )


# ══════════════════════════════════════════════════════════════
#  UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def _log_scale(x: float, base: float = 100.0) -> float:
    """Log-scale normalization: maps [0, inf) to ~[0, 1]."""
    return math.log1p(x) / math.log1p(base)


def _tanh(x: float) -> float:
    """Squash to [-1, 1]."""
    return math.tanh(x)


def _variance(values: List[float]) -> float:
    """Variance of a list of floats."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def _dot(a: List[float], b: List[float]) -> float:
    """Dot product of two float vectors."""
    return sum(x * y for x, y in zip(a, b))


def _vec_add(a: List[float], b: List[float]) -> List[float]:
    """Element-wise addition."""
    return [x + y for x, y in zip(a, b)]


def _vec_scale(a: List[float], scalar: float) -> List[float]:
    """Scalar multiplication."""
    return [x * scalar for x in a]


def _vec_sub(a: List[float], b: List[float]) -> List[float]:
    """Element-wise subtraction."""
    return [x - y for x, y in zip(a, b)]


def _vec_norm(a: List[float]) -> float:
    """L2 norm."""
    return math.sqrt(sum(x * x for x in a))
