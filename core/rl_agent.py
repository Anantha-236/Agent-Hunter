"""
Autonomous RL Agent for Hunter -- Full Reinforcement Learning Framework.

Implements all 9 core RL features:
  1. State Perception       -- EnvironmentState + StateEncoder (rl_environment.py)
  2. Action Execution       -- ActionSpace for module selection
  3. Policy                 -- Softmax, UCB1, Thompson Sampling, epsilon-greedy
  4. Reward Interpretation  -- Multi-signal reward shaping with intrinsic curiosity
  5. Learning Mechanism     -- TD(lambda) with eligibility traces + experience replay
  6. Explore-Exploit        -- UCB1, Thompson Sampling, Boltzmann, epsilon-greedy
  7. Value Function         -- Q(s,a) with linear function approximation
  8. Generalization         -- Linear FA over state features; unseen-state handling
  9. Memory                 -- Experience replay buffer + episodic recurrent state

Architecture:
  - Pure Python (no numpy/torch) for zero-dependency portability
  - Feature vectors are plain float lists with manual linear algebra
  - Persistent state saved to JSON across scan sessions
  - Backward-compatible API: rank_modules(), choose_action(), observe()
"""
from __future__ import annotations

import json
import logging
import math
import os
import random
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Any, Deque, Dict, List, Optional, Tuple

from core.rl_environment import (
    ActionSpace,
    EnvironmentState,
    Experience,
    StateEncoder,
    _dot, _vec_add, _vec_scale, _vec_sub, _vec_norm,
    _tanh,
)

logger = logging.getLogger(__name__)


# =====================================================================
#  DATA STRUCTURES
# =====================================================================

@dataclass
class ModulePolicyState:
    """Per-module statistics (kept for backward compat + Thompson Sampling)."""
    pulls: int = 0
    q_value: float = 0.0
    total_reward: float = 0.0
    successes: int = 0
    failures: int = 0
    # Thompson Sampling Beta distribution parameters
    alpha_ts: float = 1.0   # prior successes + 1
    beta_ts: float = 1.0    # prior failures + 1
    # UCB statistics
    sum_sq_reward: float = 0.0


@dataclass
class EpisodeMemory:
    """
    Recurrent internal state for partially observable environments.
    Retains information across time steps within one scan episode.
    """
    episode_id: str = ""
    steps: int = 0
    transitions: List[Dict[str, Any]] = field(default_factory=list)
    running_reward_mean: float = 0.0
    running_reward_var: float = 0.0
    _m2: float = 0.0  # for Welford's online variance
    module_sequence: List[str] = field(default_factory=list)
    context_summary: Dict[str, float] = field(default_factory=dict)

    def update_running_stats(self, reward: float) -> None:
        """Welford's online algorithm for running mean and variance."""
        self.steps += 1
        delta = reward - self.running_reward_mean
        self.running_reward_mean += delta / self.steps
        delta2 = reward - self.running_reward_mean
        self._m2 += delta * delta2
        self.running_reward_var = self._m2 / max(self.steps, 1)

    def add_transition(self, module: str, reward: float, info: Dict = None) -> None:
        self.module_sequence.append(module)
        self.transitions.append({
            "step": self.steps,
            "module": module,
            "reward": reward,
            "info": info or {},
        })
        self.update_running_stats(reward)

    def get_recurrent_features(self) -> List[float]:
        """
        Extract a summary vector from episode memory for partial observability.
        This acts as a learned hidden-state substitute.
        """
        return [
            self.running_reward_mean,
            math.sqrt(max(self.running_reward_var, 0.0)),
            min(self.steps / 50.0, 1.0),
            len(set(self.module_sequence)) / max(len(self.module_sequence), 1),
            self._recent_momentum(),
        ]

    def _recent_momentum(self) -> float:
        rewards = [t["reward"] for t in self.transitions]
        if len(rewards) < 2:
            return 0.0
        recent = rewards[-3:] if len(rewards) >= 3 else rewards
        older = rewards[-6:-3] if len(rewards) >= 6 else rewards[:max(len(rewards) // 2, 1)]
        return _tanh((sum(recent) / len(recent)) - (sum(older) / len(older)))


# =====================================================================
#  EXPERIENCE REPLAY BUFFER
# =====================================================================

class ReplayBuffer:
    """
    Fixed-size experience replay buffer with prioritized sampling.
    Uses TD-error magnitude as priority for importance weighting.
    """

    def __init__(self, capacity: int = 5000):
        self.capacity = capacity
        self.buffer: Deque[Experience] = deque(maxlen=capacity)
        self.priorities: Deque[float] = deque(maxlen=capacity)

    def push(self, exp: Experience, priority: float = 1.0) -> None:
        self.buffer.append(exp)
        self.priorities.append(abs(priority) + 1e-6)

    def sample(self, batch_size: int) -> List[Experience]:
        """Sample a mini-batch, weighted by priority."""
        n = min(batch_size, len(self.buffer))
        if n == 0:
            return []

        total_p = sum(self.priorities)
        probs = [p / total_p for p in self.priorities]

        indices = []
        remaining_probs = list(probs)
        remaining_indices = list(range(len(self.buffer)))

        for _ in range(n):
            r = random.random() * sum(remaining_probs)
            cumulative = 0.0
            for j, (idx, p) in enumerate(zip(remaining_indices, remaining_probs)):
                cumulative += p
                if cumulative >= r:
                    indices.append(idx)
                    remaining_indices.pop(j)
                    remaining_probs.pop(j)
                    break

        return [self.buffer[i] for i in indices]

    def __len__(self) -> int:
        return len(self.buffer)

    def to_list(self) -> List[Dict]:
        return [exp.to_dict() for exp in self.buffer]

    def from_list(self, data: List[Dict]) -> None:
        self.buffer.clear()
        self.priorities.clear()
        for item in data[-self.capacity:]:
            exp = Experience.from_dict(item)
            self.buffer.append(exp)
            self.priorities.append(1.0)


# =====================================================================
#  LINEAR FUNCTION APPROXIMATOR -- Q(s,a) Generalization
# =====================================================================

class LinearQApproximator:
    """
    Linear function approximator for Q(s, a).

    Q(s, a) = w_a . phi(s) + bias_a

    where phi(s) is the state feature vector and w_a are per-action weights.
    Supports TD(lambda) updates with eligibility traces.

    This is Feature 7 (Value Function) + Feature 8 (Generalization):
    the linear model generalizes Q-values to unseen states via the
    learned weight vector over state features.
    """

    def __init__(self, state_dim: int, n_actions: int,
                 learning_rate: float = 0.01,
                 lambda_trace: float = 0.8,
                 gamma: float = 0.95):
        self.state_dim = state_dim
        self.n_actions = n_actions
        self.lr = learning_rate
        self.gamma = gamma
        self.lambda_trace = lambda_trace

        # Weight matrix: n_actions x state_dim
        self.weights: List[List[float]] = [
            [0.0] * state_dim for _ in range(n_actions)
        ]
        self.biases: List[float] = [0.0] * n_actions

        # Eligibility traces (same shape as weights)
        self.traces: List[List[float]] = [
            [0.0] * state_dim for _ in range(n_actions)
        ]
        self.bias_traces: List[float] = [0.0] * n_actions

    def predict(self, state_features: List[float], action_idx: int) -> float:
        """Compute Q(s, a) = w_a . phi(s) + b_a."""
        if action_idx < 0 or action_idx >= self.n_actions:
            return 0.0
        return _dot(self.weights[action_idx], state_features) + self.biases[action_idx]

    def predict_all(self, state_features: List[float]) -> List[float]:
        """Compute Q(s, a) for all actions."""
        return [self.predict(state_features, a) for a in range(self.n_actions)]

    def update_td(self, state_features: List[float], action_idx: int,
                  td_error: float) -> None:
        """
        TD(lambda) update with eligibility traces.

        For the chosen action a:
          e_a <- gamma*lambda * e_a + phi(s)     (accumulating trace)
          w_a <- w_a + alpha * delta * e_a

        For all other actions:
          e_i <- gamma*lambda * e_i               (decay only)
        """
        for i in range(self.n_actions):
            decay = self.gamma * self.lambda_trace
            if i == action_idx:
                self.traces[i] = _vec_add(
                    _vec_scale(self.traces[i], decay),
                    state_features,
                )
                self.bias_traces[i] = decay * self.bias_traces[i] + 1.0
            else:
                self.traces[i] = _vec_scale(self.traces[i], decay)
                self.bias_traces[i] *= decay

            # Weight update: w += lr * td_error * trace
            update = _vec_scale(self.traces[i], self.lr * td_error)
            self.weights[i] = _vec_add(self.weights[i], update)
            self.biases[i] += self.lr * td_error * self.bias_traces[i]

    def update_simple(self, state_features: List[float], action_idx: int,
                      td_error: float) -> None:
        """Simple one-step TD update without eligibility traces (for replay)."""
        gradient = _vec_scale(state_features, self.lr * td_error)
        self.weights[action_idx] = _vec_add(self.weights[action_idx], gradient)
        self.biases[action_idx] += self.lr * td_error

    def reset_traces(self) -> None:
        """Reset eligibility traces (call at episode start)."""
        self.traces = [[0.0] * self.state_dim for _ in range(self.n_actions)]
        self.bias_traces = [0.0] * self.n_actions

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_dim": self.state_dim,
            "n_actions": self.n_actions,
            "lr": self.lr,
            "gamma": self.gamma,
            "lambda_trace": self.lambda_trace,
            "weights": self.weights,
            "biases": self.biases,
        }

    def from_dict(self, data: Dict[str, Any]) -> None:
        self.lr = data.get("lr", self.lr)
        self.gamma = data.get("gamma", self.gamma)
        self.lambda_trace = data.get("lambda_trace", self.lambda_trace)

        loaded_weights = data.get("weights", [])
        loaded_biases = data.get("biases", [])

        # Handle dimension changes gracefully (new modules added, etc.)
        for a in range(self.n_actions):
            if a < len(loaded_weights):
                w = loaded_weights[a]
                if len(w) == self.state_dim:
                    self.weights[a] = list(w)
                elif len(w) < self.state_dim:
                    self.weights[a] = list(w) + [0.0] * (self.state_dim - len(w))
                else:
                    self.weights[a] = list(w[:self.state_dim])

            if a < len(loaded_biases):
                self.biases[a] = float(loaded_biases[a])


# =====================================================================
#  EXPLORATION STRATEGIES (Feature 6)
# =====================================================================

class ExplorationStrategy:
    """Base class for exploration strategies."""

    def select(self, q_values: List[float], available_mask: List[bool],
               module_states: Dict[str, ModulePolicyState],
               action_space: ActionSpace, step: int) -> int:
        raise NotImplementedError


class EpsilonGreedy(ExplorationStrategy):
    """Classic epsilon-greedy with annealing."""

    def __init__(self, epsilon: float = 0.2, min_epsilon: float = 0.05,
                 decay: float = 0.995):
        self.epsilon = epsilon
        self.min_epsilon = min_epsilon
        self.decay = decay

    def select(self, q_values, available_mask, module_states, action_space, step):
        available = [i for i, m in enumerate(available_mask) if m]
        if not available:
            raise ValueError("No available actions")

        if random.random() < self.epsilon:
            choice = random.choice(available)
        else:
            best_q = max(q_values[i] for i in available)
            best = [i for i in available if abs(q_values[i] - best_q) < 1e-9]
            choice = random.choice(best)

        self.epsilon = max(self.min_epsilon, self.epsilon * self.decay)
        return choice


class BoltzmannExploration(ExplorationStrategy):
    """Softmax / Boltzmann exploration with temperature annealing."""

    def __init__(self, temperature: float = 1.0, min_temp: float = 0.1,
                 decay: float = 0.998):
        self.temperature = temperature
        self.min_temp = min_temp
        self.decay = decay

    def select(self, q_values, available_mask, module_states, action_space, step):
        available = [i for i, m in enumerate(available_mask) if m]
        if not available:
            raise ValueError("No available actions")

        max_q = max(q_values[i] for i in available)
        exp_vals = []
        for i in available:
            exponent = (q_values[i] - max_q) / max(self.temperature, 1e-8)
            exp_vals.append(math.exp(min(exponent, 50.0)))

        total = sum(exp_vals)
        probs = [e / total for e in exp_vals]

        r = random.random()
        cumulative = 0.0
        choice = available[-1]
        for idx, p in zip(available, probs):
            cumulative += p
            if cumulative >= r:
                choice = idx
                break

        self.temperature = max(self.min_temp, self.temperature * self.decay)
        return choice


class UCB1Exploration(ExplorationStrategy):
    """Upper Confidence Bound (UCB1) for exploration."""

    def __init__(self, c: float = 2.0):
        self.c = c

    def select(self, q_values, available_mask, module_states, action_space, step):
        available = [i for i, m in enumerate(available_mask) if m]
        if not available:
            raise ValueError("No available actions")

        total_pulls = max(sum(s.pulls for s in module_states.values()), 1)

        ucb_values = []
        for i in available:
            name = action_space.name_of(i)
            state = module_states.get(name, ModulePolicyState())

            if state.pulls == 0:
                ucb_values.append((i, float('inf')))
            else:
                exploitation = q_values[i]
                exploration = self.c * math.sqrt(math.log(total_pulls) / state.pulls)
                ucb_values.append((i, exploitation + exploration))

        best_ucb = max(v for _, v in ucb_values)
        best = [i for i, v in ucb_values if abs(v - best_ucb) < 1e-9 or v == float('inf')]
        return random.choice(best)


class ThompsonSampling(ExplorationStrategy):
    """Thompson Sampling using Beta distributions for binary success/fail."""

    def select(self, q_values, available_mask, module_states, action_space, step):
        available = [i for i, m in enumerate(available_mask) if m]
        if not available:
            raise ValueError("No available actions")

        sampled = []
        for i in available:
            name = action_space.name_of(i)
            state = module_states.get(name, ModulePolicyState())
            sample = random.betavariate(state.alpha_ts, state.beta_ts)
            blended = 0.6 * sample + 0.4 * _tanh(q_values[i])
            sampled.append((i, blended))

        best_val = max(v for _, v in sampled)
        best = [i for i, v in sampled if abs(v - best_val) < 1e-9]
        return random.choice(best)


class HybridExploration(ExplorationStrategy):
    """
    Adaptive hybrid: selects between strategies based on agent maturity.
    Early:  UCB1 (systematic exploration of all modules)
    Mid:    Boltzmann (soft exploitation with temperature)
    Late:   Thompson Sampling (calibrated posterior uncertainty)
    """

    def __init__(self):
        self.ucb = UCB1Exploration(c=2.0)
        self.boltzmann = BoltzmannExploration(temperature=0.5)
        self.thompson = ThompsonSampling()

    def select(self, q_values, available_mask, module_states, action_space, step):
        total_pulls = sum(s.pulls for s in module_states.values())

        if total_pulls < action_space.n * 2:
            return self.ucb.select(q_values, available_mask, module_states, action_space, step)
        elif step < 10:
            return self.boltzmann.select(q_values, available_mask, module_states, action_space, step)
        else:
            return self.thompson.select(q_values, available_mask, module_states, action_space, step)


EXPLORATION_STRATEGIES = {
    "epsilon_greedy": EpsilonGreedy,
    "boltzmann": BoltzmannExploration,
    "ucb1": UCB1Exploration,
    "thompson": ThompsonSampling,
    "hybrid": HybridExploration,
}


# =====================================================================
#  CONFIDENCE-AWARE REWARD FUNCTION (Enhanced Reward)
# =====================================================================

class ConfidenceAwareReward:
    """
    Parameterized reward function that conditions on correctness × confidence.

    R = {
        +1.0   correct answer (confident)           -- confirmed & conf ≥ τ
        +0.7   correct answer (uncertain)            -- confirmed & conf < τ
        -1.5   wrong answer (confident)              -- false_positive & conf ≥ τ
        -0.5   wrong answer (uncertain)              -- false_positive & conf < τ
        +0.3   "I don't know"  (abstain)             -- module didn't report
        +0.7   ask to learn (immediate)              -- queried AI for help
        +0.5   bonus later if correct on taught topic
    }

    Confidence = the agent's internal probability estimate (softmax output,
    VALIDATION_RULES base_confidence, or scanner heuristic score).
    The uncertainty threshold τ is configurable (default 0.7).
    """

    # Default reward table (fully tunable)
    DEFAULTS = {
        "correct_confident":       +1.0,
        "correct_uncertain":       +0.7,
        "wrong_confident":         -1.5,
        "wrong_uncertain":         -0.5,
        "abstain":                 +0.3,
        "ask_to_learn":            +0.7,
        "taught_topic_correct":    +0.5,
    }

    def __init__(
        self,
        confidence_threshold: float = 0.7,
        reward_table: Optional[Dict[str, float]] = None,
    ):
        self.confidence_threshold = confidence_threshold
        self.table = {**self.DEFAULTS, **(reward_table or {})}

    def score_finding(self, correct: bool, confidence: float) -> Tuple[float, str]:
        """
        Score one finding based on correctness and confidence level.

        Args:
            correct:    True if finding was confirmed (not false-positive).
            confidence: Agent's internal confidence in [0.0, 1.0].

        Returns:
            (reward, label) tuple.
        """
        confident = confidence >= self.confidence_threshold

        if correct and confident:
            return self.table["correct_confident"], "correct_confident"
        elif correct and not confident:
            return self.table["correct_uncertain"], "correct_uncertain"
        elif not correct and confident:
            return self.table["wrong_confident"], "wrong_confident"
        else:
            return self.table["wrong_uncertain"], "wrong_uncertain"

    def score_abstain(self) -> Tuple[float, str]:
        """Reward for admitting uncertainty ("I don't know")."""
        return self.table["abstain"], "abstain"

    def score_ask_to_learn(self) -> Tuple[float, str]:
        """Immediate reward for asking to learn (querying AI for guidance)."""
        return self.table["ask_to_learn"], "ask_to_learn"

    def score_taught_topic_correct(self) -> Tuple[float, str]:
        """Delayed bonus for being correct on a previously-taught topic."""
        return self.table["taught_topic_correct"], "taught_topic_correct"

    def compute_module_reward(self, findings_data: List[Dict[str, Any]],
                              abstained: bool = False,
                              asked_to_learn: bool = False,
                              taught_topics_hit: int = 0) -> Tuple[float, Dict[str, int]]:
        """
        Compute total reward for a module execution.

        Args:
            findings_data: list of dicts with keys:
                - "correct": bool (confirmed & not false_positive)
                - "confidence": float in [0, 1]
            abstained: whether the module reported "I don't know"
            asked_to_learn: whether the module queried AI for help
            taught_topics_hit: number of findings on previously-taught topics

        Returns:
            (total_reward, breakdown_counts) where breakdown_counts maps
            reward labels → count.
        """
        total = 0.0
        counts: Dict[str, int] = {}

        for fd in findings_data:
            r, label = self.score_finding(fd["correct"], fd["confidence"])
            total += r
            counts[label] = counts.get(label, 0) + 1

        if abstained:
            r, label = self.score_abstain()
            total += r
            counts[label] = counts.get(label, 0) + 1

        if asked_to_learn:
            r, label = self.score_ask_to_learn()
            total += r
            counts[label] = counts.get(label, 0) + 1

        for _ in range(taught_topics_hit):
            r, label = self.score_taught_topic_correct()
            total += r
            counts[label] = counts.get(label, 0) + 1

        return total, counts


class TeachingMemory:
    """
    Tracks what the agent has been "taught" (via AI consultation) so it
    can award delayed bonuses when the agent later succeeds on those topics
    without AI help.

    A "topic" is a (module, vuln_type) pair.  When the agent asks the AI
    for help, the topics it was helped on are recorded.  Future findings
    on those topics earn the 'taught_topic_correct' bonus.
    """

    def __init__(self):
        self._taught: Dict[Tuple[str, str], int] = {}   # (module, vuln_type) → teach_count
        self._ai_assisted_this_step: bool = False

    def record_teaching(self, module: str, vuln_types: List[str]) -> None:
        """Record that the agent was taught about these vuln types."""
        for vt in vuln_types:
            key = (module, vt)
            self._taught[key] = self._taught.get(key, 0) + 1
        self._ai_assisted_this_step = True

    def check_taught_hits(self, module: str, vuln_types: List[str],
                          ai_assisted: bool = False) -> int:
        """
        Count how many of the current findings hit previously-taught topics
        *without* AI assistance this step.  This triggers the delayed bonus.
        """
        if ai_assisted:
            return 0  # no bonus if still using AI assistance
        hits = 0
        for vt in vuln_types:
            if (module, vt) in self._taught:
                hits += 1
        return hits

    @property
    def taught_topics(self) -> Dict[Tuple[str, str], int]:
        return dict(self._taught)

    def reset_step(self) -> None:
        self._ai_assisted_this_step = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "taught": {f"{m}|{vt}": c for (m, vt), c in self._taught.items()},
        }

    def from_dict(self, data: Dict[str, Any]) -> None:
        self._taught = {}
        for key_str, count in data.get("taught", {}).items():
            parts = key_str.split("|", 1)
            if len(parts) == 2:
                self._taught[(parts[0], parts[1])] = count


# =====================================================================
#  REWARD INTERPRETER (Feature 4)
# =====================================================================

class RewardInterpreter:
    """
    Processes raw reward signals into shaped rewards for learning.

    Features:
      - Confidence-aware reward function (correct×confident matrix)
      - Potential-based reward shaping (preserves optimal policy)
      - Intrinsic curiosity bonus (information gain for under-explored modules)
      - Novelty bonus for discovering new vulnerability categories
      - Teaching memory for delayed "learned topic" bonuses
    """

    def __init__(self, curiosity_weight: float = 0.1, shaping_weight: float = 0.05,
                 confidence_threshold: float = 0.7,
                 reward_table: Optional[Dict[str, float]] = None):
        self.curiosity_weight = curiosity_weight
        self.shaping_weight = shaping_weight
        self._visit_counts: Dict[str, int] = {}

        # Enhanced reward components
        self.confidence_reward = ConfidenceAwareReward(
            confidence_threshold=confidence_threshold,
            reward_table=reward_table,
        )
        self.teaching_memory = TeachingMemory()
        self._last_breakdown: Dict[str, int] = {}

    def interpret(self, raw_reward: float, module: str,
                  state: EnvironmentState,
                  next_state: EnvironmentState,
                  findings_data: Optional[List[Dict[str, Any]]] = None,
                  abstained: bool = False,
                  asked_to_learn: bool = False,
                  taught_topics_hit: int = 0) -> float:
        """
        Shaped reward = confidence_aware_reward + curiosity + shaping + novelty.

        When findings_data is provided (list of {"correct": bool, "confidence": float}),
        the confidence-aware reward function replaces the raw reward as the
        base signal.  Otherwise falls back to the raw reward (backward compat).
        """
        self._visit_counts[module] = self._visit_counts.get(module, 0) + 1
        visit_count = self._visit_counts[module]

        # ── Base reward: confidence-aware or raw fallback ─────
        if findings_data is not None:
            base_reward, breakdown = self.confidence_reward.compute_module_reward(
                findings_data=findings_data,
                abstained=abstained,
                asked_to_learn=asked_to_learn,
                taught_topics_hit=taught_topics_hit,
            )
            self._last_breakdown = breakdown
        else:
            base_reward = raw_reward
            self._last_breakdown = {}

        # ── 1. Intrinsic curiosity: reward less-explored modules ──
        curiosity = self.curiosity_weight / math.sqrt(visit_count)

        # ── 2. Potential-based shaping: Phi(s') - Phi(s) ──────
        phi_s = self._potential(state)
        phi_s_next = self._potential(next_state)
        shaping = self.shaping_weight * (phi_s_next - phi_s)

        # ── 3. Novelty bonus for new vuln types ───────────────
        novelty = 0.0
        if next_state.unique_vuln_types - state.unique_vuln_types:
            novelty = 0.15

        shaped = base_reward + curiosity + shaping + novelty
        return shaped

    def _potential(self, state: EnvironmentState) -> float:
        """State potential function Phi(s) for shaping."""
        progress_val = state.scan_progress * 2.0
        finding_val = _tanh(state.findings_count / 5.0) * 3.0
        confirm_val = (state.confirmed_count / max(state.findings_count, 1)) * 2.0
        severity_val = (state.severity_counts.get("critical", 0) * 1.0
                        + state.severity_counts.get("high", 0) * 0.5)
        return progress_val + finding_val + confirm_val + severity_val

    def reset_episode(self) -> None:
        """Reset per-episode counters (visit counts persist intentionally)."""
        pass


# =====================================================================
#  MAIN RL AGENT
# =====================================================================

class RLPolicyAgent:
    """
    Full autonomous RL agent for Hunter scanner module selection.

    Integrates all 9 RL features:
      1. State Perception       -- EnvironmentState + StateEncoder
      2. Action Execution       -- ActionSpace for module selection
      3. Policy                 -- Configurable exploration strategy
      4. Reward Interpretation  -- RewardInterpreter (shaping + curiosity)
      5. Learning Mechanism     -- TD(lambda) with linear FA + experience replay
      6. Explore/Exploit        -- epsilon-greedy / Boltzmann / UCB1 / Thompson / Hybrid
      7. Value Function         -- Q(s,a) via LinearQApproximator
      8. Generalization         -- Linear FA over state feature vectors
      9. Memory                 -- ReplayBuffer + EpisodeMemory

    Backward-compatible with the original RLPolicyAgent API.
    """

    def __init__(
        self,
        modules: List[str],
        state_file: str = "rl_policy_state.json",
        alpha: float = 0.01,
        epsilon: float = 0.2,
        min_epsilon: float = 0.05,
        epsilon_decay: float = 0.995,
        gamma: float = 0.95,
        lambda_trace: float = 0.8,
        exploration_strategy: str = "hybrid",
        replay_capacity: int = 5000,
        replay_batch_size: int = 32,
        curiosity_weight: float = 0.1,
        confidence_threshold: float = 0.7,
        reward_table: Optional[Dict[str, float]] = None,
    ):
        # -- Action Space --
        self.action_space = ActionSpace(modules)

        # -- State Encoder (Feature 1) --
        self.encoder = StateEncoder(self.action_space)

        # -- Value Function / Q approximator (Features 7 + 8) --
        self.q_function = LinearQApproximator(
            state_dim=self.encoder.dim,
            n_actions=self.action_space.n,
            learning_rate=alpha,
            lambda_trace=lambda_trace,
            gamma=gamma,
        )

        # -- Exploration Strategy (Features 3 + 6) --
        strategy_cls = EXPLORATION_STRATEGIES.get(exploration_strategy, HybridExploration)
        if exploration_strategy == "epsilon_greedy":
            self.exploration: ExplorationStrategy = strategy_cls(
                epsilon=epsilon, min_epsilon=min_epsilon, decay=epsilon_decay,
            )
        else:
            self.exploration = strategy_cls()

        # -- Reward Interpreter (Feature 4 — confidence-aware) --
        self.reward_interpreter = RewardInterpreter(
            curiosity_weight=curiosity_weight,
            confidence_threshold=confidence_threshold,
            reward_table=reward_table,
        )

        # -- Experience Replay Buffer (Feature 9) --
        self.replay_buffer = ReplayBuffer(capacity=replay_capacity)
        self.replay_batch_size = replay_batch_size

        # -- Episode Memory (Feature 9, partial observability) --
        self.episode_memory = EpisodeMemory()

        # -- Per-module tabular statistics (backward compat + Thompson) --
        self.module_states: Dict[str, ModulePolicyState] = {
            name: ModulePolicyState() for name in modules
        }

        # -- Technology context bias --
        self.tech_bias: Dict[str, Dict[str, float]] = {}

        # -- Hyperparameters (exposed for diagnostics) --
        self.alpha = alpha
        self.epsilon = epsilon
        self.min_epsilon = min_epsilon
        self.epsilon_decay = epsilon_decay
        self.gamma = gamma
        self.lambda_trace = lambda_trace
        self.exploration_strategy_name = exploration_strategy
        self.state_file = state_file
        self.confidence_threshold = confidence_threshold

        # -- Internal tracking --
        self._current_state: Optional[EnvironmentState] = None
        self._current_features: Optional[List[float]] = None
        self._last_action_idx: int = -1
        self._step: int = 0
        self._total_episodes: int = 0
        self._total_learning_updates: int = 0

        # -- Load persisted state --
        self._load()
        self._ensure_modules(modules)

    # -- Backward-compatible property --

    @property
    def modules(self) -> List[str]:
        return self.action_space.modules

    # =================================================================
    #  FEATURE 1: STATE PERCEPTION
    # =================================================================

    def perceive(self, state: EnvironmentState) -> List[float]:
        """
        Perceive environment state and encode it into a feature vector.
        Incorporates episodic memory features for partial observability.
        """
        state.update_progress()
        base_features = self.encoder.encode(state)

        # Append recurrent memory features (Feature 9)
        memory_features = self.episode_memory.get_recurrent_features()
        full_features = base_features + memory_features

        # Ensure dimension matches Q-function input
        target_dim = self.q_function.state_dim
        if len(full_features) < target_dim:
            full_features.extend([0.0] * (target_dim - len(full_features)))
        elif len(full_features) > target_dim:
            full_features = full_features[:target_dim]

        self._current_state = state
        self._current_features = full_features
        return full_features

    def build_state(
        self,
        target_url: str = "",
        technologies: Optional[List[str]] = None,
        waf_detected: bool = False,
        waf_name: str = "",
        discovered_urls: int = 0,
        discovered_params: int = 0,
        findings_count: int = 0,
        confirmed_count: int = 0,
        severity_counts: Optional[Dict[str, int]] = None,
        modules_run: Optional[List[str]] = None,
        modules_remaining: Optional[List[str]] = None,
        cumulative_reward: float = 0.0,
        last_reward: float = 0.0,
        elapsed_seconds: float = 0.0,
        module_last_reward: Optional[Dict[str, float]] = None,
    ) -> EnvironmentState:
        """Convenience builder for EnvironmentState."""
        return EnvironmentState(
            target_url=target_url,
            technologies=technologies or [],
            waf_detected=waf_detected,
            waf_name=waf_name,
            discovered_urls_count=discovered_urls,
            discovered_params_count=discovered_params,
            ssl_present=target_url.startswith("https") if target_url else False,
            findings_count=findings_count,
            confirmed_count=confirmed_count,
            severity_counts=severity_counts or {},
            unique_vuln_types=set(),
            modules_run=modules_run or [],
            modules_remaining=modules_remaining or [],
            cumulative_reward=cumulative_reward,
            last_reward=last_reward,
            elapsed_seconds=elapsed_seconds,
            module_last_reward=module_last_reward or {},
            step=self._step,
            episode_id=self.episode_memory.episode_id,
        )

    # =================================================================
    #  FEATURES 2 + 3: ACTION EXECUTION + POLICY
    # =================================================================

    def choose_action(
        self,
        available_modules: List[str],
        technologies: Optional[List[str]] = None,
        env_state: Optional[EnvironmentState] = None,
    ) -> str:
        """
        Choose the next scanner module via the learned policy.

        Combines:
          - Q(s,a) from linear function approximator (Feature 7)
          - Exploration strategy selection (Feature 6)
          - State perception (Feature 1) if env_state provided
        """
        if not available_modules:
            raise ValueError("No modules available for RL action selection")

        technologies = technologies or []

        # Get state features
        if env_state is not None:
            features = self.perceive(env_state)
        elif self._current_features is not None:
            features = self._current_features
        else:
            state = self.build_state(technologies=technologies)
            features = self.perceive(state)

        # Compute Q(s, a) for all actions (Feature 7)
        q_values = self.q_function.predict_all(features)

        # Add technology context bias
        for i, mod in enumerate(self.action_space.modules):
            if mod in available_modules:
                q_values[i] += self._context_bias(mod, technologies)

        # Availability mask
        mask = self.action_space.mask(available_modules)

        # Select action via exploration strategy (Feature 3 + 6)
        action_idx = self.exploration.select(
            q_values=q_values,
            available_mask=mask,
            module_states=self.module_states,
            action_space=self.action_space,
            step=self._step,
        )

        self._last_action_idx = action_idx
        self._step += 1
        choice = self.action_space.name_of(action_idx)

        logger.debug(
            f"RL choose_action: {choice} (Q={q_values[action_idx]:.3f}, "
            f"step={self._step}, strategy={self.exploration_strategy_name})"
        )
        return choice

    def rank_modules(
        self,
        modules: List[str],
        technologies: Optional[List[str]] = None,
        preferred_order: Optional[List[str]] = None,
        env_state: Optional[EnvironmentState] = None,
    ) -> List[str]:
        """
        Rank modules by Q(s,a) + context bias + AI tie-break.
        Backward-compatible with original API.
        """
        technologies = technologies or []

        if env_state is not None:
            features = self.perceive(env_state)
        elif self._current_features is not None:
            features = self._current_features
        else:
            state = self.build_state(technologies=technologies)
            features = self.perceive(state)

        q_values = self.q_function.predict_all(features)
        preferred_index = {name: i for i, name in enumerate(preferred_order or [])}

        scored = []
        for name in modules:
            idx = self.action_space.index_of(name)
            q_val = q_values[idx] if idx >= 0 else 0.0
            tech_boost = self._context_bias(name, technologies)
            ai_tie_break = -0.001 * preferred_index.get(name, 999)
            ucb_bonus = self._ucb_bonus(name)
            score = q_val + tech_boost + ai_tie_break + 0.1 * ucb_bonus
            scored.append((name, score))

        return [name for name, _ in sorted(scored, key=lambda x: x[1], reverse=True)]

    # =================================================================
    #  FEATURES 4 + 5: REWARD INTERPRETATION + LEARNING MECHANISM
    # =================================================================

    def observe(
        self,
        module: str,
        reward: float,
        technologies: Optional[List[str]] = None,
        env_state: Optional[EnvironmentState] = None,
        next_env_state: Optional[EnvironmentState] = None,
        done: bool = False,
        findings_data: Optional[List[Dict[str, Any]]] = None,
        abstained: bool = False,
        asked_to_learn: bool = False,
        taught_topics_hit: int = 0,
    ) -> float:
        """
        Observe a (module, reward) outcome and update the policy.

        Performs:
          1. Confidence-aware reward interpretation             [Feature 4+]
          2. TD(lambda) update on Q-function                    [Feature 5]
          3. Tabular statistics update                          [backward compat]
          4. Thompson Sampling parameter update                 [Feature 6]
          5. Experience replay storage + mini-batch learning    [Feature 9]
          6. Episode memory update                              [Feature 9]

        Args:
            findings_data: optional list of {"correct": bool, "confidence": float}
                           for confidence-aware reward scoring.
            abstained: module reported "I don't know" (earns +0.3 by default).
            asked_to_learn: module queried AI for help (earns +0.7 immediate).
            taught_topics_hit: findings on previously-taught topics (each +0.5).

        Returns the shaped reward.
        """
        technologies = technologies or []
        action_idx = self.action_space.index_of(module)

        # -- State features --
        if self._current_features is not None:
            state_features = list(self._current_features)
        else:
            state = self.build_state(technologies=technologies)
            state_features = self.perceive(state)

        # -- Next state features --
        if next_env_state is not None:
            next_features = self.perceive(next_env_state)
        else:
            approx_next = self.build_state(
                technologies=technologies,
                modules_run=(
                    (self._current_state.modules_run + [module])
                    if self._current_state else [module]
                ),
                last_reward=reward,
            )
            next_features = self.perceive(approx_next)

        # -- Feature 4: Confidence-Aware Reward Interpretation --
        current_state = self._current_state or self.build_state(technologies=technologies)
        next_state = next_env_state or self.build_state(
            technologies=technologies, last_reward=reward,
        )
        shaped_reward = self.reward_interpreter.interpret(
            raw_reward=reward,
            module=module,
            state=current_state,
            next_state=next_state,
            findings_data=findings_data,
            abstained=abstained,
            asked_to_learn=asked_to_learn,
            taught_topics_hit=taught_topics_hit,
        )

        # -- Feature 5a: TD(lambda) Learning --
        td_error = 0.0
        if action_idx >= 0:
            q_current = self.q_function.predict(state_features, action_idx)
            if done:
                td_target = shaped_reward
            else:
                q_next_all = self.q_function.predict_all(next_features)
                td_target = shaped_reward + self.gamma * max(q_next_all)

            td_error = td_target - q_current
            self.q_function.update_td(state_features, action_idx, td_error)
            self._total_learning_updates += 1

        # -- Tabular statistics --
        ms = self.module_states.setdefault(module, ModulePolicyState())
        ms.pulls += 1
        ms.total_reward += reward
        ms.q_value = ms.q_value + 0.2 * (reward - ms.q_value)
        ms.sum_sq_reward += reward ** 2

        if reward > 0:
            ms.successes += 1
            ms.alpha_ts += 1.0   # Thompson Sampling: success
        elif reward < 0:
            ms.failures += 1
            ms.beta_ts += 1.0    # Thompson Sampling: failure

        # -- Technology context bias --
        for tech in technologies[:8]:
            bucket = self.tech_bias.setdefault(tech, {})
            prev = bucket.get(module, 0.0)
            bucket[module] = prev + 0.1 * (reward - prev)

        # -- Feature 5b: Experience Replay --
        exp = Experience(
            state_features=state_features,
            action_idx=action_idx,
            reward=shaped_reward,
            next_state_features=next_features,
            done=done,
            info={"module": module, "raw_reward": reward},
        )
        self.replay_buffer.push(exp, priority=abs(td_error) + 0.01)

        if len(self.replay_buffer) >= self.replay_batch_size:
            self._replay_learn()

        # -- Feature 9: Episode Memory --
        self.episode_memory.add_transition(module, reward, {"shaped": shaped_reward})

        # -- Epsilon sync (backward compat) --
        if isinstance(self.exploration, EpsilonGreedy):
            self.epsilon = self.exploration.epsilon

        # -- Persist --
        self.save()

        logger.debug(
            f"RL observe: {module} raw={reward:+.3f} shaped={shaped_reward:+.3f} "
            f"td_err={td_error:.4f}"
        )
        return shaped_reward

    def _replay_learn(self) -> None:
        """Learn from a mini-batch of replayed past experiences (Feature 5)."""
        batch = self.replay_buffer.sample(self.replay_batch_size)
        for exp in batch:
            if exp.action_idx < 0:
                continue

            q_current = self.q_function.predict(exp.state_features, exp.action_idx)
            if exp.done:
                td_target = exp.reward
            else:
                q_next_all = self.q_function.predict_all(exp.next_state_features)
                td_target = exp.reward + self.gamma * max(q_next_all)

            td_error = td_target - q_current
            self.q_function.update_simple(exp.state_features, exp.action_idx, td_error)
            self._total_learning_updates += 1

    # =================================================================
    #  FEATURE 6: EXPLORE-EXPLOIT HELPERS
    # =================================================================

    def _ucb_bonus(self, module: str) -> float:
        """Compute UCB exploration bonus for a module."""
        state = self.module_states.get(module, ModulePolicyState())
        total_pulls = max(sum(s.pulls for s in self.module_states.values()), 1)
        if state.pulls == 0:
            return 5.0
        return 2.0 * math.sqrt(math.log(total_pulls) / state.pulls)

    def set_exploration_strategy(self, strategy_name: str, **kwargs) -> None:
        """Switch exploration strategy at runtime."""
        cls = EXPLORATION_STRATEGIES.get(strategy_name)
        if cls:
            self.exploration = cls(**kwargs) if kwargs else cls()
            self.exploration_strategy_name = strategy_name
            logger.info(f"RL exploration strategy changed to: {strategy_name}")

    # =================================================================
    #  FEATURE 7: VALUE FUNCTION ACCESS
    # =================================================================

    def get_q_values(
        self,
        env_state: Optional[EnvironmentState] = None,
        technologies: Optional[List[str]] = None,
    ) -> Dict[str, float]:
        """Get Q(s, a) for all modules in current state."""
        if env_state:
            features = self.perceive(env_state)
        elif self._current_features:
            features = self._current_features
        else:
            state = self.build_state(technologies=technologies)
            features = self.perceive(state)

        q_values = self.q_function.predict_all(features)
        return {
            self.action_space.name_of(i): q_values[i]
            for i in range(self.action_space.n)
        }

    def get_state_value(
        self,
        env_state: Optional[EnvironmentState] = None,
    ) -> float:
        """V(s) = max_a Q(s, a) -- state value estimate."""
        if env_state:
            features = self.perceive(env_state)
        elif self._current_features:
            features = self._current_features
        else:
            return 0.0

        q_values = self.q_function.predict_all(features)
        return max(q_values) if q_values else 0.0

    # =================================================================
    #  FEATURE 9: EPISODE MANAGEMENT
    # =================================================================

    def start_episode(self, episode_id: str = "") -> None:
        """Initialize a new scan episode."""
        import uuid
        self.episode_memory = EpisodeMemory(
            episode_id=episode_id or str(uuid.uuid4()),
        )
        self.q_function.reset_traces()
        self.reward_interpreter.reset_episode()
        self._step = 0
        self._current_state = None
        self._current_features = None
        self._last_action_idx = -1
        self._total_episodes += 1
        logger.info(f"RL episode started: {self.episode_memory.episode_id}")

    def end_episode(self) -> Dict[str, Any]:
        """Finalize episode, return summary statistics."""
        summary = {
            "episode_id": self.episode_memory.episode_id,
            "steps": self.episode_memory.steps,
            "total_reward": sum(t["reward"] for t in self.episode_memory.transitions),
            "mean_reward": self.episode_memory.running_reward_mean,
            "reward_variance": self.episode_memory.running_reward_var,
            "modules_used": list(set(self.episode_memory.module_sequence)),
            "module_sequence": self.episode_memory.module_sequence,
        }
        self.q_function.reset_traces()
        self.save()
        logger.info(
            f"RL episode ended: {summary['steps']} steps, "
            f"total_reward={summary['total_reward']:.3f}"
        )
        return summary

    # =================================================================
    #  CONTEXT BIAS (backward compat)
    # =================================================================

    def _context_bias(self, module: str, technologies: List[str]) -> float:
        if not technologies:
            return 0.0
        vals = []
        for tech in technologies[:8]:
            vals.append(self.tech_bias.get(tech, {}).get(module, 0.0))
        return sum(vals) / len(vals) if vals else 0.0

    def _ensure_modules(self, modules: List[str]) -> None:
        for name in modules:
            if name not in self.module_states:
                self.module_states[name] = ModulePolicyState()
            self.action_space.add_module(name)

    # =================================================================
    #  PERSISTENCE
    # =================================================================

    def save(self) -> None:
        """Persist full agent state to disk."""
        data = {
            "version": 2,
            "alpha": self.alpha,
            "epsilon": self.epsilon if isinstance(self.exploration, EpsilonGreedy) else 0.2,
            "min_epsilon": self.min_epsilon,
            "epsilon_decay": self.epsilon_decay,
            "gamma": self.gamma,
            "lambda_trace": self.lambda_trace,
            "exploration_strategy": self.exploration_strategy_name,
            "module_states": {
                k: asdict(v) for k, v in self.module_states.items()
            },
            "tech_bias": self.tech_bias,
            "q_function": self.q_function.to_dict(),
            "replay_buffer_size": len(self.replay_buffer),
            "replay_buffer": self.replay_buffer.to_list()[-500:],
            "visit_counts": self.reward_interpreter._visit_counts,
            "teaching_memory": self.reward_interpreter.teaching_memory.to_dict(),
            "confidence_threshold": self.confidence_threshold,
            "reward_table": self.reward_interpreter.confidence_reward.table,
            "total_episodes": self._total_episodes,
            "total_learning_updates": self._total_learning_updates,
        }
        try:
            os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.debug(f"Failed to save RL agent state: {exc}")

    def _load(self) -> None:
        """Load agent state from disk if present."""
        if not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            version = data.get("version", 1)

            self.alpha = float(data.get("alpha", self.alpha))
            self.epsilon = float(data.get("epsilon", self.epsilon))
            self.min_epsilon = float(data.get("min_epsilon", self.min_epsilon))
            self.epsilon_decay = float(data.get("epsilon_decay", self.epsilon_decay))
            self.gamma = float(data.get("gamma", self.gamma))
            self.lambda_trace = float(data.get("lambda_trace", self.lambda_trace))

            if isinstance(self.exploration, EpsilonGreedy):
                self.exploration.epsilon = self.epsilon
                self.exploration.min_epsilon = self.min_epsilon
                self.exploration.decay = self.epsilon_decay

            # Module states
            loaded_states = data.get("module_states", {})
            for name, raw in loaded_states.items():
                self.module_states[name] = ModulePolicyState(
                    pulls=int(raw.get("pulls", 0)),
                    q_value=float(raw.get("q_value", 0.0)),
                    total_reward=float(raw.get("total_reward", 0.0)),
                    successes=int(raw.get("successes", 0)),
                    failures=int(raw.get("failures", 0)),
                    alpha_ts=float(raw.get("alpha_ts", 1.0)),
                    beta_ts=float(raw.get("beta_ts", 1.0)),
                    sum_sq_reward=float(raw.get("sum_sq_reward", 0.0)),
                )

            self.tech_bias = data.get("tech_bias", {}) or {}

            # Q-function (v2 only)
            if version >= 2 and "q_function" in data:
                self.q_function.from_dict(data["q_function"])

            # Replay buffer
            if "replay_buffer" in data:
                self.replay_buffer.from_list(data["replay_buffer"])

            # Reward interpreter
            if "visit_counts" in data:
                self.reward_interpreter._visit_counts = data["visit_counts"]

            # Teaching memory (enhanced reward)
            if "teaching_memory" in data:
                self.reward_interpreter.teaching_memory.from_dict(data["teaching_memory"])

            # Confidence threshold override
            if "confidence_threshold" in data:
                self.confidence_threshold = float(data["confidence_threshold"])
                self.reward_interpreter.confidence_reward.confidence_threshold = self.confidence_threshold

            if "reward_table" in data:
                self.reward_interpreter.confidence_reward.table.update(data["reward_table"])

            # Statistics
            self._total_episodes = int(data.get("total_episodes", 0))
            self._total_learning_updates = int(data.get("total_learning_updates", 0))

            logger.info(
                f"RL agent loaded: v{version}, {len(loaded_states)} modules, "
                f"{len(self.replay_buffer)} replay experiences"
            )
        except Exception as exc:
            logger.debug(f"Failed to load RL agent state: {exc}")

    # =================================================================
    #  DIAGNOSTICS
    # =================================================================

    def summary(self, top_n: int = 5) -> str:
        """Human-readable policy summary for logs/TUI."""
        ranked = sorted(
            self.module_states.items(),
            key=lambda x: x[1].q_value,
            reverse=True,
        )
        top = ranked[:top_n]

        eps_str = ""
        if isinstance(self.exploration, EpsilonGreedy):
            eps_str = f"eps={self.exploration.epsilon:.3f}"
        elif isinstance(self.exploration, BoltzmannExploration):
            eps_str = f"temp={self.exploration.temperature:.3f}"

        parts = [
            f"strategy={self.exploration_strategy_name}",
            eps_str,
            f"replay={len(self.replay_buffer)}",
            "top=" + ", ".join(f"{n}:{s.q_value:+.2f}" for n, s in top),
        ]
        return " | ".join(p for p in parts if p)

    def diagnostics(self) -> Dict[str, Any]:
        """Full diagnostic data for the RL agent."""
        total_pulls = sum(s.pulls for s in self.module_states.values())
        total_successes = sum(s.successes for s in self.module_states.values())
        total_failures = sum(s.failures for s in self.module_states.values())
        total_reward = sum(s.total_reward for s in self.module_states.values())

        ranked = sorted(
            self.module_states.items(),
            key=lambda x: x[1].q_value,
            reverse=True,
        )

        return {
            "exploration_strategy": self.exploration_strategy_name,
            "epsilon": (
                self.exploration.epsilon
                if isinstance(self.exploration, EpsilonGreedy) else None
            ),
            "temperature": (
                self.exploration.temperature
                if isinstance(self.exploration, BoltzmannExploration) else None
            ),
            "alpha": self.alpha,
            "gamma": self.gamma,
            "lambda_trace": self.lambda_trace,
            "total_pulls": total_pulls,
            "total_successes": total_successes,
            "total_failures": total_failures,
            "total_reward": total_reward,
            "total_episodes": self._total_episodes,
            "total_learning_updates": self._total_learning_updates,
            "replay_buffer_size": len(self.replay_buffer),
            "replay_buffer_capacity": self.replay_buffer.capacity,
            "q_function_state_dim": self.q_function.state_dim,
            "q_function_n_actions": self.q_function.n_actions,
            "n_tech_biases": len(self.tech_bias),
            "visit_counts": dict(self.reward_interpreter._visit_counts),
            "confidence_threshold": self.confidence_threshold,
            "reward_table": self.reward_interpreter.confidence_reward.table,
            "taught_topics": len(self.reward_interpreter.teaching_memory.taught_topics),
            "last_reward_breakdown": self.reward_interpreter._last_breakdown,
            "module_ranking": [
                {
                    "module": name,
                    "q_value": st.q_value,
                    "pulls": st.pulls,
                    "avg_reward": st.total_reward / max(st.pulls, 1),
                    "successes": st.successes,
                    "failures": st.failures,
                    "ucb_bonus": self._ucb_bonus(name),
                    "thompson_alpha": st.alpha_ts,
                    "thompson_beta": st.beta_ts,
                }
                for name, st in ranked
            ],
        }
