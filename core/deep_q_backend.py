"""Pure-Python deep Q-value approximator used by Hunter's neural backend."""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from core.rl_environment import _dot


class DeepQApproximator:
    """
    Small MLP-based Q approximator.

    This keeps Hunter zero-dependency while providing a real neural backend:
      input -> hidden(ReLU) -> hidden(ReLU) -> action Q-values
    """

    backend = "deep"

    def __init__(
        self,
        state_dim: int,
        n_actions: int,
        learning_rate: float = 0.001,
        lambda_trace: float = 0.0,
        gamma: float = 0.95,
        hidden_dims: Optional[List[int]] = None,
        seed: int = 1337,
    ):
        self.state_dim = state_dim
        self.n_actions = n_actions
        self.lr = learning_rate
        self.gamma = gamma
        self.lambda_trace = lambda_trace
        self.hidden_dims = list(hidden_dims or [64, 32])
        self._rng = random.Random(seed)

        h1, h2 = self.hidden_dims
        self.w1 = [self._rand_vec(state_dim) for _ in range(h1)]
        self.b1 = [0.0 for _ in range(h1)]
        self.w2 = [self._rand_vec(h1) for _ in range(h2)]
        self.b2 = [0.0 for _ in range(h2)]
        self.w3 = [self._rand_vec(h2) for _ in range(n_actions)]
        self.b3 = [0.0 for _ in range(n_actions)]

    def _rand_vec(self, dim: int) -> List[float]:
        scale = 1.0 / max(dim, 1)
        return [self._rng.uniform(-scale, scale) for _ in range(dim)]

    @staticmethod
    def _relu(value: float) -> float:
        return value if value > 0.0 else 0.0

    @staticmethod
    def _relu_grad(value: float) -> float:
        return 1.0 if value > 0.0 else 0.0

    def _forward(self, state_features: List[float]) -> Dict[str, Any]:
        z1 = [_dot(row, state_features) + bias for row, bias in zip(self.w1, self.b1)]
        h1 = [self._relu(v) for v in z1]

        z2 = [_dot(row, h1) + bias for row, bias in zip(self.w2, self.b2)]
        h2 = [self._relu(v) for v in z2]

        out = [_dot(row, h2) + bias for row, bias in zip(self.w3, self.b3)]
        return {"z1": z1, "h1": h1, "z2": z2, "h2": h2, "out": out}

    def predict(self, state_features: List[float], action_idx: int) -> float:
        if action_idx < 0 or action_idx >= self.n_actions:
            return 0.0
        return self._forward(state_features)["out"][action_idx]

    def predict_all(self, state_features: List[float]) -> List[float]:
        return self._forward(state_features)["out"]

    def _train_target(self, state_features: List[float], action_idx: int, target_value: float) -> None:
        if action_idx < 0 or action_idx >= self.n_actions:
            return

        cache = self._forward(state_features)
        out = cache["out"]
        h2 = cache["h2"]
        h1 = cache["h1"]
        z2 = cache["z2"]
        z1 = cache["z1"]

        prediction = out[action_idx]
        delta_out = prediction - target_value

        old_w3 = list(self.w3[action_idx])

        # Output layer update for selected action only.
        for j in range(len(self.w3[action_idx])):
            self.w3[action_idx][j] -= self.lr * delta_out * h2[j]
        self.b3[action_idx] -= self.lr * delta_out

        delta_h2 = [
            delta_out * old_w3[j] * self._relu_grad(z2[j])
            for j in range(len(h2))
        ]

        old_w2 = [list(row) for row in self.w2]
        for j, delta in enumerate(delta_h2):
            for i in range(len(self.w2[j])):
                self.w2[j][i] -= self.lr * delta * h1[i]
            self.b2[j] -= self.lr * delta

        delta_h1 = []
        for i in range(len(h1)):
            propagated = sum(delta_h2[j] * old_w2[j][i] for j in range(len(delta_h2)))
            delta_h1.append(propagated * self._relu_grad(z1[i]))

        for i, delta in enumerate(delta_h1):
            for k in range(len(self.w1[i])):
                self.w1[i][k] -= self.lr * delta * state_features[k]
            self.b1[i] -= self.lr * delta

    def update_td(self, state_features: List[float], action_idx: int, td_error: float) -> None:
        current_q = self.predict(state_features, action_idx)
        self._train_target(state_features, action_idx, current_q + td_error)

    def update_simple(self, state_features: List[float], action_idx: int, td_error: float) -> None:
        self.update_td(state_features, action_idx, td_error)

    def reset_traces(self) -> None:
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "state_dim": self.state_dim,
            "n_actions": self.n_actions,
            "lr": self.lr,
            "gamma": self.gamma,
            "lambda_trace": self.lambda_trace,
            "hidden_dims": self.hidden_dims,
            "w1": self.w1,
            "b1": self.b1,
            "w2": self.w2,
            "b2": self.b2,
            "w3": self.w3,
            "b3": self.b3,
        }

    def from_dict(self, data: Dict[str, Any]) -> None:
        self.lr = float(data.get("lr", self.lr))
        self.gamma = float(data.get("gamma", self.gamma))
        self.lambda_trace = float(data.get("lambda_trace", self.lambda_trace))
        saved_hidden = data.get("hidden_dims", self.hidden_dims)

        # If hidden dims match, we can selectively load weights with
        # dimension adaptation for changed state_dim / n_actions.
        h1, h2 = self.hidden_dims

        if list(saved_hidden) == self.hidden_dims:
            # -- w1: shape [h1, state_dim] --
            if "w1" in data:
                self.w1 = self._adapt_matrix(data["w1"], h1, self.state_dim)
            if "b1" in data:
                self.b1 = self._adapt_bias(data["b1"], h1)
            # -- w2: shape [h2, h1] — hidden dims unchanged, load directly --
            if "w2" in data:
                self.w2 = self._adapt_matrix(data["w2"], h2, h1)
            if "b2" in data:
                self.b2 = self._adapt_bias(data["b2"], h2)
            # -- w3: shape [n_actions, h2] --
            if "w3" in data:
                self.w3 = self._adapt_matrix(data["w3"], self.n_actions, h2)
            if "b3" in data:
                self.b3 = self._adapt_bias(data["b3"], self.n_actions)
        # else: hidden dims differ — keep freshly initialized weights

    @staticmethod
    def _adapt_matrix(saved: List[List[float]], target_rows: int, target_cols: int) -> List[List[float]]:
        """Load a saved weight matrix, padding/truncating to (target_rows, target_cols)."""
        result = []
        for r in range(target_rows):
            if r < len(saved):
                row = list(saved[r])
                if len(row) < target_cols:
                    row.extend([0.0] * (target_cols - len(row)))
                elif len(row) > target_cols:
                    row = row[:target_cols]
                result.append(row)
            else:
                result.append([0.0] * target_cols)
        return result

    @staticmethod
    def _adapt_bias(saved: List[float], target_len: int) -> List[float]:
        """Load a saved bias vector, padding/truncating to target_len."""
        bias = list(saved)
        if len(bias) < target_len:
            bias.extend([0.0] * (target_len - len(bias)))
        elif len(bias) > target_len:
            bias = bias[:target_len]
        return bias

    def output_weight_norms(self) -> List[float]:
        return [sum(weight * weight for weight in row) ** 0.5 for row in self.w3]
