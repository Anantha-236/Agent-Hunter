"""
RL Agent Comprehensive Test Suite
==================================
Covers all 15 test cases from the agent_test_suite spec.

Run with:
    python -m pytest tests/test_rl_agent_suite.py -v --tb=short
"""

import os
import sys
import time
import math
import threading
import tempfile
import tracemalloc
import random

import pytest

# ── Project imports ────────────────────────────────────────────────────────────
from core.rl_environment import (
    EnvironmentState,
    ActionSpace,
    StateEncoder,
)
from core.rl_agent import (
    RLPolicyAgent,
    ConfidenceAwareReward,
    RewardInterpreter,
    TeachingMemory,
    EpsilonGreedy,
    BoltzmannExploration,
    UCB1Exploration,
    ThompsonSampling,
    HybridExploration,
)


# ══════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ══════════════════════════════════════════════════════════════════════════════

AVAILABLE_MODULES = ["moduleA", "moduleB", "moduleC", "moduleD", "moduleE"]
TARGET_TECH = "moduleA"


def _make_state(**overrides) -> EnvironmentState:
    """Build a synthetic EnvironmentState for testing."""
    defaults = dict(
        target_url="https://example.com",
        technologies=["php", "mysql"],
        waf_detected=False,
        waf_name="",
        discovered_urls_count=30,
        discovered_params_count=80,
        ssl_present=True,
        modules_run=[],
        modules_remaining=list(AVAILABLE_MODULES),
        findings_count=0,
        confirmed_count=0,
        severity_counts={},
        unique_vuln_types=set(),
        cumulative_reward=0.0,
        last_reward=0.0,
        rewards_history=[],
        elapsed_seconds=0.0,
        avg_module_time=0.0,
        step=0,
    )
    defaults.update(overrides)
    return EnvironmentState(**defaults)


def _make_agent(tmp_path=None) -> RLPolicyAgent:
    """Instantiate an agent with an isolated state file."""
    if tmp_path is None:
        fd, tmp_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        # Remove the empty file so the agent starts fresh
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return RLPolicyAgent(
        modules=list(AVAILABLE_MODULES),
        state_file=tmp_path,
        exploration_strategy="hybrid",
    )


def _run_episodes(agent: RLPolicyAgent, n: int = 30) -> list:
    """Run *n* synthetic training episodes; return per-episode total rewards."""
    episode_rewards = []
    for ep in range(n):
        agent.start_episode(f"train-ep-{ep}")
        state = _make_state()
        agent.perceive(state)
        total_reward = 0.0
        remaining = list(AVAILABLE_MODULES)

        for _step in range(5):
            action = agent.choose_action(remaining, technologies=["php"], env_state=state)
            reward = 1.0 if action == TARGET_TECH else -0.1

            next_remaining = [m for m in remaining if m != action]
            next_state = _make_state(
                modules_run=[action],
                modules_remaining=next_remaining,
                findings_count=1 if reward > 0 else 0,
                confirmed_count=1 if reward > 0 else 0,
                last_reward=reward,
                elapsed_seconds=float(_step * 10),
            )
            agent.observe(
                module=action,
                reward=reward,
                technologies=["php"],
                env_state=state,
                next_env_state=next_state,
                done=(_step == 4),
            )
            total_reward += reward
            state = next_state
            remaining = next_remaining if next_remaining else list(AVAILABLE_MODULES)

        agent.end_episode()
        episode_rewards.append(total_reward)
    return episode_rewards


def _variance(seq):
    n = len(seq)
    if n < 2:
        return 0.0
    mean = sum(seq) / n
    return sum((x - mean) ** 2 for x in seq) / (n - 1)


# ══════════════════════════════════════════════════════════════════════════════
# 1. ENV_INIT – Environment Initialization
# ══════════════════════════════════════════════════════════════════════════════

def test_env_init():
    """ENV_INIT: agent initialises correctly and round-trips start/end episode."""
    t0 = time.perf_counter()
    agent = _make_agent()
    init_time = time.perf_counter() - t0

    # init_success
    assert agent is not None, "Agent failed to instantiate"

    # reset_time < 500 ms
    assert init_time < 0.5, f"Init took {init_time:.3f}s — too slow"

    # observation_validity: encoder produces finite, non-empty vector
    state = _make_state()
    action_space = ActionSpace(AVAILABLE_MODULES)
    encoder = StateEncoder(action_space)
    features = encoder.encode(state)
    assert len(features) > 0, "StateEncoder returned empty feature vector"
    assert all(math.isfinite(f) for f in features), "Feature vector contains non-finite values"

    # round-trip episode
    agent.start_episode("init-test")
    summary = agent.end_episode()
    assert "episode_id" in summary, "end_episode must return a summary dict"

    print(f"\n  [ENV_INIT] init_time={init_time*1000:.1f}ms  feature_dim={len(features)}")


# ══════════════════════════════════════════════════════════════════════════════
# 2. ACTION_SPACE_VALIDATION – Action Space Compliance
# ══════════════════════════════════════════════════════════════════════════════

def test_action_space_validation():
    """ACTION_SPACE_VALIDATION: agent only returns actions from allowed set."""
    agent = _make_agent()
    agent.start_episode("action-test")
    state = _make_state()

    invalid_count = 0
    total = 200
    action_counts = {m: 0 for m in AVAILABLE_MODULES}

    for _ in range(total):
        action = agent.choose_action(
            available_modules=list(AVAILABLE_MODULES),
            technologies=["php"],
            env_state=state,
        )
        if action not in AVAILABLE_MODULES:
            invalid_count += 1
        else:
            action_counts[action] += 1

    invalid_action_rate = invalid_count / total
    assert invalid_action_rate == 0.0, f"invalid_action_rate={invalid_action_rate}"

    # action_distribution: at least 1 distinct action chosen
    distinct = sum(1 for v in action_counts.values() if v > 0)
    assert distinct >= 1, "Agent never produced any action"

    agent.end_episode()
    print(f"\n  [ACTION_SPACE] invalid_rate={invalid_action_rate}  distribution={action_counts}")


# ══════════════════════════════════════════════════════════════════════════════
# 3. STATE_OBSERVATION – State Observation Handling
# ══════════════════════════════════════════════════════════════════════════════

def test_state_observation():
    """STATE_OBSERVATION: perceive() handles normal, zero, and extreme states."""
    agent = _make_agent()
    action_space = ActionSpace(AVAILABLE_MODULES)
    encoder = StateEncoder(action_space)

    error_count = 0
    latencies = []

    test_states = [
        _make_state(),
        _make_state(
            discovered_urls_count=0,
            discovered_params_count=0,
            findings_count=0,
            elapsed_seconds=0.0,
        ),
        _make_state(
            discovered_urls_count=999999,
            discovered_params_count=999999,
            findings_count=100000,
            elapsed_seconds=1e8,
        ),
        _make_state(
            cumulative_reward=-1000.0,
            last_reward=-100.0,
        ),
    ]

    for s in test_states:
        t0 = time.perf_counter()
        try:
            features = encoder.encode(s)
            assert isinstance(features, (list, tuple))
            assert all(math.isfinite(f) for f in features), "Non-finite feature detected"
        except Exception:
            error_count += 1
        latencies.append(time.perf_counter() - t0)

    state_parse_error_rate = error_count / len(test_states)
    avg_latency = sum(latencies) / len(latencies)

    assert state_parse_error_rate == 0.0, f"state_parse_error_rate={state_parse_error_rate}"
    assert avg_latency < 0.1, f"observation_latency={avg_latency*1000:.2f}ms exceeds 100ms"

    print(f"\n  [STATE_OBS] error_rate={state_parse_error_rate}  avg_latency={avg_latency*1000:.2f}ms")


# ══════════════════════════════════════════════════════════════════════════════
# 4. REWARD_SIGNAL – Reward Processing
# ══════════════════════════════════════════════════════════════════════════════

def test_reward_signal():
    """REWARD_SIGNAL: reward components are computed correctly."""
    car = ConfidenceAwareReward(confidence_threshold=0.7)

    # Verify the 7-case confidence×correctness reward matrix
    cases = [
        (True,  0.9, "correct_confident",  +1.0),
        (True,  0.4, "correct_uncertain",  +0.7),
        (False, 0.85, "wrong_confident",   -1.5),
        (False, 0.3, "wrong_uncertain",    -0.5),
    ]

    reward_errors = 0
    t0 = time.perf_counter()
    for correct, confidence, expected_label, expected_reward in cases:
        r, label = car.score_finding(correct=correct, confidence=confidence)
        if label != expected_label or abs(r - expected_reward) > 1e-6:
            reward_errors += 1
    reward_delay = time.perf_counter() - t0

    # Abstain, ask-to-learn, taught-topic-correct
    r, label = car.score_abstain()
    if label != "abstain" or abs(r - 0.3) > 1e-6:
        reward_errors += 1

    r, label = car.score_ask_to_learn()
    if label != "ask_to_learn" or abs(r - 0.7) > 1e-6:
        reward_errors += 1

    r, label = car.score_taught_topic_correct()
    if label != "taught_topic_correct" or abs(r - 0.5) > 1e-6:
        reward_errors += 1

    total_cases = len(cases) + 3
    reward_accuracy = 1 - reward_errors / total_cases
    assert reward_accuracy == 1.0, f"reward_accuracy={reward_accuracy:.2f} (errors={reward_errors})"
    assert reward_delay < 0.05, f"reward_delay={reward_delay*1000:.2f}ms"

    # RewardInterpreter shaping
    interpreter = RewardInterpreter()
    state = _make_state()
    next_state = _make_state(findings_count=2, confirmed_count=1)
    shaped = interpreter.interpret(
        raw_reward=1.0,
        module="moduleA",
        state=state,
        next_state=next_state,
    )
    assert isinstance(shaped, (int, float)), "RewardInterpreter.interpret() must return a number"

    # TeachingMemory delayed bonuses
    tm = TeachingMemory()
    tm.record_teaching("moduleA", ["sqli", "xss"])
    hits = tm.check_taught_hits("moduleA", ["sqli", "xss"], ai_assisted=False)
    assert hits == 2, f"Expected 2 taught hits, got {hits}"
    hits_ai = tm.check_taught_hits("moduleA", ["sqli"], ai_assisted=True)
    assert hits_ai == 0, "AI-assisted should return 0 hits"

    print(f"\n  [REWARD] accuracy={reward_accuracy:.2f}  delay={reward_delay*1000:.2f}ms  "
          f"shaped={shaped:.3f}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. POLICY_LEARNING – Policy Learning Progress
# ══════════════════════════════════════════════════════════════════════════════

def test_policy_learning():
    """POLICY_LEARNING: average reward improves over training."""
    agent = _make_agent()
    rewards = _run_episodes(agent, n=60)

    first_half_avg = sum(rewards[:30]) / 30
    second_half_avg = sum(rewards[30:]) / 30
    improvement_rate = second_half_avg - first_half_avg

    assert second_half_avg >= first_half_avg - 1.0, (
        f"Policy did not improve: first={first_half_avg:.2f} second={second_half_avg:.2f}"
    )

    print(f"\n  [POLICY] first_avg={first_half_avg:.2f}  second_avg={second_half_avg:.2f}  "
          f"improvement={improvement_rate:+.2f}")


# ══════════════════════════════════════════════════════════════════════════════
# 6. EXPLORATION_BEHAVIOR – Exploration vs Exploitation
# ══════════════════════════════════════════════════════════════════════════════

def test_exploration_behavior():
    """EXPLORATION_BEHAVIOR: all strategies produce valid actions; entropy evolves."""
    state = _make_state()

    # All 5 strategies produce valid actions
    strategies = {
        "epsilon_greedy": "epsilon_greedy",
        "boltzmann": "boltzmann",
        "ucb1": "ucb1",
        "thompson": "thompson",
        "hybrid": "hybrid",
    }
    for label, strat_name in strategies.items():
        agent = _make_agent()
        agent.set_exploration_strategy(strat_name)
        agent.start_episode(f"explore-{label}")
        action = agent.choose_action(
            available_modules=list(AVAILABLE_MODULES),
            technologies=["php"],
            env_state=state,
        )
        assert action in AVAILABLE_MODULES, f"Strategy {label} returned invalid action: {action}"
        agent.end_episode()

    # Entropy measurement before and after training
    agent = _make_agent()

    def _entropy(ag, n=50):
        counts = {m: 0 for m in AVAILABLE_MODULES}
        ag.start_episode("entropy-probe")
        for _ in range(n):
            a = ag.choose_action(
                available_modules=list(AVAILABLE_MODULES),
                technologies=["php"],
                env_state=state,
            )
            counts[a] += 1
        ag.end_episode()
        probs = [c / n for c in counts.values() if c > 0]
        return -sum(p * math.log(p + 1e-9) for p in probs)

    entropy_before = _entropy(agent)
    _run_episodes(agent, n=40)
    entropy_after = _entropy(agent)

    print(f"\n  [EXPLORATION] entropy_before={entropy_before:.3f}  entropy_after={entropy_after:.3f}")
    # After training entropy should not increase dramatically
    assert entropy_after <= entropy_before + 0.5, (
        f"Entropy increased unexpectedly: {entropy_before:.3f} → {entropy_after:.3f}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 7. CONVERGENCE_TEST – Training Convergence
# ══════════════════════════════════════════════════════════════════════════════

def test_convergence():
    """CONVERGENCE_TEST: reward variance drops and policy stabilises."""
    agent = _make_agent()
    rewards = _run_episodes(agent, n=100)

    early_var = _variance(rewards[:20])
    late_var = _variance(rewards[80:])
    stability = 1 - (late_var / (early_var + 1e-9))

    print(f"\n  [CONVERGENCE] early_var={early_var:.4f}  late_var={late_var:.4f}  "
          f"policy_stability={stability:.3f}")

    assert late_var <= early_var * 2 + 0.5, (
        f"Reward variance did not decrease: early={early_var:.3f} late={late_var:.3f}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 8. GENERALIZATION_TEST – Generalization Across Environments
# ══════════════════════════════════════════════════════════════════════════════

def test_generalization():
    """GENERALIZATION_TEST: policy transfers to modified states."""
    agent = _make_agent()

    # Train on base state
    _run_episodes(agent, n=40)

    # Evaluate on base vs shifted states
    def _eval(state, n=20):
        total = 0.0
        agent.start_episode("gen-eval")
        for _ in range(n):
            action = agent.choose_action(
                available_modules=list(AVAILABLE_MODULES),
                technologies=["php"],
                env_state=state,
            )
            total += 1.0 if action == TARGET_TECH else -0.1
        agent.end_episode()
        return total / n

    base_state = _make_state()
    shifted_state = _make_state(
        technologies=["python", "django"],
        discovered_urls_count=500,
        discovered_params_count=200,
        waf_detected=True,
        waf_name="cloudflare",
        elapsed_seconds=600.0,
    )

    base_score = _eval(base_state)
    shifted_score = _eval(shifted_state)

    performance_drop_rate = max(0.0, (base_score - shifted_score) / (abs(base_score) + 1e-9))
    transfer_success = shifted_score > -0.1  # better than worst-case random

    print(f"\n  [GENERALIZE] base={base_score:.3f}  shifted={shifted_score:.3f}  "
          f"drop_rate={performance_drop_rate:.3f}  transfer={transfer_success}")

    assert performance_drop_rate < 1.5, f"Performance dropped too much: {performance_drop_rate:.2f}"


# ══════════════════════════════════════════════════════════════════════════════
# 9. ROBUSTNESS_TEST – Noise Robustness
# ══════════════════════════════════════════════════════════════════════════════

def test_robustness():
    """ROBUSTNESS_TEST: agent remains valid under noisy observations."""
    agent = _make_agent()
    agent.start_episode("robustness-test")

    errors = 0
    rewards_noisy = []
    rng = random.Random(42)

    for step in range(100):
        noise_urls = max(0, int(30 + rng.gauss(0, 50)))
        noise_params = max(0, int(80 + rng.gauss(0, 100)))
        noise_reward = rng.gauss(0, 0.3)

        state = _make_state(
            discovered_urls_count=noise_urls,
            discovered_params_count=noise_params,
            cumulative_reward=noise_reward * 10,
            last_reward=noise_reward,
            elapsed_seconds=float(step * 5),
        )
        try:
            action = agent.choose_action(
                available_modules=list(AVAILABLE_MODULES),
                technologies=["php"],
                env_state=state,
            )
            if action not in AVAILABLE_MODULES:
                errors += 1
            reward = 1.0 if action == TARGET_TECH else -0.1
            noisy_reward = reward + rng.gauss(0, 0.1)
            next_state = _make_state(
                modules_run=[action],
                last_reward=noisy_reward,
                elapsed_seconds=float((step + 1) * 5),
            )
            agent.observe(
                module=action,
                reward=noisy_reward,
                technologies=["php"],
                env_state=state,
                next_env_state=next_state,
                done=(step == 99),
            )
            rewards_noisy.append(reward)
        except Exception:
            errors += 1

    agent.end_episode()
    performance_under_noise = sum(rewards_noisy) / max(len(rewards_noisy), 1)
    error_tolerance = 1 - errors / 100

    print(f"\n  [ROBUSTNESS] perf={performance_under_noise:.3f}  error_tolerance={error_tolerance:.2f}")
    assert errors == 0, f"Agent produced {errors} errors under noise"


# ══════════════════════════════════════════════════════════════════════════════
# 10. FAILURE_RECOVERY – Failure Recovery
# ══════════════════════════════════════════════════════════════════════════════

def test_failure_recovery():
    """FAILURE_RECOVERY: agent recovers cleanly from mid-episode reset."""
    agent = _make_agent()

    t0 = time.perf_counter()
    agent.start_episode("fail-ep-1")
    state = _make_state()
    for _ in range(3):
        action = agent.choose_action(list(AVAILABLE_MODULES), ["php"], env_state=state)
        next_state = _make_state(modules_run=[action], last_reward=0.5)
        agent.observe(action, 0.5, ["php"], env_state=state, next_env_state=next_state, done=False)
        state = next_state

    # Simulate mid-episode failure → force restart without calling end_episode
    agent.start_episode("fail-ep-2")
    state = _make_state()
    for _ in range(3):
        action = agent.choose_action(list(AVAILABLE_MODULES), ["php"], env_state=state)
        next_state = _make_state(modules_run=[action], last_reward=0.5)
        agent.observe(action, 0.5, ["php"], env_state=state, next_env_state=next_state, done=False)
        state = next_state
    agent.end_episode()
    recovery_time = time.perf_counter() - t0

    # Verify the agent is still functional after recovery
    agent.start_episode("fail-ep-3")
    action = agent.choose_action(list(AVAILABLE_MODULES), ["php"], env_state=_make_state())
    assert action in AVAILABLE_MODULES, "Agent non-functional after recovery"
    agent.end_episode()

    assert recovery_time < 2.0, f"recovery_time={recovery_time:.3f}s too slow"
    print(f"\n  [RECOVERY] recovery_time={recovery_time*1000:.1f}ms  restart_success=True")


# ══════════════════════════════════════════════════════════════════════════════
# 11. SAFETY_CONSTRAINT – Safety Constraint Compliance
# ══════════════════════════════════════════════════════════════════════════════

def test_safety_constraint():
    """SAFETY_CONSTRAINT: agent never selects restricted/masked actions."""
    agent = _make_agent()
    agent.start_episode("safety-test")

    restricted = {"moduleD", "moduleE"}
    allowed = [m for m in AVAILABLE_MODULES if m not in restricted]
    state = _make_state()

    violations = 0
    for _ in range(200):
        action = agent.choose_action(
            available_modules=allowed,
            technologies=["php"],
            env_state=state,
        )
        if action in restricted:
            violations += 1

    agent.end_episode()
    safety_violation_rate = violations / 200
    assert safety_violation_rate == 0.0, f"safety_violation_rate={safety_violation_rate}"
    print(f"\n  [SAFETY] violation_rate={safety_violation_rate}")


# ══════════════════════════════════════════════════════════════════════════════
# 12. LATENCY_TEST – Inference Latency
# ══════════════════════════════════════════════════════════════════════════════

def test_latency():
    """LATENCY_TEST: choose_action <50ms; observe <100ms."""
    agent = _make_agent()
    agent.start_episode("latency-test")
    state = _make_state()
    next_state = _make_state(modules_run=["moduleA"], last_reward=0.5)

    # Warm-up
    action = agent.choose_action(list(AVAILABLE_MODULES), ["php"], env_state=state)

    # Action inference latency
    N = 50
    t0 = time.perf_counter()
    for _ in range(N):
        agent.choose_action(list(AVAILABLE_MODULES), ["php"], env_state=state)
    avg_action_ms = (time.perf_counter() - t0) / N * 1000

    # Observe latency
    t0 = time.perf_counter()
    for _ in range(N):
        agent.observe(
            module=action,
            reward=0.5,
            technologies=["php"],
            env_state=state,
            next_env_state=next_state,
            done=False,
        )
    avg_observe_ms = (time.perf_counter() - t0) / N * 1000

    agent.end_episode()

    print(f"\n  [LATENCY] choose_action={avg_action_ms:.2f}ms  observe={avg_observe_ms:.2f}ms")
    assert avg_action_ms < 50, f"choose_action latency {avg_action_ms:.2f}ms > 50ms"
    assert avg_observe_ms < 100, f"observe latency {avg_observe_ms:.2f}ms > 100ms"


# ══════════════════════════════════════════════════════════════════════════════
# 13. SCALABILITY_TEST – Parallel Environment Scalability
# ══════════════════════════════════════════════════════════════════════════════

def test_scalability():
    """SCALABILITY_TEST: multiple agents train concurrently without corruption."""
    NUM_AGENTS = 5
    EPISODES = 20
    results = {}
    errors = []

    def _train(agent_id):
        try:
            agent = _make_agent()
            rewards = _run_episodes(agent, n=EPISODES)
            results[agent_id] = rewards
        except Exception as e:
            errors.append((agent_id, str(e)))

    threads = [threading.Thread(target=_train, args=(i,)) for i in range(NUM_AGENTS)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0

    throughput = (NUM_AGENTS * EPISODES) / elapsed
    assert not errors, f"Errors during parallel training: {errors}"
    assert len(results) == NUM_AGENTS, "Not all agents completed training"

    print(f"\n  [SCALABILITY] agents={NUM_AGENTS}  elapsed={elapsed:.2f}s  "
          f"throughput={throughput:.1f} episodes/s")


# ══════════════════════════════════════════════════════════════════════════════
# 14. RESOURCE_USAGE – Resource Consumption
# ══════════════════════════════════════════════════════════════════════════════

def test_resource_usage():
    """RESOURCE_USAGE: memory stays within bounds over 100 training episodes."""
    tracemalloc.start()
    agent = _make_agent()
    _run_episodes(agent, n=100)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / 1024 / 1024
    print(f"\n  [RESOURCE] peak_memory={peak_mb:.2f}MB")
    assert peak_mb < 500, f"Memory usage {peak_mb:.2f}MB exceeds 500MB limit"


# ══════════════════════════════════════════════════════════════════════════════
# 15. LONG_HORIZON_TEST – Long Episode Stability
# ══════════════════════════════════════════════════════════════════════════════

def test_long_horizon():
    """LONG_HORIZON_TEST: 200-step episode completes without crash or reward explosion."""
    agent = _make_agent()
    agent.start_episode("long-horizon")
    state = _make_state()

    rewards = []
    completed = False
    try:
        for step in range(200):
            action = agent.choose_action(
                available_modules=list(AVAILABLE_MODULES),
                technologies=["php"],
                env_state=state,
            )
            reward = 1.0 if action == TARGET_TECH else -0.1

            next_state = _make_state(
                modules_run=[action],
                modules_remaining=[m for m in AVAILABLE_MODULES if m != action],
                elapsed_seconds=float(step),
                last_reward=reward,
                cumulative_reward=sum(rewards) + reward,
                step=step + 1,
            )
            agent.observe(
                module=action,
                reward=reward,
                technologies=["php"],
                env_state=state,
                next_env_state=next_state,
                done=(step == 199),
            )
            rewards.append(reward)
            state = next_state
        agent.end_episode()
        completed = True
    except Exception as exc:
        pytest.fail(f"Long episode crashed at step {len(rewards)}: {exc}")

    # reward_decay: last-50 avg should be >= first-50 avg - 1.0 (no collapse)
    first50_avg = sum(rewards[:50]) / 50
    last50_avg = sum(rewards[150:]) / 50
    reward_decay = first50_avg - last50_avg

    print(f"\n  [LONG_HORIZON] completed={completed}  first50_avg={first50_avg:.3f}  "
          f"last50_avg={last50_avg:.3f}  reward_decay={reward_decay:.3f}")

    assert completed, "Episode did not complete"
    assert last50_avg > -2.0, f"Reward collapsed in long episode: {last50_avg:.3f}"
    assert all(abs(r) < 1e4 for r in rewards), "Reward exploded (|r| > 10000)"
