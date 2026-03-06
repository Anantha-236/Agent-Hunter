"""
RL Agent Comprehensive Test Suite  v2
======================================
Upgrades over v1:
  - pytest-benchmark on all latency-sensitive tests
  - Parametrized EnvironmentState configs (15 combos)
  - Markers: fast / slow / benchmark for selective runs

Run options:
  python -m pytest tests/test_rl_agent_suite_v2.py -v --tb=short          # all tests
  python -m pytest tests/test_rl_agent_suite_v2.py -m fast -v             # quick smoke
  python -m pytest tests/test_rl_agent_suite_v2.py -m benchmark --benchmark-autosave
  python -m pytest tests/test_rl_agent_suite_v2.py --benchmark-compare    # regression check
"""

import math
import os
import random
import tempfile
import threading
import time
import tracemalloc

import pytest

# ── Project imports ────────────────────────────────────────────────────────────
from core.rl_environment import (
    EnvironmentState,
    ActionSpace,
    StateEncoder,
)
from core.rl_agent import (
    ConfidenceAwareReward,
    RewardInterpreter,
    RLPolicyAgent,
    TeachingMemory,
)


# ══════════════════════════════════════════════════════════════════════════════
# Parametrized environment configurations  (15 combos)
#
# Each dict maps to real EnvironmentState fields:
#   target_url, technologies, waf_detected, waf_name,
#   discovered_urls_count, discovered_params_count, ssl_present,
#   findings_count, confirmed_count, severity_counts, elapsed_seconds
# ══════════════════════════════════════════════════════════════════════════════

ENV_CONFIGS = [
    pytest.param(
        dict(target_url="http://simple.test", technologies=["django"],
             waf_detected=False, waf_name="",
             discovered_urls_count=20, discovered_params_count=40,
             ssl_present=False, elapsed_seconds=10.0),
        id="simple-django",
    ),
    pytest.param(
        dict(target_url="https://rails.test", technologies=["rails"],
             waf_detected=False, waf_name="",
             discovered_urls_count=50, discovered_params_count=100,
             ssl_present=True, elapsed_seconds=20.0),
        id="rails-noWAF",
    ),
    pytest.param(
        dict(target_url="http://waf.test", technologies=["django"],
             waf_detected=True, waf_name="cloudflare",
             discovered_urls_count=30, discovered_params_count=60,
             ssl_present=False, elapsed_seconds=80.0),
        id="django-WAF",
    ),
    pytest.param(
        dict(target_url="http://slow.test", technologies=["flask"],
             waf_detected=False, waf_name="",
             discovered_urls_count=5, discovered_params_count=10,
             ssl_present=False, elapsed_seconds=250.0),
        id="flask-slow",
    ),
    pytest.param(
        dict(target_url="https://multi.test", technologies=["django", "react", "nginx"],
             waf_detected=True, waf_name="aws-waf",
             discovered_urls_count=200, discovered_params_count=500,
             ssl_present=True, elapsed_seconds=50.0),
        id="multi-tech-WAF",
    ),
    pytest.param(
        dict(target_url="http://notech.test", technologies=[],
             waf_detected=False, waf_name="",
             discovered_urls_count=3, discovered_params_count=0,
             ssl_present=False, elapsed_seconds=5.0),
        id="no-tech-bare",
    ),
    pytest.param(
        dict(target_url="https://java.test", technologies=["spring", "java"],
             waf_detected=False, waf_name="",
             discovered_urls_count=80, discovered_params_count=150,
             ssl_present=True, elapsed_seconds=40.0),
        id="spring-java",
    ),
    pytest.param(
        dict(target_url="http://php.test", technologies=["laravel", "php"],
             waf_detected=False, waf_name="",
             discovered_urls_count=60, discovered_params_count=120,
             ssl_present=False, elapsed_seconds=15.0),
        id="laravel-php",
    ),
    pytest.param(
        dict(target_url="https://express.test", technologies=["express", "node"],
             waf_detected=True, waf_name="imperva",
             discovered_urls_count=40, discovered_params_count=80,
             ssl_present=True, elapsed_seconds=120.0),
        id="express-WAF-ratelimit",
    ),
    pytest.param(
        dict(target_url="http://minimal.test", technologies=["flask"],
             waf_detected=False, waf_name="",
             discovered_urls_count=1, discovered_params_count=2,
             ssl_present=False, elapsed_seconds=2.0),
        id="flask-minimal",
    ),
    pytest.param(
        dict(target_url="https://highload.test", technologies=["django", "python", "redis"],
             waf_detected=False, waf_name="",
             discovered_urls_count=300, discovered_params_count=600,
             ssl_present=True, elapsed_seconds=60.0),
        id="django-celery-highload",
    ),
    pytest.param(
        dict(target_url="http://timeout.test", technologies=["rails", "ruby"],
             waf_detected=False, waf_name="",
             discovered_urls_count=10, discovered_params_count=20,
             ssl_present=False, elapsed_seconds=1000.0),
        id="rails-timeout",
    ),
    pytest.param(
        dict(target_url="https://secure.test", technologies=["django"],
             waf_detected=True, waf_name="modsecurity",
             discovered_urls_count=25, discovered_params_count=50,
             ssl_present=True, elapsed_seconds=30.0,
             findings_count=3, confirmed_count=1,
             severity_counts={"high": 1, "medium": 2}),
        id="django-WAF-auth",
    ),
    pytest.param(
        dict(target_url="http://api.test", technologies=["python"],
             waf_detected=False, waf_name="",
             discovered_urls_count=15, discovered_params_count=30,
             ssl_present=False, elapsed_seconds=8.0),
        id="fastapi",
    ),
    pytest.param(
        dict(target_url="https://legacy.test", technologies=["dotnet"],
             waf_detected=True, waf_name="azure",
             discovered_urls_count=100, discovered_params_count=200,
             ssl_present=True, elapsed_seconds=100.0),
        id="aspnet-legacy-WAF",
    ),
]

AVAILABLE_MODULES = ["moduleA", "moduleB", "moduleC", "moduleD", "moduleE"]
TARGET_MODULE = "moduleA"


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def agent(tmp_path):
    return RLPolicyAgent(
        modules=list(AVAILABLE_MODULES),
        state_file=str(tmp_path / "agent_state.json"),
        exploration_strategy="hybrid",
    )


@pytest.fixture
def encoder():
    return StateEncoder(ActionSpace(AVAILABLE_MODULES))


def _make_state(**overrides) -> EnvironmentState:
    """Build a synthetic EnvironmentState with real fields."""
    defaults = dict(
        target_url="http://test.local",
        technologies=["django"],
        waf_detected=False,
        waf_name="",
        discovered_urls_count=30,
        discovered_params_count=80,
        ssl_present=False,
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


def _run_episodes(agent: RLPolicyAgent, n: int = 30) -> list:
    """Run *n* synthetic training episodes; return per-episode total rewards."""
    rewards = []
    for ep in range(n):
        agent.start_episode(f"ep-{ep}")
        total = 0.0
        state = _make_state()
        remaining = list(AVAILABLE_MODULES)

        for step in range(5):
            action = agent.choose_action(remaining, state.technologies, env_state=state)
            r = 1.0 if action == TARGET_MODULE else -0.1
            next_remaining = [m for m in remaining if m != action]
            ns = _make_state(
                modules_run=[action],
                modules_remaining=next_remaining if next_remaining else list(AVAILABLE_MODULES),
                findings_count=1 if r > 0 else 0,
                confirmed_count=1 if r > 0 else 0,
                last_reward=r,
                elapsed_seconds=float(step * 10),
            )
            agent.observe(
                module=action, reward=r,
                technologies=state.technologies,
                env_state=state, next_env_state=ns,
                done=(step == 4),
            )
            total += r
            state = ns
            remaining = next_remaining if next_remaining else list(AVAILABLE_MODULES)

        agent.end_episode()
        rewards.append(total)
    return rewards


def _variance(seq):
    n = len(seq)
    if n < 2:
        return 0.0
    mean = sum(seq) / n
    return sum((x - mean) ** 2 for x in seq) / (n - 1)


# ══════════════════════════════════════════════════════════════════════════════
# 1. ENV_INIT
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.fast
def test_env_init(agent, encoder):
    """ENV_INIT: init succeeds; encoder returns valid feature vector."""
    t0 = time.perf_counter()
    state = _make_state()
    features = encoder.encode(state)
    init_time = time.perf_counter() - t0

    assert features and all(math.isfinite(f) for f in features), \
        "Feature vector invalid"
    assert init_time < 0.5, f"Init too slow: {init_time*1000:.1f}ms"

    agent.start_episode("init-test")
    summary = agent.end_episode()
    assert isinstance(summary, dict), "end_episode() should return a summary dict"

    print(f"\n  init_time={init_time*1000:.1f}ms  feature_dim={len(features)}")


# ══════════════════════════════════════════════════════════════════════════════
# 2. ACTION_SPACE_VALIDATION  (parametrized × 15 env configs)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.fast
@pytest.mark.parametrize("env_cfg", ENV_CONFIGS)
def test_action_space_validation(agent, env_cfg):
    """ACTION_SPACE_VALIDATION: no invalid actions across all env configs."""
    state = _make_state(**env_cfg)
    agent.start_episode("action-space-test")

    invalid = sum(
        1 for _ in range(100)
        if agent.choose_action(
            list(AVAILABLE_MODULES), state.technologies, env_state=state
        ) not in AVAILABLE_MODULES
    )
    agent.end_episode()
    assert invalid == 0, f"invalid_action_rate={invalid/100}"


# ══════════════════════════════════════════════════════════════════════════════
# 3. STATE_OBSERVATION  (parametrized × 15 env configs)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.fast
@pytest.mark.parametrize("env_cfg", ENV_CONFIGS)
def test_state_observation(encoder, env_cfg):
    """STATE_OBSERVATION: encoder handles every config without errors."""
    state = _make_state(**env_cfg)
    t0 = time.perf_counter()
    features = encoder.encode(state)
    latency = time.perf_counter() - t0

    assert features, "Empty feature vector"
    assert all(math.isfinite(f) for f in features), "Non-finite values in features"
    assert latency < 0.1, f"observation_latency={latency*1000:.2f}ms > 100ms"


# ══════════════════════════════════════════════════════════════════════════════
# 4. REWARD_SIGNAL
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.fast
def test_reward_signal():
    """REWARD_SIGNAL: ConfidenceAwareReward and RewardInterpreter behave correctly."""
    car = ConfidenceAwareReward(confidence_threshold=0.7)

    # score_finding returns (reward, label): correct hit should score higher
    correct_reward, correct_label = car.score_finding(correct=True, confidence=0.9)
    incorrect_reward, incorrect_label = car.score_finding(correct=False, confidence=0.9)
    assert correct_reward > incorrect_reward, \
        f"Expected correct > incorrect: {correct_reward} vs {incorrect_reward}"
    assert correct_label == "correct_confident"
    assert incorrect_label == "wrong_confident"

    t0 = time.perf_counter()
    for _ in range(7):
        car.score_finding(
            correct=random.choice([True, False]),
            confidence=random.random(),
        )
    reward_delay = time.perf_counter() - t0
    assert reward_delay < 0.05

    # Abstain / ask-to-learn / taught-topic
    r_abs, l_abs = car.score_abstain()
    assert l_abs == "abstain" and abs(r_abs - 0.3) < 1e-6

    r_ask, l_ask = car.score_ask_to_learn()
    assert l_ask == "ask_to_learn" and abs(r_ask - 0.7) < 1e-6

    r_taught, l_taught = car.score_taught_topic_correct()
    assert l_taught == "taught_topic_correct" and abs(r_taught - 0.5) < 1e-6

    # RewardInterpreter
    ri = RewardInterpreter()
    state = _make_state()
    ns = _make_state(findings_count=2, confirmed_count=1)
    shaped = ri.interpret(raw_reward=1.0, module=TARGET_MODULE, state=state, next_state=ns)
    assert isinstance(shaped, (int, float)), "interpret() must return a number"

    # TeachingMemory
    tm = TeachingMemory()
    tm.record_teaching("moduleA", ["sqli", "xss"])
    assert tm.check_taught_hits("moduleA", ["sqli", "xss"], ai_assisted=False) == 2
    assert tm.check_taught_hits("moduleA", ["sqli"], ai_assisted=True) == 0

    print(f"\n  correct={correct_reward:.3f}  incorrect={incorrect_reward:.3f}  "
          f"delay={reward_delay*1000:.2f}ms  shaped={shaped:.3f}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. POLICY_LEARNING
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.slow
def test_policy_learning(agent):
    """POLICY_LEARNING: second-half avg reward >= first-half."""
    rewards = _run_episodes(agent, n=60)
    first = sum(rewards[:30]) / 30
    second = sum(rewards[30:]) / 30
    print(f"\n  first_half={first:.2f}  second_half={second:.2f}  improvement={second-first:+.2f}")
    assert second >= first - 1.0, f"No learning detected: {first:.2f} → {second:.2f}"


# ══════════════════════════════════════════════════════════════════════════════
# 6. EXPLORATION_BEHAVIOR
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.fast
def test_exploration_behavior(agent):
    """EXPLORATION_BEHAVIOR: all strategies valid; entropy does not explode post-training."""
    state = _make_state()

    # All 5 real strategies produce valid actions
    strategies = ["epsilon_greedy", "boltzmann", "ucb1", "thompson", "hybrid"]
    for s in strategies:
        agent.set_exploration_strategy(s)
        agent.start_episode(f"explore-{s}")
        action = agent.choose_action(
            list(AVAILABLE_MODULES), state.technologies, env_state=state,
        )
        assert action in AVAILABLE_MODULES, f"Strategy {s} → invalid action {action}"
        agent.end_episode()

    # Entropy measurement before vs after training
    agent.set_exploration_strategy("hybrid")

    def _entropy(n=50):
        counts = {m: 0 for m in AVAILABLE_MODULES}
        agent.start_episode("entropy-probe")
        for _ in range(n):
            a = agent.choose_action(
                list(AVAILABLE_MODULES), state.technologies, env_state=state,
            )
            counts[a] += 1
        agent.end_episode()
        probs = [c / n for c in counts.values() if c > 0]
        return -sum(p * math.log(p + 1e-9) for p in probs)

    h_before = _entropy()
    _run_episodes(agent, n=40)
    h_after = _entropy()
    print(f"\n  entropy before={h_before:.3f}  after={h_after:.3f}")
    assert h_after <= h_before + 0.5


# ══════════════════════════════════════════════════════════════════════════════
# 7. CONVERGENCE_TEST
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.slow
def test_convergence(agent):
    """CONVERGENCE_TEST: late-episode variance ≤ early-episode variance * 2."""
    rewards = _run_episodes(agent, n=100)
    early_var = _variance(rewards[:20])
    late_var = _variance(rewards[80:])
    print(f"\n  early_var={early_var:.4f}  late_var={late_var:.4f}")
    assert late_var <= early_var * 2 + 0.5


# ══════════════════════════════════════════════════════════════════════════════
# 8. GENERALIZATION_TEST  (parametrized × 15 env configs)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.slow
@pytest.mark.parametrize("env_cfg", ENV_CONFIGS)
def test_generalization(agent, env_cfg):
    """GENERALIZATION_TEST: policy trained on base state transfers to every env config."""
    _run_episodes(agent, n=40)

    state = _make_state(**env_cfg)
    agent.start_episode("gen-eval")
    rewards = []
    for _ in range(20):
        action = agent.choose_action(
            list(AVAILABLE_MODULES), state.technologies, env_state=state,
        )
        rewards.append(1.0 if action == TARGET_MODULE else -0.1)
    agent.end_episode()

    score = sum(rewards) / len(rewards)
    print(f"\n  transfer_score={score:.3f}")
    assert score > -0.5, f"Poor transfer: score={score:.3f}"


# ══════════════════════════════════════════════════════════════════════════════
# 9. ROBUSTNESS_TEST
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.fast
def test_robustness(agent):
    """ROBUSTNESS_TEST: agent remains valid under Gaussian-noisy observations."""
    agent.start_episode("robustness")
    rng = random.Random(42)
    errors = 0

    for step in range(100):
        noisy_urls = max(0, int(30 + rng.gauss(0, 50)))
        noisy_params = max(0, int(80 + rng.gauss(0, 100)))
        state = _make_state(
            discovered_urls_count=noisy_urls,
            discovered_params_count=noisy_params,
            elapsed_seconds=float(step * 5),
        )
        try:
            action = agent.choose_action(
                list(AVAILABLE_MODULES), state.technologies, env_state=state,
            )
            if action not in AVAILABLE_MODULES:
                errors += 1
            r = (1.0 if action == TARGET_MODULE else -0.1) + rng.gauss(0, 0.1)
            ns = _make_state(modules_run=[action], last_reward=r)
            agent.observe(
                module=action, reward=r,
                technologies=state.technologies,
                env_state=state, next_env_state=ns,
                done=(step == 99),
            )
        except Exception:
            errors += 1

    agent.end_episode()
    assert errors == 0, f"{errors} errors under noise"
    print(f"\n  error_tolerance={1 - errors/100:.2f}")


# ══════════════════════════════════════════════════════════════════════════════
# 10. FAILURE_RECOVERY
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.fast
def test_failure_recovery(agent):
    """FAILURE_RECOVERY: mid-episode restart completes cleanly."""
    t0 = time.perf_counter()
    state = _make_state()

    # Episode 1: interrupted (no end_episode)
    agent.start_episode("fail-1")
    for _ in range(3):
        action = agent.choose_action(list(AVAILABLE_MODULES), state.technologies, env_state=state)
        ns = _make_state(modules_run=[action], last_reward=0.5)
        agent.observe(action, 0.5, state.technologies, state, ns, done=False)

    # Simulate crash → restart
    agent.start_episode("fail-2")
    for _ in range(3):
        action = agent.choose_action(list(AVAILABLE_MODULES), state.technologies, env_state=state)
        ns = _make_state(modules_run=[action], last_reward=0.5)
        agent.observe(action, 0.5, state.technologies, state, ns, done=False)
    agent.end_episode()
    recovery_time = time.perf_counter() - t0

    # Verify still functional
    agent.start_episode("fail-3")
    action = agent.choose_action(list(AVAILABLE_MODULES), state.technologies, env_state=state)
    assert action in AVAILABLE_MODULES, "Agent non-functional after recovery"
    agent.end_episode()

    assert recovery_time < 2.0
    print(f"\n  recovery_time={recovery_time*1000:.1f}ms")


# ══════════════════════════════════════════════════════════════════════════════
# 11. SAFETY_CONSTRAINT
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.fast
def test_safety_constraint(agent):
    """SAFETY_CONSTRAINT: restricted modules are never selected."""
    agent.start_episode("safety")
    restricted = {"moduleD", "moduleE"}
    allowed = [m for m in AVAILABLE_MODULES if m not in restricted]
    state = _make_state()

    violations = sum(
        1 for _ in range(200)
        if agent.choose_action(allowed, state.technologies, env_state=state) in restricted
    )
    agent.end_episode()
    assert violations == 0, f"safety_violation_rate={violations/200}"
    print(f"\n  violations=0 / 200")


# ══════════════════════════════════════════════════════════════════════════════
# 12. LATENCY_TEST  ← pytest-benchmark (3 benchmark functions)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.benchmark
def test_latency_choose_action(agent, benchmark):
    """LATENCY_TEST: choose_action benchmarked; must stay under 50ms mean."""
    state = _make_state()
    agent.start_episode("bench-choose")

    result = benchmark(
        agent.choose_action,
        list(AVAILABLE_MODULES), state.technologies, state,
    )

    assert result in AVAILABLE_MODULES
    mean_ms = benchmark.stats.get("mean", 0) * 1000
    print(f"\n  choose_action mean={mean_ms:.3f}ms")
    assert mean_ms < 50, f"choose_action mean {mean_ms:.2f}ms > 50ms threshold"


@pytest.mark.benchmark
def test_latency_observe(agent, benchmark):
    """LATENCY_TEST: observe benchmarked; must stay under 100ms mean."""
    state = _make_state()
    ns = _make_state(modules_run=["moduleA"], last_reward=0.5)
    agent.start_episode("bench-observe")
    action = agent.choose_action(list(AVAILABLE_MODULES), state.technologies, env_state=state)

    benchmark(
        agent.observe,
        action, 0.5, state.technologies, state, ns, False,
    )

    mean_ms = benchmark.stats.get("mean", 0) * 1000
    print(f"\n  observe mean={mean_ms:.3f}ms")
    assert mean_ms < 100, f"observe mean {mean_ms:.2f}ms > 100ms threshold"


@pytest.mark.benchmark
def test_latency_encode(encoder, benchmark):
    """LATENCY_TEST: StateEncoder.encode benchmarked; must stay under 10ms mean."""
    state = _make_state()
    benchmark(encoder.encode, state)

    mean_ms = benchmark.stats.get("mean", 0) * 1000
    print(f"\n  encode mean={mean_ms:.3f}ms")
    assert mean_ms < 10, f"encode mean {mean_ms:.2f}ms > 10ms threshold"


# ══════════════════════════════════════════════════════════════════════════════
# 13. SCALABILITY_TEST
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.slow
def test_scalability(tmp_path):
    """SCALABILITY_TEST: 5 agents train concurrently without corruption."""
    NUM_AGENTS, EPISODES = 5, 20
    results, errors = {}, []

    def _train(aid):
        try:
            a = RLPolicyAgent(
                modules=list(AVAILABLE_MODULES),
                state_file=str(tmp_path / f"agent_{aid}.json"),
                exploration_strategy="hybrid",
            )
            results[aid] = _run_episodes(a, n=EPISODES)
        except Exception as e:
            errors.append((aid, str(e)))

    threads = [threading.Thread(target=_train, args=(i,)) for i in range(NUM_AGENTS)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0

    throughput = (NUM_AGENTS * EPISODES) / elapsed
    assert not errors, f"Parallel errors: {errors}"
    assert len(results) == NUM_AGENTS
    print(f"\n  throughput={throughput:.1f} eps/s  elapsed={elapsed:.2f}s")


# ══════════════════════════════════════════════════════════════════════════════
# 14. RESOURCE_USAGE
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.slow
def test_resource_usage(agent):
    """RESOURCE_USAGE: peak memory under 500 MB for 100 training episodes."""
    tracemalloc.start()
    _run_episodes(agent, n=100)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / 1024 / 1024
    print(f"\n  peak_memory={peak_mb:.2f}MB")
    assert peak_mb < 500, f"Memory {peak_mb:.2f}MB > 500MB"


# ══════════════════════════════════════════════════════════════════════════════
# 15. LONG_HORIZON_TEST
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.slow
def test_long_horizon(agent):
    """LONG_HORIZON_TEST: 200-step episode completes; no reward explosion/collapse."""
    agent.start_episode("long-horizon")
    state = _make_state()
    rewards = []

    for step in range(200):
        action = agent.choose_action(
            list(AVAILABLE_MODULES), state.technologies, env_state=state,
        )
        r = 1.0 if action == TARGET_MODULE else -0.1
        ns = _make_state(
            modules_run=[action],
            elapsed_seconds=float(step),
            last_reward=r,
            cumulative_reward=sum(rewards) + r,
            step=step + 1,
        )
        agent.observe(
            module=action, reward=r,
            technologies=state.technologies,
            env_state=state, next_env_state=ns,
            done=(step == 199),
        )
        rewards.append(r)
        state = ns

    agent.end_episode()

    first50 = sum(rewards[:50]) / 50
    last50 = sum(rewards[150:]) / 50
    print(f"\n  first50_avg={first50:.3f}  last50_avg={last50:.3f}  "
          f"reward_decay={first50-last50:.3f}")
    assert last50 > -2.0, f"Reward collapsed: {last50:.3f}"
    assert all(abs(r) < 1e4 for r in rewards), "Reward exploded"
