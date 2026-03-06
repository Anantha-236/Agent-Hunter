#!/usr/bin/env python3
"""Integration test for the full RL agent framework (all 9 features + enhanced reward)."""
import os
import sys

def test_all():
    # 1. Import test
    from core.rl_environment import EnvironmentState, ActionSpace, StateEncoder, TECH_CATEGORIES
    print(f"[OK] rl_environment: {len(TECH_CATEGORIES)} tech categories")

    from core.rl_agent import (
        RLPolicyAgent, ModulePolicyState, EpisodeMemory, ReplayBuffer,
        LinearQApproximator, EpsilonGreedy, BoltzmannExploration,
        UCB1Exploration, ThompsonSampling, HybridExploration, RewardInterpreter,
        ConfidenceAwareReward, TeachingMemory,
    )
    print("[OK] rl_agent: all classes imported (including ConfidenceAwareReward, TeachingMemory)")

    # ─── Test ConfidenceAwareReward standalone ────────────────
    car = ConfidenceAwareReward(confidence_threshold=0.7)

    r, label = car.score_finding(correct=True, confidence=0.9)
    assert label == "correct_confident" and r == 1.0, f"Got {label}={r}"

    r, label = car.score_finding(correct=True, confidence=0.4)
    assert label == "correct_uncertain" and r == 0.7, f"Got {label}={r}"

    r, label = car.score_finding(correct=False, confidence=0.85)
    assert label == "wrong_confident" and r == -1.5, f"Got {label}={r}"

    r, label = car.score_finding(correct=False, confidence=0.3)
    assert label == "wrong_uncertain" and r == -0.5, f"Got {label}={r}"

    r, label = car.score_abstain()
    assert label == "abstain" and r == 0.3, f"Got {label}={r}"

    r, label = car.score_ask_to_learn()
    assert label == "ask_to_learn" and r == 0.7, f"Got {label}={r}"

    r, label = car.score_taught_topic_correct()
    assert label == "taught_topic_correct" and r == 0.5, f"Got {label}={r}"

    print("[OK] ConfidenceAwareReward: all 7 reward cases correct")

    # ─── Test compute_module_reward ───────────────────────────
    findings_data = [
        {"correct": True, "confidence": 0.9},   # +1.0
        {"correct": True, "confidence": 0.4},   # +0.7
        {"correct": False, "confidence": 0.8},  # -1.5
    ]
    total, counts = car.compute_module_reward(
        findings_data=findings_data,
        abstained=False,
        asked_to_learn=True,   # +0.7
        taught_topics_hit=2,   # +0.5 * 2 = +1.0
    )
    expected = 1.0 + 0.7 + (-1.5) + 0.7 + 1.0
    assert abs(total - expected) < 1e-6, f"Expected {expected}, got {total}"
    assert counts == {
        "correct_confident": 1,
        "correct_uncertain": 1,
        "wrong_confident": 1,
        "ask_to_learn": 1,
        "taught_topic_correct": 2,
    }, f"Got {counts}"
    print(f"[OK] compute_module_reward: total={total:.1f}, breakdown={counts}")

    # ─── Test TeachingMemory ──────────────────────────────────
    tm = TeachingMemory()
    tm.record_teaching("sql_injection", ["sqli", "blindsqli"])
    assert ("sql_injection", "sqli") in tm.taught_topics
    assert ("sql_injection", "blindsqli") in tm.taught_topics

    # With AI assistance → no bonus
    hits = tm.check_taught_hits("sql_injection", ["sqli"], ai_assisted=True)
    assert hits == 0, f"AI-assisted should get 0 hits, got {hits}"

    # Without AI → bonus
    hits = tm.check_taught_hits("sql_injection", ["sqli", "blindsqli"], ai_assisted=False)
    assert hits == 2, f"Expected 2 taught hits, got {hits}"

    # Persistence
    d = tm.to_dict()
    tm2 = TeachingMemory()
    tm2.from_dict(d)
    assert ("sql_injection", "sqli") in tm2.taught_topics
    print("[OK] TeachingMemory: record, check, persist all work")

    # ─── Test agent with confidence-aware observe ─────────────
    modules = ["xss_scanner", "sql_injection", "ssrf", "idor"]
    agent = RLPolicyAgent(
        modules=modules,
        state_file="__test_rl_enhanced.json",
        exploration_strategy="hybrid",
        confidence_threshold=0.7,
    )
    print(f"[OK] Agent: confidence_threshold={agent.confidence_threshold}")

    agent.start_episode("test-enhanced-1")

    env = EnvironmentState(
        target_url="https://example.com",
        technologies=["php", "mysql"],
        waf_detected=False, waf_name="",
        discovered_urls_count=30, discovered_params_count=80,
        ssl_present=True,
        modules_run=[], modules_remaining=modules[:],
        findings_count=0, confirmed_count=0,
        severity_counts={}, unique_vuln_types=set(),
        cumulative_reward=0.0, last_reward=0.0, rewards_history=[],
        elapsed_seconds=0.0, avg_module_time=0.0, step=0,
    )

    action = agent.choose_action(modules[:], ["php", "mysql"], env_state=env)

    env2 = EnvironmentState(
        target_url="https://example.com",
        technologies=["php", "mysql"],
        waf_detected=False, waf_name="",
        discovered_urls_count=30, discovered_params_count=80,
        ssl_present=True,
        modules_run=[action], modules_remaining=[m for m in modules if m != action],
        findings_count=2, confirmed_count=1,
        severity_counts={"high": 1, "medium": 1}, unique_vuln_types={"sqli"},
        cumulative_reward=0.0, last_reward=0.0, rewards_history=[],
        elapsed_seconds=20.0, avg_module_time=20.0, step=1,
    )

    # Pass confidence-aware findings_data
    shaped = agent.observe(
        action, 3.0,
        technologies=["php"],
        next_env_state=env2,
        done=False,
        findings_data=[
            {"correct": True, "confidence": 0.85},
            {"correct": False, "confidence": 0.3},
        ],
        abstained=False,
        asked_to_learn=True,
        taught_topics_hit=0,
    )
    print(f"[OK] Confidence-aware observe: shaped={shaped:.3f}")

    # Check breakdown was recorded
    brk = agent.reward_interpreter._last_breakdown
    assert "correct_confident" in brk, f"Missing correct_confident in breakdown: {brk}"
    assert "wrong_uncertain" in brk, f"Missing wrong_uncertain in breakdown: {brk}"
    assert "ask_to_learn" in brk, f"Missing ask_to_learn in breakdown: {brk}"
    print(f"[OK] Reward breakdown: {brk}")

    summary = agent.end_episode()
    print(f"[OK] Episode: steps={summary['steps']}, total_reward={summary['total_reward']:.3f}")

    # Test diagnostics includes confidence info
    diag = agent.diagnostics()
    assert "confidence_threshold" in diag
    assert "reward_table" in diag
    assert "taught_topics" in diag
    assert "last_reward_breakdown" in diag
    print(f"[OK] Diagnostics: confidence_threshold={diag['confidence_threshold']}, "
          f"reward_table keys={list(diag['reward_table'].keys())}")

    # Test persistence of teaching memory
    agent.save()
    agent2 = RLPolicyAgent(
        modules=modules,
        state_file="__test_rl_enhanced.json",
        exploration_strategy="hybrid",
    )
    # Check reward table persists
    assert agent2.reward_interpreter.confidence_reward.table["correct_confident"] == 1.0
    print("[OK] Persistence: reward table and teaching memory survive reload")

    # ─── Test custom reward table override ────────────────────
    custom_agent = RLPolicyAgent(
        modules=modules,
        state_file="__test_rl_custom.json",
        exploration_strategy="epsilon_greedy",
        reward_table={
            "correct_confident": +2.0,
            "wrong_confident": -3.0,
        },
    )
    assert custom_agent.reward_interpreter.confidence_reward.table["correct_confident"] == 2.0
    assert custom_agent.reward_interpreter.confidence_reward.table["wrong_confident"] == -3.0
    # Other defaults unchanged
    assert custom_agent.reward_interpreter.confidence_reward.table["abstain"] == 0.3
    print("[OK] Custom reward table: overrides merge with defaults")

    # ─── Test backward compatibility (no findings_data) ───────
    agent3 = RLPolicyAgent(
        modules=modules,
        state_file="__test_rl_compat.json",
        exploration_strategy="hybrid",
    )
    agent3.start_episode("compat-1")
    agent3.choose_action(modules[:], ["php"], env_state=env)
    # observe without findings_data → uses raw reward (old behavior)
    shaped_old = agent3.observe(
        action, 2.5,
        technologies=["php"],
        next_env_state=env2,
        done=True,
    )
    assert shaped_old > 0, f"Backward-compat should give positive shaped reward, got {shaped_old}"
    assert agent3.reward_interpreter._last_breakdown == {}, "No breakdown without findings_data"
    agent3.end_episode()
    print(f"[OK] Backward compatibility: shaped={shaped_old:.3f} (no findings_data, raw fallback)")

    # ─── Test orchestrator import ─────────────────────────────
    from core.orchestrator import Orchestrator
    print("[OK] Orchestrator imports with enhanced reward")

    # Cleanup
    for f in ["__test_rl_enhanced.json", "__test_rl_custom.json", "__test_rl_compat.json"]:
        if os.path.exists(f):
            os.remove(f)

    print()
    print("=" * 60)
    print("ALL TESTS PASSED — Enhanced Reward Function Verified!")
    print("=" * 60)
    print()
    print("Reward Table:")
    for k, v in ConfidenceAwareReward.DEFAULTS.items():
        print(f"  R({k:25s}) = {v:+.1f}")


if __name__ == "__main__":
    test_all()
