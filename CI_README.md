# RL Agent Test Suite v2 — Quick Reference

## Setup

```powershell
pip install pytest-benchmark
```

## Run Tests

| Command | What It Does |
|---|---|
| `python -m pytest tests/test_rl_agent_suite_v2.py -v` | Run all tests |
| `python -m pytest tests/test_rl_agent_suite_v2.py -m fast -v` | Quick smoke tests only |
| `python -m pytest tests/test_rl_agent_suite_v2.py -m slow -v` | Training-loop tests only |
| `python -m pytest tests/test_rl_agent_suite_v2.py -m benchmark --benchmark-autosave` | Save benchmark baseline |
| `python -m pytest tests/test_rl_agent_suite_v2.py --benchmark-compare` | Compare against last baseline |

## CI Pipeline

```powershell
.\ci_local.ps1              # fast + slow tests
.\ci_local.ps1 -Fast        # only @fast (used by pre-commit hook)
.\ci_local.ps1 -Benchmark   # fast + benchmarks (saves results)
.\ci_local.ps1 -Full        # everything
.\ci_local.ps1 -Full -Compare   # everything + regression check
```

## Install Pre-Commit Hook

```powershell
.\ci_local.ps1 -Install
```

Blocks `git commit` if any `@fast` test fails.

## Test Markers

| Marker | Tests | Approx Time |
|---|---|---|
| `fast` | ENV_INIT, ACTION_SPACE (×15), STATE_OBS (×15), REWARD, EXPLORATION, ROBUSTNESS, FAILURE_RECOVERY, SAFETY | ~30s |
| `slow` | POLICY_LEARNING, CONVERGENCE, GENERALIZATION (×15), SCALABILITY, RESOURCE_USAGE, LONG_HORIZON | ~8 min |
| `benchmark` | choose_action, observe, encode latency | ~10s |

## Benchmark Thresholds

| Function | Max Mean Latency |
|---|---|
| `choose_action` | 50 ms |
| `observe` | 100 ms |
| `StateEncoder.encode` | 10 ms |
