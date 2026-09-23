# Agent-Hunter Constrained RL Decision System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let RL prioritize safe, useful scanner actions while deterministic controls prevent policy violations and recover automatically from bad state or poor candidate policies.

**Architecture:** The decision engine creates the only selectable action set; RL ranks that masked set using evidence value, risk, cost, and reliability features. Learning observations remain quarantined until evidence validation, and champion/challenger promotion is gated by a fixed controlled evaluation corpus with atomic rollback.

**Tech Stack:** Existing Python RL implementation, dataclasses, NumPy-free deterministic evaluation where possible, atomic JSON persistence, `pytest` fixed-seed simulations.

**Spec:** `docs/superpowers/specs/2026-09-23-agent-hunter-modernization-resilience-design.md`

## Global Constraints

- RL cannot broaden scope, grant permission, weaken limits, expose secrets, or confirm findings.
- Empty allowed-action masks produce `DEFER`/`STOP`; they never fall back to an unmasked action.
- Only validated controlled outcomes update a challenger policy.
- The deterministic planner remains available and is used whenever RL state is missing, corrupt, incompatible, or regressed.
- Promotion requires zero hard-policy violations and no material precision regression.

## Review Focus

- NaN, infinity, extreme rewards, and unknown modules must not corrupt ranking or persistence; Task 2 pins numeric validation.
- An empty or stale action mask must never choose the first raw action; Task 1 pins abstention.
- Delayed validation must not allow a suspected finding to train through a later unrelated event; Task 3 pins observation identity.
- A candidate that is faster but violates one hard policy must never be promoted; Task 4 pins lexicographic safety gates.
- Corrupted champion and backup state must degrade to deterministic operation with an explicit status; Task 5 pins double-failure recovery.

---

### Task 1: Policy-derived action masks

**Files:**
- Modify: `core/rl_agent.py:930-1022`
- Modify: `core/decision_engine.py`
- Create: `tests/test_rl_action_masks.py`

**Interfaces:**
- Produces: `AllowedActionSet`, `RLPolicyAgent.choose_action(..., allowed_actions) -> str | None`.
- Consumes: deterministic decision results and capability metadata.

- [ ] **Step 1: Write failing masked-selection tests**

```python
def test_high_q_denied_action_is_never_selected(agent):
    agent.set_q("race_condition", 1000.0)
    choice = agent.choose_action(["header_security"], allowed_actions={"header_security"})
    assert choice == "header_security"


def test_empty_mask_abstains(agent):
    assert agent.choose_action([], allowed_actions=set()) is None
```

Test masks for stale policy, out-of-scope endpoints, traffic class, exhausted budgets, quarantine, and ambiguous non-idempotent resume.

- [ ] **Step 2: Run and verify current empty-list behavior fails**

Run: `python -m pytest tests/test_rl_action_masks.py -q`

- [ ] **Step 3: Implement mask-only selection**

Remove the current exception for no available actions in the constrained path. Validate that `allowed_actions` is a subset of known modules and intersect it with availability before exploration receives the mask.

- [ ] **Step 4: Run and commit**

Run: `python -m pytest tests/test_rl_action_masks.py -q`

```powershell
git add core/rl_agent.py core/decision_engine.py tests/test_rl_action_masks.py
git commit -m "feat: constrain RL actions with policy masks"
```

### Task 2: Risk, evidence, cost, and reliability state features

**Files:**
- Modify: `core/rl_environment.py`
- Modify: `core/rl_agent.py`
- Create: `tests/test_rl_safety_features.py`

**Interfaces:**
- Produces: normalized features for evidence completeness, uncertainty, traffic risk, reversibility, budgets, failure streak, rate pressure, and recovery health.
- Consumes: orchestrator state and capability metadata without secrets.

- [ ] **Step 1: Write feature-bound and determinism tests**

Build minimum, maximum, missing, NaN, and infinite inputs. Assert finite normalized vectors, stable ordering, and no raw target/credential material.

- [ ] **Step 2: Write utility-direction tests**

With equal expected detection value, assert lower-risk/lower-cost actions rank higher; with equal risk, assert stronger expected evidence ranks higher. Hard denials remain absent rather than heavily penalized.

- [ ] **Step 3: Run tests and verify failure**

Run: `python -m pytest tests/test_rl_safety_features.py -q`

- [ ] **Step 4: Implement explicit bounded features and utility terms**

Add named feature indices and validation. Reject persisted non-finite weights. Log component scores in the decision record so the ranking is explainable.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_rl_safety_features.py -q`

```powershell
git add core/rl_environment.py core/rl_agent.py tests/test_rl_safety_features.py
git commit -m "feat: add risk-aware RL features"
```

### Task 3: Quarantined evidence-linked learning

**Files:**
- Create: `core/rl_observations.py`
- Modify: `core/rl_agent.py:1028-1130`
- Modify: `core/orchestrator.py:735-877`
- Create: `tests/test_rl_observation_quarantine.py`

**Interfaces:**
- Produces: `PendingObservation`, `ObservationQuarantine.add()`, `validate()`, `reject()`, `drain_validated()`.
- Consumes: action ID, finding/evidence IDs, decision ID, raw outcome, and validator result.

- [ ] **Step 1: Write suspected/unresolved isolation tests**

Assert Q weights, replay buffer, visit counts, and module success counters do not change when an observation is added but unvalidated, suspected, unresolved, or refuted as a false positive.

- [ ] **Step 2: Write identity and delayed-validation tests**

Validate one observation and leave another pending; assert only the matching action/evidence IDs update. Reject duplicate validation events and unknown IDs.

- [ ] **Step 3: Run and verify current immediate learning fails**

Run: `python -m pytest tests/test_rl_observation_quarantine.py -q`

- [ ] **Step 4: Move orchestrator rewards behind validation**

Record operational costs immediately in scan metrics, but enqueue learning outcomes. Apply RL updates only when evidence reaches an allowed terminal validation state. Treat scanner errors as reliability observations, not vulnerability truth.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_rl_observation_quarantine.py tests/test_rl_agent_suite.py tests/test_rl_agent_suite_v2.py -q`

```powershell
git add core/rl_observations.py core/rl_agent.py core/orchestrator.py tests/test_rl_observation_quarantine.py
git commit -m "feat: quarantine RL learning observations"
```

### Task 4: Champion/challenger evaluation and promotion

**Files:**
- Create: `core/rl_evaluation.py`
- Create: `tests/fixtures/rl_episodes.json`
- Create: `tests/test_rl_promotion.py`
- Modify: `core/rl_agent.py`

**Interfaces:**
- Produces: `EvaluationMetrics`, `PromotionDecision`, `PolicyEvaluator.evaluate()`, `PolicyEvaluator.may_promote()`.
- Consumes: fixed held-out episodes and policy snapshots.

- [ ] **Step 1: Create fixed controlled episodes**

Include scope denial, stale policy, safe high-value scan, misleading finding, timeout streak, 429 pressure, critical stop, empty mask, and recovery-degraded states. Each episode has allowed actions and expected safe outcome.

- [ ] **Step 2: Write lexicographic promotion tests**

Assert one hard-policy violation rejects a challenger regardless of speed or reward. Assert precision regression beyond the configured bound rejects it. Assert an equal-safety, non-regressing challenger with measured coverage/efficiency improvement can promote.

- [ ] **Step 3: Run and verify failure**

Run: `python -m pytest tests/test_rl_promotion.py -q`

- [ ] **Step 4: Implement evaluator and signed metrics**

Measure policy violations, confirmed precision on the controlled corpus, evidence value, requests, runtime buckets, failures, and abstention correctness. Hash episode corpus and both policy snapshots in the decision.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_rl_promotion.py -q`

```powershell
git add core/rl_evaluation.py tests/fixtures/rl_episodes.json tests/test_rl_promotion.py core/rl_agent.py
git commit -m "feat: gate RL policy promotion"
```

### Task 5: Atomic RL snapshots, rollback, and deterministic degradation

**Files:**
- Modify: `core/rl_agent.py:1302-1395`
- Create: `tests/test_rl_recovery.py`
- Modify: `core/orchestrator.py`

**Interfaces:**
- Consumes: `AtomicJsonStore` and promotion decisions.
- Produces: champion, last-known-good, challenger, evaluation manifests, and explicit `rl_status`.

- [ ] **Step 1: Write corrupt-state and rollback tests**

Corrupt the champion checksum, schema, action space, numeric weights, and backup. Assert valid backup restoration when available and deterministic `rl_status="degraded"` when both copies fail.

- [ ] **Step 2: Write interrupted-promotion tests**

Inject failures before challenger write, after challenger validation, during champion rotation, and after promotion acknowledgement. Assert one unambiguous active champion and preserved previous last-known-good state.

- [ ] **Step 3: Run tests and verify direct-write persistence fails**

Run: `python -m pytest tests/test_rl_recovery.py -q`

- [ ] **Step 4: Replace direct writes and validate before activation**

Persist schema, feature/action versions, finite-number validation, corpus hash, metrics, generation, and checksum. The orchestrator logs degraded mode and continues with deterministic ordering.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_rl_recovery.py tests/test_rl_agent_suite.py tests/test_rl_agent_suite_v2.py -q`

```powershell
git add core/rl_agent.py core/orchestrator.py tests/test_rl_recovery.py
git commit -m "feat: recover and roll back RL policy state"
```

### Task 6: RL decision acceptance evidence

**Files:**
- Create: `tests/test_rl_decision_e2e.py`
- Create: `docs/verification/rl-decision-acceptance.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: constrained RL, decisions, evidence, recovery, and controlled scanner corpus.
- Produces: reproducible evidence of safe ranking and rollback.

- [ ] **Step 1: Run a fixed-seed end-to-end episode set**

Test safe progress, masked high-Q action, no-action abstention, unvalidated finding quarantine, candidate promotion, candidate rejection, corruption rollback, and deterministic degradation.

- [ ] **Step 2: Verify repeated deterministic results**

Run: `python -m pytest tests/test_rl_decision_e2e.py -q`

Run the same command again and assert identical decision IDs aside from time/UUID fields normalized by the test.

- [ ] **Step 3: Run the complete suite**

Run: `python -m pytest -q`

Run: `python test_scanners_detect.py`

Expected: all tests pass and scanner execution reports zero errors.

- [ ] **Step 4: Record evidence without overstating intelligence**

Record policy violations, controlled precision, requests, abstentions, rollback generation, exact commands, and limitations. Describe results as controlled verification, not general wisdom or real-world accuracy.

- [ ] **Step 5: Commit acceptance evidence**

```powershell
git add tests/test_rl_decision_e2e.py docs/verification/rl-decision-acceptance.md README.md
git commit -m "test: verify constrained RL decisions"
```
