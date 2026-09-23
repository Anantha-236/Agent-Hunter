# Agent-Hunter Bugcrowd Controlled Pilot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare and execute one tightly scoped Bugcrowd pilot only after Hunter passes all local acceptance gates and the current engagement brief is manually reviewed.

**Architecture:** A policy-snapshot importer converts a human-reviewed Bugcrowd brief into a fail-closed local policy. Dry-run planning and passive checks precede any safe-active request; evidence is reviewed locally and submission remains manual.

**Tech Stack:** Existing Agent-Hunter policy/orchestrator/reporting code, Python JSON/hashlib, `pytest`, official Bugcrowd researcher documentation and engagement brief.

**Spec:** `docs/superpowers/specs/2026-09-23-agent-hunter-modernization-resilience-design.md`

## Global Constraints

- Candidate: Bolt’s public Bugcrowd engagement, based only on Bugcrowd’s official June 4, 2025 launch announcement. This is provisional until its current authenticated engagement brief, status, safe-harbor level, targets, exclusions, and rules are reviewed on the day of testing.
- No traffic is sent merely because the candidate was publicly announced.
- If the authenticated brief is unavailable, paused, private, invitation-only, stale, ambiguous, or incompatible with automated scanning, select no target and stop the pilot.
- Only explicitly in-scope targets are authorized; discoveries and sibling hosts do not inherit scope.
- Bugcrowd account login, OTP/MFA, CAPTCHA, and final submission are manual.
- Default Bugcrowd exclusions and each program’s stricter rules are enforced; program-specific rules win.
- DoS, social engineering, credential attacks, brute force, data exfiltration, destructive actions, privacy-impacting access, and unapproved state changes are excluded.
- Reports and program details remain confidential under the applicable disclosure policy.

## Review Focus

- A program announced publicly in 2025 may be paused or have different scope in 2026; Task 1 requires a same-day authenticated snapshot.
- Wildcards, mobile backends, CDN hosts, and third-party integrations must not be inferred as in scope; Task 2 pins exact target parsing.
- Program rules may forbid automation or impose rates below Hunter defaults; Task 2 always selects the stricter bound.
- A redirect from an allowed host to an unlisted host must stop before the second request; Task 3 pins redirect handling.
- Finding evidence may include confidential or personal data; Task 4 requires minimization and human review before any submission draft leaves the local machine.

---

### Task 1: Local acceptance and same-day program eligibility gate

**Files:**
- Create: `core/program_snapshot.py`
- Create: `tests/test_program_snapshot.py`
- Create: `docs/pilots/bugcrowd/README.md`

**Interfaces:**
- Produces: `ProgramSnapshot`, `ProgramEligibility`, and `verify_acceptance_records()`.
- Consumes: committed Hunter acceptance records and manually entered current engagement-brief facts.

- [ ] **Step 1: Write failing acceptance-record tests**

Assert the pilot blocks when any foundation, SMTP, modern-scanner, or RL acceptance record is missing, refers to a different commit, or records a failed gate. SMTP readiness may be disabled, but a missing SMTP test result cannot be silently treated as passed.

- [ ] **Step 2: Write freshness and completeness tests**

```python
def test_snapshot_expires_before_testing_day_changes():
    snapshot = sample_snapshot(reviewed_at="2026-09-22T23:59:00Z")
    assert snapshot.is_current(date(2026, 9, 23)) is False


def test_ambiguous_automation_rule_blocks_active_testing():
    snapshot = sample_snapshot(automation_permission="unknown")
    assert snapshot.eligibility.active_testing_allowed is False
```

- [ ] **Step 3: Run tests and verify failure**

Run: `python -m pytest tests/test_program_snapshot.py -q`

- [ ] **Step 4: Implement fail-closed snapshots**

Require engagement URL, title, type, status, safe-harbor level, reviewed time, tester acknowledgment, disclosure rule, automation rule, rate limits, exact targets, out-of-scope entries, prohibited methods, eligible vulnerability classes, test-account requirements, contact path, and SHA-256 hash.

- [ ] **Step 5: Document the manual review procedure**

The operator signs in manually, opens the complete current brief, known issues, changelog, targets, engagement rules, testing instructions, safe-harbor indicator, and disclosure policy. No password or OTP is given to Agent-Hunter.

- [ ] **Step 6: Run and commit**

Run: `python -m pytest tests/test_program_snapshot.py -q`

```powershell
git add core/program_snapshot.py tests/test_program_snapshot.py docs/pilots/bugcrowd/README.md
git commit -m "feat: add bug bounty program snapshot gate"
```

### Task 2: Exact scope, prohibition, and rate policy import

**Files:**
- Create: `core/program_policy_import.py`
- Create: `tests/test_program_policy_import.py`
- Modify: `core/bbp_policy.py`

**Interfaces:**
- Produces: `import_program_snapshot(snapshot) -> BBPPolicy`.
- Consumes: complete `ProgramSnapshot`; refuses free-form ambiguous scope.

- [ ] **Step 1: Write exact-scope parsing tests**

Test exact host, exact URL prefix, wildcard, port, scheme, IDNA, IP range rejection, mobile-app identifiers, API paths, and third-party domains. Assert unspecified assets remain denied.

- [ ] **Step 2: Write stricter-rule composition tests**

Combine Hunter defaults, Bugcrowd general exclusions, and program rules. Assert the strictest rate, traffic class, vulnerability exclusion, and automation rule wins.

- [ ] **Step 3: Run tests and verify failure**

Run: `python -m pytest tests/test_program_policy_import.py -q`

- [ ] **Step 4: Implement typed import and policy hash binding**

Reject incomplete snapshots and preserve source text hashes/review timestamps. Bind the policy hash to checkpoints, evidence, decisions, and reports.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_program_policy_import.py tests/test_decision_engine.py -q`

```powershell
git add core/program_policy_import.py core/bbp_policy.py tests/test_program_policy_import.py
git commit -m "feat: import exact bug bounty scope rules"
```

### Task 3: Dry-run and passive-first pilot command

**Files:**
- Modify: `main.py`
- Modify: `core/orchestrator.py`
- Create: `tests/test_pilot_command.py`

**Interfaces:**
- Produces: `hunter pilot --policy <snapshot> --dry-run` and staged `--phase passive|safe-active` behavior.
- Consumes: validated program policy and completed local acceptance gates.

- [ ] **Step 1: Write dry-run no-network tests**

Assert dry-run displays exact assets, exclusions, modules by traffic class, blocked modules/reasons, estimated requests, concurrency, redirects, authentication needs, evidence controls, backups, and stop conditions while making zero network calls.

- [ ] **Step 2: Write passive-first and redirect tests**

Assert safe-active cannot run before a recorded passive review approval. Simulate an allowed URL redirecting out of scope and prove the HTTP transport blocks before following it.

- [ ] **Step 3: Run and verify failure**

Run: `python -m pytest tests/test_pilot_command.py -q`

- [ ] **Step 4: Add staged pilot execution**

Require a new explicit confirmation containing the snapshot hash before each live phase. Start with the narrowest exact target and a request budget lower than or equal to the program limit. Keep all state-changing/disruptive scanners disabled.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_pilot_command.py -q`

```powershell
git add main.py core/orchestrator.py tests/test_pilot_command.py
git commit -m "feat: add dry-run bug bounty pilot mode"
```

### Task 4: Confidential draft review and manual submission handoff

**Files:**
- Modify: `reporting/reporter.py`
- Create: `tests/test_bugcrowd_draft.py`
- Create: `docs/pilots/bugcrowd/report-review-checklist.md`

**Interfaces:**
- Produces: local Bugcrowd-compatible draft with eligibility, scope, evidence, impact, reproduction, and redaction sections.
- Consumes: confirmed or explicitly unresolved findings selected by a human.

- [ ] **Step 1: Write confidentiality and minimization tests**

Assert drafts exclude program credentials, tokens, cookies, OTPs, unrelated user data, raw response bodies, and findings from out-of-scope or stale-policy evidence. Assert suspected results are labeled and cannot be presented as confirmed.

- [ ] **Step 2: Write no-auto-submit tests**

Search routes, integrations, CLI options, and transport spies. Assert generating or emailing a draft performs no Bugcrowd login or submission request.

- [ ] **Step 3: Run and verify failure**

Run: `python -m pytest tests/test_bugcrowd_draft.py -q`

- [ ] **Step 4: Implement the local draft and checklist**

Include title, asset, vulnerability class, evidence status, impact, minimal reproduction, controls, request count, timestamps, policy hash, cleanup status, uncertainty, and attachments manifest. Require human checks for known issue/duplicate, eligibility, confidentiality, and disclosure terms.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_bugcrowd_draft.py -q`

```powershell
git add reporting/reporter.py tests/test_bugcrowd_draft.py docs/pilots/bugcrowd/report-review-checklist.md
git commit -m "feat: generate confidential bounty report drafts"
```

### Task 5: Pilot readiness decision

**Files:**
- Create: `docs/verification/bugcrowd-pilot-readiness.md`

**Interfaces:**
- Consumes: current program snapshot, all test results, dry-run output, and operator review.
- Produces: one explicit decision: `READY_FOR_PASSIVE_PILOT`, `DEFERRED`, or `STOPPED`.

- [ ] **Step 1: Re-run every acceptance gate on the exact pilot commit**

Run: `python -m pytest -q`

Run: `python test_scanners_detect.py`

Run the pilot dry-run against the local policy snapshot. Expected: no network traffic and no failed gate.

- [ ] **Step 2: Review the current Bolt engagement brief manually**

On the intended testing day, verify its status, type, safe harbor, scope, automation language, rates, prohibited methods, known issues, credentials, disclosure, and changes. If any item is unavailable or ambiguous, the readiness decision is `DEFERRED` and no target hostname is entered into a live command.

- [ ] **Step 3: Record the decision and evidence**

Write the tested commit, snapshot hash/time, exact selected asset if eligible, enabled modules, request/concurrency ceilings, excluded modules, rollback/checkpoint location, human confirmations, and unresolved questions. Do not include confidential brief text beyond what is necessary for local authorized operation.

- [ ] **Step 4: Commit readiness evidence before live traffic**

```powershell
git add docs/verification/bugcrowd-pilot-readiness.md
git commit -m "docs: record Bugcrowd pilot readiness"
```

- [ ] **Step 5: Require a separate explicit live-run confirmation**

After the readiness document exists, present the exact target, policy hash, module list, request ceiling, and stop conditions to the user. Live traffic starts only after that separate confirmation; readiness work itself sends no traffic.
