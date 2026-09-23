# Agent-Hunter Safety, Evidence, and Recovery Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every scanner policy-constrained, evidence-explicit, secret-safe, and recoverable before adding more capabilities.

**Architecture:** Extend the mounted orchestrator with typed capability metadata, deterministic decision gates, structured evidence validation, and one atomic persistence service. Preserve compatibility with existing scanner and report interfaces while migrating callers incrementally.

**Tech Stack:** Python 3 dataclasses and enums, `httpx`, `pytest`, standard-library JSON/hashlib/pathlib/os/tempfile.

**Spec:** `docs/superpowers/specs/2026-09-23-agent-hunter-modernization-resilience-design.md`

## Global Constraints

- Deterministic scope and policy gates veto AI and RL choices.
- `STATE_CHANGING` and `DISRUPTIVE` scanners are disabled by default.
- Raw passwords, OTPs, cookies, authorization headers, bearer tokens, request bodies, and payment values are never persisted.
- Existing source ownership remains mounted through `core/orchestrator.py`; no replacement pipeline is introduced.
- A result is not `CONFIRMED` from response status, response length, reflection, or a generic error alone.
- All durable state writes are atomic, checksummed, schema-versioned, and recoverable.

## Review Focus

- Unicode, wildcard, suffix, redirect, scheme, and port variations must never escape the approved scope; Task 3 pins each case.
- A process interruption during persistence must leave either the previous valid file or the new valid file; Task 2 injects failures at each transition.
- Legacy findings with contradictory booleans must migrate to `UNRESOLVED`, not silently become confirmed; Task 1 pins migration.
- A scanner missing capability metadata must fail closed before network traffic; Task 3 verifies the request client is untouched.
- Sensitive headers and nested secret values must be removed at capture time from checkpoints and reports; Task 4 exercises nested structures.

---

## File Structure

- `core/models.py`: evidence, coverage, and decision types shared by the pipeline.
- `core/scanner_capabilities.py`: capability declarations and complete-registry validation.
- `core/decision_engine.py`: deterministic action filtering and continue/defer/stop/escalate decisions.
- `core/evidence.py`: redaction, control comparison, and evidence-state transitions.
- `core/recovery.py`: atomic JSON envelopes, checksum validation, retention, and last-known-good restore.
- `core/base_scanner.py`: scanner capability/evidence contract.
- `core/bbp_policy.py`: enforce capability, scope, policy freshness, and budgets.
- `core/orchestrator.py`: invoke the new owners and record coverage/decisions/checkpoints.
- `reporting/reporter.py`: render evidence and coverage states without leaking secrets.

### Task 1: Explicit evidence, coverage, and decision models

**Files:**
- Modify: `core/models.py:1-205`
- Create: `tests/test_evidence_models.py`

**Interfaces:**
- Produces: `EvidenceStatus`, `CoverageStatus`, `DecisionOutcome`, `EvidenceRef`, `DecisionRecord`, `CoverageRecord`, and `Finding.normalize_legacy_status()`.
- Consumes: existing `Finding`, `Target`, and `ScanState` dataclasses.

- [ ] **Step 1: Write failing enum and migration tests**

```python
from core.models import EvidenceStatus, Finding


def test_legacy_confirmed_maps_to_confirmed():
    finding = Finding(confirmed=True, false_positive=False)
    finding.normalize_legacy_status()
    assert finding.evidence_status is EvidenceStatus.CONFIRMED


def test_contradictory_legacy_flags_are_unresolved():
    finding = Finding(confirmed=True, false_positive=True)
    finding.normalize_legacy_status()
    assert finding.evidence_status is EvidenceStatus.UNRESOLVED
```

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `python -m pytest tests/test_evidence_models.py -q`

Expected: collection fails because `EvidenceStatus` is not defined.

- [ ] **Step 3: Add the typed states and compatibility mapping**

```python
class EvidenceStatus(str, Enum):
    NOT_TESTED = "not_tested"
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    UNRESOLVED = "unresolved"


class DecisionOutcome(str, Enum):
    CONTINUE = "continue"
    DEFER = "defer"
    STOP = "stop"
    ESCALATE = "escalate"


def normalize_legacy_status(self) -> None:
    if self.confirmed and self.false_positive:
        self.evidence_status = EvidenceStatus.UNRESOLVED
    elif self.confirmed:
        self.evidence_status = EvidenceStatus.CONFIRMED
    elif self.false_positive:
        self.evidence_status = EvidenceStatus.REFUTED
```

Add structured references, decision rationale, policy hash, and coverage records to `ScanState`; serialize enum values and all non-secret fields in `to_dict()`.

- [ ] **Step 4: Add round-trip and invalid-transition tests**

```python
def test_finding_dict_has_explicit_evidence_status():
    finding = Finding(evidence_status=EvidenceStatus.SUSPECTED)
    assert finding.to_dict()["evidence_status"] == "suspected"


def test_confirmed_requires_validator_reference():
    finding = Finding(evidence_status=EvidenceStatus.CONFIRMED, evidence_refs=[])
    with pytest.raises(ValueError, match="validator evidence"):
        finding.validate_evidence_state()
```

- [ ] **Step 5: Run focused and compatibility tests**

Run: `python -m pytest tests/test_evidence_models.py tests/test_full_plan.py -q`

Expected: all tests pass.

- [ ] **Step 6: Commit the model contract**

```powershell
git add core/models.py tests/test_evidence_models.py
git commit -m "feat: add explicit evidence and decision states"
```

### Task 2: Atomic persistence and last-known-good recovery

**Files:**
- Create: `core/recovery.py`
- Create: `tests/test_recovery.py`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `AtomicJsonStore(path: Path, schema: str, retain: int = 3)`, `write(payload) -> StoredEnvelope`, `read() -> dict`, `restore_last_known_good() -> dict`.
- Consumes: JSON-serializable dictionaries.

- [ ] **Step 1: Write failing atomicity, checksum, and rollback tests**

```python
def test_corrupt_active_restores_backup(tmp_path):
    store = AtomicJsonStore(tmp_path / "state.json", "hunter.test.v1")
    store.write({"generation": 1})
    store.write({"generation": 2})
    (tmp_path / "state.json").write_text("{broken", encoding="utf-8")
    assert store.restore_last_known_good()["generation"] == 1


def test_failed_replace_preserves_old_valid_state(tmp_path, monkeypatch):
    store = AtomicJsonStore(tmp_path / "state.json", "hunter.test.v1")
    store.write({"generation": 1})
    monkeypatch.setattr(os, "replace", Mock(side_effect=OSError("injected")))
    with pytest.raises(OSError, match="injected"):
        store.write({"generation": 2})
    assert store.read()["generation"] == 1
```

- [ ] **Step 2: Verify the tests fail because the store is absent**

Run: `python -m pytest tests/test_recovery.py -q`

Expected: import failure for `core.recovery`.

- [ ] **Step 3: Implement envelopes and atomic replacement**

```python
@dataclass(frozen=True)
class StoredEnvelope:
    schema: str
    generation: int
    written_at: str
    payload: dict[str, Any]
    checksum: str


class AtomicJsonStore:
    def write(self, payload: dict[str, Any]) -> StoredEnvelope:
        # Serialize canonical payload, hash it, write a same-directory temp file,
        # flush + os.fsync, read back and validate, rotate the valid active file,
        # then os.replace the temp file and prune only excess versioned snapshots.
```

Use `secrets.token_hex()` for temporary names, `json.dumps(..., sort_keys=True, separators=(",", ":"))` for hashing, and `hmac.compare_digest()` for checksum checks. Reject schema mismatch and non-dictionary payloads.

- [ ] **Step 4: Add retention, schema mismatch, partial JSON, and disk-error tests**

Use monkeypatches for `open`, `os.fsync`, and `os.replace`. Assert temporary files are removed after handled failures and active state remains readable.

- [ ] **Step 5: Run recovery tests**

Run: `python -m pytest tests/test_recovery.py -q`

Expected: all tests pass.

- [ ] **Step 6: Ignore generated recovery artifacts and commit**

Add `reports/checkpoints/`, `reports/outbox/`, `*.tmp.*`, and `*.bak.*` to `.gitignore` without removing existing rules.

```powershell
git add core/recovery.py tests/test_recovery.py .gitignore
git commit -m "feat: add atomic state recovery"
```

### Task 3: Capability registry and deterministic decision gate

**Files:**
- Create: `core/scanner_capabilities.py`
- Create: `core/decision_engine.py`
- Create: `tests/test_scanner_capabilities.py`
- Create: `tests/test_decision_engine.py`
- Modify: `core/base_scanner.py`
- Modify: `core/bbp_policy.py:317-370`

**Interfaces:**
- Produces: `TrafficClass`, `ScannerCapability`, `CapabilityRegistry`, `DecisionContext`, `DecisionEngine.evaluate(context) -> DecisionRecord`.
- Consumes: policy snapshot hash, remaining budgets, candidate module names, and evidence/failure state.

- [ ] **Step 1: Write failing registry completeness and deny tests**

```python
def test_unknown_scanner_fails_closed():
    registry = CapabilityRegistry({})
    with pytest.raises(CapabilityError, match="missing capability"):
        registry.require("unknown")


def test_state_changing_scanner_denied_without_permission():
    record = engine.evaluate(context_for(TrafficClass.STATE_CHANGING))
    assert record.outcome is DecisionOutcome.DEFER
    assert record.allowed_actions == []
```

- [ ] **Step 2: Write scope normalization tests before implementation**

Test `example.com`, `api.example.com`, `example.com.evil.test`, Unicode IDNA, explicit ports, HTTP-to-HTTPS redirects, IP literals, and wildcard rules. Assert a discovered URL never inherits permission merely because the crawler found it.

- [ ] **Step 3: Run tests and capture expected failures**

Run: `python -m pytest tests/test_scanner_capabilities.py tests/test_decision_engine.py -q`

Expected: imports fail for the new modules.

- [ ] **Step 4: Implement capability types and fail-closed validation**

```python
class TrafficClass(str, Enum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    STATE_CHANGING = "state_changing"
    DISRUPTIVE = "disruptive"


@dataclass(frozen=True)
class ScannerCapability:
    module: str
    version: str
    traffic_class: TrafficClass
    request_cost: int
    max_concurrency: int
    required_permissions: tuple[str, ...]
    positive_controls: tuple[str, ...]
    negative_controls: tuple[str, ...]
    fallback_module: str | None
    idempotent: bool
```

Require each registered scanner to expose a capability or receive an explicit registry entry. Do not yet enable any new scanner.

- [ ] **Step 5: Implement deterministic decisions**

Evaluate in order: policy freshness, scope, capability presence, traffic permission, request/risk budget, prior ambiguous state, repeated failures, and expected evidence value. Produce one of the four decision outcomes with denied rule IDs and recovery text.

- [ ] **Step 6: Make `PolicyEnforcer.is_module_allowed()` actually deny**

Return `(False, reason)` for disallowed traffic classes, prohibited modules, stale policy, insufficient budgets, and missing metadata. Preserve warning-only behavior only for explicitly permitted safe-active scanners.

- [ ] **Step 7: Run focused tests**

Run: `python -m pytest tests/test_scanner_capabilities.py tests/test_decision_engine.py -q`

Expected: all tests pass, including a spy proving no HTTP call occurs after denial.

- [ ] **Step 8: Commit the gate**

```powershell
git add core/scanner_capabilities.py core/decision_engine.py core/base_scanner.py core/bbp_policy.py tests/test_scanner_capabilities.py tests/test_decision_engine.py
git commit -m "feat: enforce scanner capability decisions"
```

### Task 4: Capture-time redaction and evidence validation

**Files:**
- Create: `core/evidence.py`
- Create: `tests/test_evidence_pipeline.py`
- Modify: `core/base_scanner.py`
- Modify: `utils/http_client.py`

**Interfaces:**
- Produces: `Redactor.redact(value)`, `EvidenceValidator.validate(baseline, probe, controls, rule) -> ValidationResult`, `EvidenceManifest.add(...) -> EvidenceRef`.
- Consumes: sanitized response fingerprints and scanner-specific validation rules.

- [ ] **Step 1: Write failing nested redaction tests**

```python
def test_redacts_nested_sensitive_values():
    value = {"headers": {"Authorization": "Bearer abc", "X-Test": "ok"},
             "cookies": {"session": "secret"}, "body": "password=hunter2"}
    redacted = Redactor().redact(value)
    assert "abc" not in json.dumps(redacted)
    assert "secret" not in json.dumps(redacted)
    assert "hunter2" not in json.dumps(redacted)
    assert redacted["headers"]["X-Test"] == "ok"
```

- [ ] **Step 2: Write weak-evidence rejection tests**

Assert equal-status length changes, generic 500 responses, unescaped reflection, and JSON error text remain `SUSPECTED` or `REFUTED`. Assert a vulnerability-specific differential with its negative control can become `CONFIRMED`.

- [ ] **Step 3: Run tests and verify failure**

Run: `python -m pytest tests/test_evidence_pipeline.py -q`

Expected: import failure for `core.evidence`.

- [ ] **Step 4: Implement redacted fingerprints and validation results**

Hash normalized body content, retain content type/status/timing buckets, and retain only allowlisted header names with redacted values. Store no raw request body. Make confirmation require the rule’s named controls and validator evidence IDs.

- [ ] **Step 5: Integrate capture into the base scanner and HTTP client**

The HTTP layer returns the live response to the scanner but emits only the sanitized evidence object to persistence callbacks. Add a test spy showing the manifest never receives the raw authorization header, cookie, or body.

- [ ] **Step 6: Run focused tests and scanner contracts**

Run: `python -m pytest tests/test_evidence_pipeline.py test_scanners_unit.py test_scanners_detect.py -q`

Expected: all tests pass.

- [ ] **Step 7: Commit evidence handling**

```powershell
git add core/evidence.py core/base_scanner.py utils/http_client.py tests/test_evidence_pipeline.py
git commit -m "feat: validate and redact scanner evidence"
```

### Task 5: Versioned orchestrator checkpoints and coverage journal

**Files:**
- Modify: `core/orchestrator.py:69-1207`
- Create: `tests/test_orchestrator_recovery.py`
- Modify: `core/models.py`

**Interfaces:**
- Consumes: `AtomicJsonStore`, `CapabilityRegistry`, `DecisionEngine`, and evidence/coverage models.
- Produces: per-scan checkpoint directory, decision journal, coverage summary, safe resume behavior.

- [ ] **Step 1: Write failing corrupt-checkpoint and policy-drift tests**

```python
def test_resume_uses_last_known_good_checkpoint(tmp_path):
    # Save two generations, corrupt newest, resume, and assert the earlier
    # generation's module cursor is restored without replaying completed work.


def test_resume_rejects_changed_policy_hash(tmp_path):
    with pytest.raises(ResumeBlocked, match="policy snapshot changed"):
        orchestrator.resume(checkpoint, policy_hash="different")
```

- [ ] **Step 2: Add ambiguous-action and missing-capability tests**

Use scanner spies. Assert no request is made when metadata is absent, and an action marked started-but-not-completed with `idempotent=False` becomes `ESCALATE` on resume.

- [ ] **Step 3: Run tests and verify they fail on current checkpoint behavior**

Run: `python -m pytest tests/test_orchestrator_recovery.py -q`

Expected: failures show the single direct-write checkpoint cannot validate or recover.

- [ ] **Step 4: Replace direct checkpoint writes with the atomic store**

Use `reports/checkpoints/<scan_id>/checkpoint.json`. Persist schema version, target identity, policy hash, action IDs, budgets, coverage, decision IDs, module cursor, application version, and evidence references. Keep a compatibility loader for the old file that imports it once as an untrusted legacy checkpoint and requires policy re-acknowledgement.

- [ ] **Step 5: Invoke decisions before scanner setup and requests**

Record denied/deferred modules in coverage. Quarantine a module after the configured consecutive-error threshold. Preserve unrelated in-scope work after a branch-level denial; stop the scan for stale policy, critical proof, or global risk-budget exhaustion.

- [ ] **Step 6: Run recovery and full-plan tests**

Run: `python -m pytest tests/test_orchestrator_recovery.py tests/test_full_plan.py -q`

Expected: all tests pass.

- [ ] **Step 7: Commit orchestrator recovery**

```powershell
git add core/orchestrator.py core/models.py tests/test_orchestrator_recovery.py
git commit -m "feat: add recoverable scan decisions and coverage"
```

### Task 6: Content-aware header correction and report migration

**Files:**
- Modify: `scanners/misconfig/header_security.py`
- Modify: `reporting/reporter.py`
- Create: `tests/test_header_applicability.py`
- Create: `tests/test_report_evidence_states.py`
- Modify: `Architecture.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: explicit evidence and coverage states.
- Produces: content-aware header findings and reports grouped by evidence status.

- [ ] **Step 1: Write failing applicability tests**

```python
@pytest.mark.parametrize("content_type", ["application/json", "image/png", "text/css"])
def test_document_only_headers_not_reported_for_non_documents(content_type):
    findings = scan_headers(headers={"content-type": content_type})
    assert not any(f.extra.get("header") in {"content-security-policy", "x-frame-options"}
                   for f in findings)
```

Also assert HTML documents still receive applicable checks and API-relevant headers remain separately evaluated.

- [ ] **Step 2: Write report grouping and leak tests**

Create one finding in every evidence state plus synthetic secrets. Assert Markdown, JSON, and HTML totals remain separate and no secret appears in any format.

- [ ] **Step 3: Run tests and verify current false-positive behavior fails**

Run: `python -m pytest tests/test_header_applicability.py tests/test_report_evidence_states.py -q`

Expected: the JSON applicability test and evidence-group rendering fail.

- [ ] **Step 4: Implement content-aware rules and report sections**

Apply CSP/frame-ancestor/X-Frame-Options checks only to browser-renderable documents. Render confirmed, suspected, unresolved, refuted, not-tested, blocked, deferred, and failed coverage separately. Include decision reasons and policy hash without serializing secrets.

- [ ] **Step 5: Update architecture and operating documentation**

Document the current scanner registry count from code, evidence meanings, recovery paths, and the rule that “no finding” is not proof that a class was fully tested.

- [ ] **Step 6: Run the complete current verification set**

Run: `python test_scanners_detect.py`

Run: `python -m pytest tests test_scanners_unit.py test_rl_integration.py -q`

Expected: scanner harness reports zero execution errors; all test suites pass.

- [ ] **Step 7: Commit the foundation integration**

```powershell
git add scanners/misconfig/header_security.py reporting/reporter.py tests/test_header_applicability.py tests/test_report_evidence_states.py Architecture.md README.md
git commit -m "feat: report calibrated scanner coverage"
```

### Task 7: Foundation restore drill and acceptance record

**Files:**
- Create: `tests/test_foundation_e2e.py`
- Create: `docs/verification/foundation-acceptance.md`

**Interfaces:**
- Consumes: all foundation components.
- Produces: reproducible end-to-end evidence for the next plan.

- [ ] **Step 1: Add a controlled end-to-end test**

Start `tests/vuln_server.py` on an ephemeral local port. Exercise an allowed scanner, a denied scanner, an out-of-scope redirect, a simulated crash between modules, checkpoint restore, report generation, and secret-leak scan.

- [ ] **Step 2: Run the end-to-end test twice**

Run: `python -m pytest tests/test_foundation_e2e.py -q`

Expected: both runs pass; the second run does not replay completed non-idempotent work.

- [ ] **Step 3: Run the full suite from a clean process**

Run: `python -m pytest -q`

Run: `python test_scanners_detect.py`

Expected: all tests pass and all registered scanner classes load without errors.

- [ ] **Step 4: Record exact evidence**

Write the commands, timestamps, commit, Python version, pass/fail counts, injected failure cases, restored generation, and remaining limitations to `docs/verification/foundation-acceptance.md`. Do not write a generic “all passed” statement without the captured output summary.

- [ ] **Step 5: Commit the acceptance evidence**

```powershell
git add tests/test_foundation_e2e.py docs/verification/foundation-acceptance.md
git commit -m "test: verify Hunter recovery foundation"
```
