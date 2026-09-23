# Foundation acceptance record

Date: 2026-09-23 (Asia/Calcutta)  
Tested source commit: `4e37dc6de5136c1112a6707aa0328315b1e224b0`  
Branch: `codex/agent-hunter-modernization`  
Python: `3.12.10`  
Scope: local tests and synthetic mock responses only; no Supabase, bug-bounty target, platform account, OTP, SMTP login, or external application was accessed.

## Acceptance results

### Controlled restore drill

Command, executed twice:

```text
python -m pytest tests/test_foundation_e2e.py -q
```

Result 1: `1 passed` in 5.5 seconds.  
Result 2: `1 passed` in 3.0 seconds.

The test starts `tests/vuln_server.py` through an ephemeral loopback-only `HTTPServer`. It verifies:

- `header_security` is allowed under a passive-only local policy decision;
- `race_condition` is denied under that same traffic policy before scanner execution;
- an in-scope `/login` response cannot redirect the HTTP client to an unapproved path;
- a completed non-idempotent `csrf_scanner` action remains completed and is not replayed;
- a simulated crash corrupts checkpoint generation 2;
- resume restores checksummed generation 1, with `modules_run == ["csrf_scanner"]` and `modules_pending == ["header_security"]`;
- the restored completed action does not create an `ESCALATE` decision;
- Markdown, JSON, and HTML reports redact an injected password value.

The first redirect assertion failed before the transport fix (`DID NOT RAISE ScopeViolationError`). `HttpClient` now applies the scope/policy check to every HTTPX request event, including generated redirect requests. The same drill then passed twice.

### Clean-process Hunter suite

Command:

```text
python -m pytest -q
```

Result: `214 passed` in 1,141.7 seconds (progress reached 100%, process exit code 0).

The run included the 48-test scanner integration file, the v1 and v2 RL suites, async AI tests, recovery tests, evidence/report tests, root scanner unit tests, and root RL integration tests. The three v2 benchmark cases also passed. Captured benchmark means from this run were approximately:

- state encoding: 15.54 microseconds;
- action choice: 121.62 microseconds;
- observation/update: 67.80 milliseconds.

Before acceptance, a bare run incorrectly collected unrelated tests under vendored source directories and failed on `scripts.grader` / `scripts.parser` imports. `pytest.ini` now limits default discovery to Hunter's `tests/`, `test_scanners_unit.py`, and `test_rl_integration.py`. `requirements-dev.txt` records the previously missing async and benchmark plugins.

### Scanner load/detection harness

Command:

```text
python test_scanners_detect.py
```

Result at 2026-09-23T23:03:02+05:30:

```text
Scanners OK:           25/25
Scanners ERRORED:      0
Detection confirmed:   8/8
```

This harness uses mock vulnerable responses. “Detection confirmed: 8/8” refers only to its eight explicit synthetic expectations; it is not a claim that every scanner is accurate on real applications.

## Additional constituent verification

The single full command initially exceeded shorter five- and ten-minute execution windows. To distinguish cumulative runtime from a hang, the suite was also measured in constituents before the final 20-minute clean run:

- non-RL group: 99 passed;
- `tests/test_full_plan.py`: 48 passed in 137.8 seconds;
- RL v1 learning group: 8 passed in 47 seconds;
- RL v1 robustness/scale group: 7 passed in 264.9 seconds;
- RL v2 fast group: 36 passed;
- RL v2 slow group: 20 passed in 468.6 seconds;
- RL v2 benchmark group: 3 passed.

These split results are diagnostic evidence only; the acceptance result is the later clean `python -m pytest -q` exit code 0.

## Remaining limitations

- The suite emits many `datetime.utcnow()` deprecation warnings and one legacy event-loop deprecation warning. They did not fail this gate but should be migrated to timezone-aware UTC values.
- Scanner harness responses are synthetic. Passing them establishes loading, execution, and specified regression behavior, not field accuracy, universal vulnerability coverage, or production readiness.
- `MisconfigScanner` still emits 115 findings in the broad mock harness. The dedicated `HeaderSecurityScanner` now applies CSP and frame checks only to browser-renderable documents, but the broad misconfiguration scanner needs separate false-positive calibration in the modern-scanner plan.
- Checkpoint recovery can restore only generations that were successfully persisted. An interrupted external side effect cannot be inferred from local state; unfinished non-idempotent work is therefore escalated rather than replayed.
- No live bug-bounty traffic is authorized by this record. A current authenticated program brief, exact asset selection, permitted techniques, rate limits, and same-day policy hash are still required before any external request.
- SMTP/notification support, modern scanner validators, constrained RL behavior, and the Bugcrowd dry-run/pilot remain separate implementation plans after this foundation gate.
