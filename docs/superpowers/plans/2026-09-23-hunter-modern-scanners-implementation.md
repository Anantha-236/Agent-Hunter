# Agent-Hunter Modern Scanner Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add modern web/API coverage and calibrate every active scanner against paired vulnerable and non-vulnerable controlled fixtures.

**Architecture:** Each scanner is a focused `BaseScanner` implementation with declared capability metadata, applicability checks, bounded request costs, vulnerability-specific controls, and structured evidence output. Shared protocol parsing lives in small helper modules; scanner-specific security conclusions stay in their scanner.

**Tech Stack:** Python, `httpx`, BeautifulSoup/lxml, JSON/OpenAPI parsing, WebSockets 12, `pytest`, controlled FastAPI fixtures.

**Spec:** `docs/superpowers/specs/2026-09-23-agent-hunter-modernization-resilience-design.md`

## Global Constraints

- All network tests run against local controlled fixtures until the bug-bounty pilot gate is approved.
- Active requests pass scope, policy, traffic-class, rate, and evidence gates.
- New scanners default to passive or safe-active behavior; write/race/callback behavior remains disabled.
- Authenticated authorization tests require two explicitly supplied synthetic test identities.
- Every positive fixture has a paired negative/misleading control and a bounded request-count assertion.

## Review Focus

- Content encodings, redirects, and JSON/HTML content-type mismatches must not bypass applicability checks; Task 1 pins them.
- OpenAPI references, server URLs, and operation parameters must remain in scope after normalization; Task 2 pins malicious/external references.
- BOLA comparisons must distinguish different permitted object content from unauthorized cross-principal access; Task 3 pins semantic identity.
- OAuth metadata and callback checks must not follow or register arbitrary external redirect URIs; Task 4 pins scope and passive-only behavior.
- Cache and WebSocket checks must stop on authentication ambiguity and never persist session material; Tasks 5 and 6 pin both behaviors.

---

### Task 1: Complete existing scanner calibration corpus

**Files:**
- Modify: `tests/vuln_server.py`
- Create: `tests/fixtures/safe_server.py`
- Create: `tests/test_scanner_calibration.py`
- Modify: each file under `scanners/` only when its paired control demonstrates a defect

**Interfaces:**
- Produces: `ScannerCase(module, vulnerable_url, safe_url, expected_types, max_requests)` and a parameterized calibration suite.
- Consumes: current scanner registry and capability metadata.

- [ ] **Step 1: Inventory every registered scanner into test cases**

Build the case list from `SCANNER_REGISTRY`; assert the case-name set equals the registry-name set so a newly registered scanner cannot skip calibration.

- [ ] **Step 2: Add misleading negative controls**

Provide safe endpoints with generic 500s, reflected but escaped input, constant-length authorization errors, different-length authorized resources, JSON without document headers, redirects, compressed bodies, and delayed safe responses.

- [ ] **Step 3: Run the corpus and preserve failing cases**

Run: `python -m pytest tests/test_scanner_calibration.py -q`

Expected: failures identify current false positives and false negatives; capture them by module rather than weakening assertions.

- [ ] **Step 4: Correct scanners one at a time with vulnerability-specific evidence**

For each failure, add the smallest semantic validator and run that module’s case. Preserve the existing IDOR baseline-body correction and strengthen it with principal/object controls rather than returning to a size threshold.

- [ ] **Step 5: Enforce no heuristic-only confirmation**

Add a registry-wide assertion that any `CONFIRMED` high/critical result has at least one validator evidence reference and the capability’s required controls.

- [ ] **Step 6: Run and commit**

Run: `python -m pytest tests/test_scanner_calibration.py -q`

Run: `python test_scanners_detect.py`

```powershell
git add scanners tests/vuln_server.py tests/fixtures/safe_server.py tests/test_scanner_calibration.py
git commit -m "test: calibrate existing scanner detections"
```

### Task 2: OpenAPI discovery and schema-driven coverage

**Files:**
- Create: `scanners/recon/openapi_scanner.py`
- Create: `scanners/recon/openapi_model.py`
- Create: `tests/test_openapi_scanner.py`
- Modify: `core/orchestrator.py`
- Modify: `config/settings.py`

**Interfaces:**
- Produces: `OpenApiDocument.parse(raw, source_url)`, `OpenApiOperation`, `OpenAPIScanner.scan()`, sanitized endpoint candidates.
- Consumes: scope validator and request budget.

- [ ] **Step 1: Write parser and scope tests**

Test OpenAPI 3 JSON/YAML, relative and absolute servers, path/query parameters, local `$ref`, external `$ref`, malformed documents, oversized specs, duplicate operations, and external server URLs. External references and servers must be recorded as blocked, never fetched automatically.

- [ ] **Step 2: Verify failure before implementation**

Run: `python -m pytest tests/test_openapi_scanner.py -q`

- [ ] **Step 3: Implement bounded passive discovery**

Probe only configured conventional spec paths within the request budget, parse documents with byte/depth limits, normalize operations, and emit coverage candidates rather than vulnerability findings.

- [ ] **Step 4: Mount the scanner and capability**

Register `openapi_scanner` as `PASSIVE`, declare its maximum path probes, and feed its in-scope operation candidates into existing discovery state without executing them automatically.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_openapi_scanner.py tests/test_scanner_capabilities.py -q`

```powershell
git add scanners/recon/openapi_scanner.py scanners/recon/openapi_model.py tests/test_openapi_scanner.py core/orchestrator.py config/settings.py
git commit -m "feat: add bounded OpenAPI discovery"
```

### Task 3: Two-principal REST BOLA and mass-assignment workflows

**Files:**
- Create: `scanners/authz/bola_scanner.py`
- Create: `scanners/authz/mass_assignment_scanner.py`
- Create: `core/test_identities.py`
- Create: `tests/test_api_authz_scanners.py`
- Modify: `core/auth_session.py`
- Modify: `core/orchestrator.py`

**Interfaces:**
- Produces: `TestIdentity(label, sanitized_headers_provider)`, `BOLAScanner`, `MassAssignmentScanner`.
- Consumes: explicitly configured test identities, OpenAPI operations, cleanup declaration, and policy permissions.

- [ ] **Step 1: Write identity isolation and secret-persistence tests**

Assert two identities are required for BOLA confirmation, providers return headers only in memory, serialized state contains labels/fingerprints only, and one-identity runs become `DEFER`/`NOT_TESTED`.

- [ ] **Step 2: Write BOLA differential tests**

Fixture A owns object A and cannot read object B; fixture B is vulnerable and can. Assert object identity is established from stable schema fields or explicit fixture metadata, not response length. Assert 404/403 equivalence remains refuted/unresolved as configured.

- [ ] **Step 3: Write mass-assignment safety tests**

Use only an allowlisted reversible synthetic field. Require before/after/cleanup verification, deny privilege-role/admin/billing fields, and stop with `ESCALATE` if cleanup cannot be confirmed.

- [ ] **Step 4: Implement and mount BOLA**

Classify read-only two-principal BOLA as `SAFE_ACTIVE`; require explicit identity labels and operation candidates. Cap objects and requests per operation.

- [ ] **Step 5: Implement mass assignment disabled by default**

Classify it as `STATE_CHANGING`, require exact field allowlist, cleanup handler, idempotency key, explicit policy permission, and operator confirmation.

- [ ] **Step 6: Run and commit**

Run: `python -m pytest tests/test_api_authz_scanners.py -q`

```powershell
git add scanners/authz/bola_scanner.py scanners/authz/mass_assignment_scanner.py core/test_identities.py core/auth_session.py core/orchestrator.py tests/test_api_authz_scanners.py
git commit -m "feat: add constrained API authorization scanners"
```

### Task 4: OAuth 2.0 and OpenID Connect configuration scanner

**Files:**
- Create: `scanners/auth/oauth_oidc_scanner.py`
- Create: `scanners/auth/oauth_metadata.py`
- Create: `tests/test_oauth_oidc_scanner.py`
- Modify: `config/settings.py`

**Interfaces:**
- Produces: `OAuthMetadata`, `OAuthOIDCScanner` with passive metadata and safe callback-validation checks.
- Consumes: in-scope issuer/authorization endpoints and explicit synthetic client configuration when active checks are enabled.

- [ ] **Step 1: Write metadata validation tests**

Test issuer mismatch, duplicate JSON keys, algorithm metadata, missing PKCE support, `none` advertisement, external endpoints, oversized metadata, and malformed URLs. Missing best-practice metadata is `OBSERVED` or informational unless exploitability is independently proven.

- [ ] **Step 2: Write redirect/state/nonce safety tests**

Use only a local fixture callback and synthetic client. Assert no arbitrary external URI is requested, credentials are absent from persisted evidence, and active flow checks defer without explicit client configuration.

- [ ] **Step 3: Implement passive metadata scanner**

Fetch only standard discovery documents under scope and budget. Validate issuer/audience consistency and endpoint scope. Keep algorithm findings calibrated to actual server behavior and program eligibility.

- [ ] **Step 4: Add opt-in safe-active flow controls**

Test state/nonce/PKCE/redirect validation only against the controlled fixture or an explicitly permitted program test client. Never register clients or change account settings automatically.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_oauth_oidc_scanner.py -q`

```powershell
git add scanners/auth/oauth_oidc_scanner.py scanners/auth/oauth_metadata.py tests/test_oauth_oidc_scanner.py config/settings.py
git commit -m "feat: add OAuth and OIDC checks"
```

### Task 5: Session, cookie, and authenticated cache scanner

**Files:**
- Create: `scanners/auth/session_cookie_scanner.py`
- Create: `scanners/misconfig/cache_behavior_scanner.py`
- Create: `tests/test_session_cache_scanners.py`
- Modify: `core/auth_session.py`

**Interfaces:**
- Produces: metadata-only cookie observations and authenticated cache differential findings.
- Consumes: two test identities for private-response cache checks.

- [ ] **Step 1: Write cookie metadata tests**

Assert values are discarded at capture, duplicate cookie names are handled by scope/path, prefix rules are evaluated, and missing flags are not elevated beyond program eligibility without meaningful impact.

- [ ] **Step 2: Write cache differential tests**

Create fixtures for safe private responses, vulnerable shared responses, misleading identical public content, `Vary`, CDN-like age headers, conditional requests, and authentication expiry. Confirm only when identity-specific content crosses principals under a repeatable control.

- [ ] **Step 3: Implement metadata-only session analysis**

Retain cookie name, domain/path flags, secure attributes, SameSite classification, expiry class, and salted value fingerprint only when needed for rotation comparison.

- [ ] **Step 4: Implement bounded cache behavior checks**

Use GET/HEAD only, strict request counts, response fingerprints, and immediate stop on unexpected state changes or authentication ambiguity.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_session_cache_scanners.py -q`

```powershell
git add scanners/auth/session_cookie_scanner.py scanners/misconfig/cache_behavior_scanner.py core/auth_session.py tests/test_session_cache_scanners.py
git commit -m "feat: add session and cache scanners"
```

### Task 6: GraphQL hardening and WebSocket scanner

**Files:**
- Modify: `scanners/injection/graphql_scanner.py`
- Create: `scanners/realtime/websocket_scanner.py`
- Create: `scanners/realtime/__init__.py`
- Create: `tests/test_graphql_websocket_scanners.py`
- Modify: `core/orchestrator.py`

**Interfaces:**
- Produces: budget-aware GraphQL observations and `WebSocketScanner` for origin/auth/access-control checks.
- Consumes: explicit endpoints, scope gate, message/query budgets, optional synthetic identities.

- [ ] **Step 1: Write GraphQL cost and false-positive tests**

Test introspection enabled by policy, introspection disabled, generic GraphQL errors, depth/cost enforcement, batching, aliases, and unauthorized field access. Introspection alone must not become a confirmed high-impact finding.

- [ ] **Step 2: Write WebSocket scope and auth tests**

Test origin acceptance, missing/invalid auth, two-principal topic access, redirect/external upgrade endpoints, connection/message budgets, close frames, and secret-free evidence.

- [ ] **Step 3: Strengthen GraphQL scanner**

Separate configuration observations from authorization findings, cap depth/aliases/batches, and require semantic field-level controls for confirmation.

- [ ] **Step 4: Implement and mount WebSocket scanner**

Classify handshake-only checks as `SAFE_ACTIVE`; require explicit permission and identities for subscription authorization checks. Never flood messages or hold long-lived connections.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_graphql_websocket_scanners.py -q`

```powershell
git add scanners/injection/graphql_scanner.py scanners/realtime/websocket_scanner.py scanners/realtime/__init__.py tests/test_graphql_websocket_scanners.py core/orchestrator.py
git commit -m "feat: harden GraphQL and WebSocket coverage"
```

### Task 7: Modern scanner acceptance gate

**Files:**
- Modify: `test_scanners_detect.py`
- Create: `tests/test_modern_scanners_e2e.py`
- Create: `docs/verification/modern-scanners-acceptance.md`
- Modify: `Architecture.md`

**Interfaces:**
- Consumes: all registered scanners and controlled fixtures.
- Produces: current accuracy/coverage evidence and updated architecture inventory.

- [ ] **Step 1: Update the explicit detection harness**

Derive expected registered count from the registry. Require zero load/runtime errors and list detection expectations by fixture and evidence state.

- [ ] **Step 2: Run paired-fixture end-to-end tests**

Run: `python -m pytest tests/test_scanner_calibration.py tests/test_modern_scanners_e2e.py -q`

Expected: all vulnerable fixtures produce their expected evidence state; all safe/misleading fixtures stay unconfirmed.

- [ ] **Step 3: Run full verification**

Run: `python test_scanners_detect.py`

Run: `python -m pytest -q`

Expected: zero scanner execution errors and all tests pass.

- [ ] **Step 4: Record measured results**

Record corpus composition, per-scanner true/false outcomes, request ceilings, untested areas, and exact commands in `docs/verification/modern-scanners-acceptance.md`. Do not describe controlled-fixture performance as real-world universal accuracy.

- [ ] **Step 5: Commit acceptance evidence**

```powershell
git add test_scanners_detect.py tests/test_modern_scanners_e2e.py docs/verification/modern-scanners-acceptance.md Architecture.md
git commit -m "test: verify modern scanner coverage"
```
