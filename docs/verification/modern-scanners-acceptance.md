# Modern Scanner Acceptance Evidence

Date: 2026-09-23  
Branch: `codex/agent-hunter-modernization`  
Implementation base: `ce3e9f6158b6790c8aea91f6ed97f272d2d816b7`

## Status

**EXPERIMENTALLY VERIFIED on controlled local fixtures.** This acceptance record does not establish universal real-world accuracy, permission to test a live target, or eligibility under any Bugcrowd/HackerOne program.

No Supabase project, mailbox, OTP, bounty platform, or public target was accessed. All networked tests used loopback fixtures or in-memory protocol doubles.

## Measured results

| Gate | Result |
|---|---:|
| Registered scanners | 32 |
| Paired calibration + modern e2e | 37 passed |
| Dynamic scanner harness | 32/32 ran; 0 load/runtime errors |
| Legacy explicit detections | 8/8 |
| Full repository suite | 330 passed; exit 0 |
| Full-suite elapsed time | 523.5 seconds |

The paired corpus contains one calibration entry per registry module, a vulnerable loopback fixture, and a misleading-safe control fixture. Twenty-five modules have explicit expected vulnerability families in the shared corpus. Seven discovery/gated modules produce no vulnerability finding by default and are validated by their focused suites: OpenAPI, BOLA, mass assignment, OAuth/OIDC, session cookies, authenticated cache, and WebSocket.

Safe controls cover generic 500 responses, escaped reflection, constant-size authorization denials, different-length permitted objects, non-document JSON header applicability, same-origin redirects, compressed content, delay, 403/404 equivalence, identical public cache content, `Vary`/`Age`, conditional responses, authentication expiry, and external protocol endpoints. These controls produced no confirmed finding. Informational/observed output is permitted where the scanner explicitly labels it as non-exploit proof.

## Controlled-case request ceilings

These are assertions for the specific one-endpoint calibration cases, not universal target-wide traffic limits. Scanners that scale across discovered parameters or URLs remain additionally constrained by policy, scope, rate, and scan budgets.

| Scanner | Expected controlled outcome | Maximum requests/connections |
|---|---|---:|
| sql_injection | sql_injection | 220 |
| ssti | ssti | 100 |
| crlf_injection | crlf / response_splitting | 35 |
| xss_scanner | reflected_xss | 120 |
| ssrf | ssrf | 100 |
| auth_scanner | default_credentials / jwt_alg_none | 30 |
| oauth_oidc_scanner | coverage only | 2 |
| session_cookie_scanner | coverage only | 5 |
| jwt_scanner | jwt_weak_secret | 5 |
| rate_limit_scanner | rate_limit_missing | 10 |
| idor_scanner | idor | 40 |
| bola_scanner | focused two-principal suite | 20 |
| mass_assignment_scanner | focused gated cleanup suite | 6 |
| broken_access_control | broken_access_control | 20 |
| path_traversal | path_traversal | 70 |
| lfi_rfi_scanner | lfi_rfi / lfi_wrapper | 45 |
| misconfig_scanner | sensitive_file_exposure / directory_listing | 140 |
| cors_scanner | cors_credentials_reflection | 4 |
| header_security | header_missing | 2 |
| sensitive_data_exposure | secret/sensitive exposure | 14 |
| open_redirect | open_redirect | 90 |
| subdomain_takeover | subdomain_takeover | 2 |
| ssl_tls_scanner | tls_missing_https | 2 |
| openapi_scanner | discovery only | 5 |
| csrf_scanner | csrf | 3 |
| host_header | host-header family | 30 |
| cache_behavior_scanner | focused two-principal suite | 10 |
| xxe_scanner | xxe | 30 |
| race_condition | race_condition | 22 |
| command_injection | command_injection | 120 |
| graphql_scanner | introspection observation | 20 |
| websocket_scanner | focused handshake/topic suite | 4 connections / 2 messages |

## Modern coverage verified

- OpenAPI 3 JSON/YAML parsing with byte/depth limits, local references, relative servers, duplicate operation suppression, and blocked external references/servers. Operations remain metadata candidates and are not automatically executed.
- BOLA requires exactly two in-memory synthetic identities and stable object-identity fields; response length alone cannot confirm it.
- Mass assignment is disabled by default and requires one reversible allowlisted field, explicit permission, operator confirmation, an idempotency key, before/after evidence, and verified cleanup. Cleanup ambiguity escalates and stops writes.
- OAuth/OIDC metadata uses duplicate-key detection and blocks malformed/cross-origin endpoints. Introspection/best-practice gaps remain observations. Active flow checks require an explicitly permitted synthetic client and same-origin, in-scope callback.
- Cookie capture retains scope/flags/expiry class and a keyed fingerprint, never raw values. Auth session serialization retains secret names/fingerprints only.
- Authenticated cache confirmation requires an uncached identity control plus two repeat cross-principal semantic-owner matches. Public identical content, `Vary`, CDN-like age, conditional responses, and authentication expiry do not confirm leakage.
- GraphQL introspection, aliases, batching, depth behavior, field suggestions, and unauthenticated sensitive-looking data are observations/suspicions unless semantic authorization controls prove impact.
- WebSocket redirects are not followed. Handshake checks are bounded; topic authorization requires two synthetic identities, at most four connections/two messages, and every connection is closed.

## Known limitations and unverified areas

- Controlled fixtures do not measure internet-wide precision, recall, WAF behavior, framework diversity, CDN behavior, or bounty-program eligibility.
- The broad legacy `misconfig_scanner` still emits 115 findings in the permissive synthetic mock harness. That harness is intentionally unrealistic and is not an accuracy score; the paired safe fixture is the relevant negative control.
- Several legacy scanners remain high-volume per parameter. Their controlled-case ceilings are measured above, but target-wide totals depend on discovery breadth and policy budgets.
- No real identity provider, CDN, WebSocket service, browser, or bug-bounty target was exercised.
- Full-suite output contains existing `datetime.utcnow()` deprecation warnings. They did not fail the suite but remain maintenance work.
- No real SMTP provider handshake was performed in this phase; SMTP has a separate fake-server acceptance record.

## Exact verification commands

```powershell
python -m pytest tests/test_scanner_calibration.py tests/test_modern_scanners_e2e.py -q
python test_scanners_detect.py
python -m pytest -q
python -m pytest --collect-only -q
```

Observed outcomes: `37 passed`; `32/32` scanners with `0` errors and `8/8` explicit legacy detections; full suite exit `0`, `330` collected/passed, `523.5s`.
