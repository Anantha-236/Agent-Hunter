# Agent-Hunter Modernization Program Index

The approved design is delivered through four independently testable implementation plans followed by one controlled external pilot:

1. `2026-09-23-hunter-foundation-implementation.md` — evidence states, capability metadata, deterministic policy gates, redaction, atomic checkpoints, report calibration, and restore drills.
2. `2026-09-23-hunter-smtp-reporting-implementation.md` — outbound-only TLS SMTP, allowlisting, durable idempotent outbox, explicit send controls, and fake-server verification.
3. `2026-09-23-hunter-modern-scanners-implementation.md` — paired calibration fixtures plus OpenAPI, BOLA, mass assignment, OAuth/OIDC, session/cookie, cache, GraphQL, and WebSocket coverage.
4. `2026-09-23-hunter-constrained-rl-implementation.md` — hard action masks, risk/evidence features, quarantined learning, champion/challenger gates, atomic state, and deterministic rollback.
5. `2026-09-23-bugcrowd-controlled-pilot.md` — same-day authenticated brief review, exact scope import, dry-run, passive-first execution, confidential draft, and manual submission.

## Required Order

Plans 1 through 4 execute in order because later interfaces depend on earlier contracts. Plan 5 starts only after all four acceptance records pass on the same final commit.

Each task uses test-first development and ends with a narrow commit. A failed acceptance gate pauses progression and preserves the previous working phase. No plan authorizes Supabase changes, OTP/inbox access, automated Bugcrowd login, broad platform scanning, or unattended report submission.

## Provisional Pilot Candidate

Bolt is the provisional Bugcrowd candidate because Bugcrowd officially announced its public program on June 4, 2025. This is not current scope authorization. The exact authenticated engagement brief must be reviewed on the testing day; if the program, scope, or automation rules cannot be confirmed, the pilot remains deferred with no live traffic.
