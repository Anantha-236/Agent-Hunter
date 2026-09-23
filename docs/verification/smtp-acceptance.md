# Outbound SMTP acceptance record

Date: 2026-09-23 (Asia/Calcutta)  
Tested source commit: `a3db4a0ada1c20d242ef0b5129d22f84e65ab9a5`  
Branch: `codex/agent-hunter-modernization`  
Python: `3.12.10`  
Boundary: synthetic settings, temporary files, and an injected in-memory SMTP transport only. No real SMTP provider, mailbox, OTP, platform account, Supabase project, or bug-bounty target was accessed.

## Focused SMTP verification

Command:

```text
python -m pytest tests/test_email_config.py tests/test_email_client.py tests/test_email_outbox.py tests/test_email_entrypoints.py tests/test_smtp_e2e.py tests/test_report_evidence_states.py -q
```

Result: `43 passed`, exit code 0.

The focused set verifies:

- environment-only configuration and secret-safe representations;
- mandatory STARTTLS and a default certificate-verifying SSL context;
- finite transport timeout and sanitized typed errors;
- normalized, deduplicated, IDNA-aware recipient allowlisting;
- rejection of CR/LF injection, malformed addresses, insecure TLS settings, oversized files, binary files, and secret-bearing artifacts;
- content-addressed idempotency based on report digest, recipients, and template version;
- persisted `pending`, `retryable`, `delivery_unknown`, `delivered`, and terminal `failed` states;
- bounded exponential retry and no automatic retry from `delivery_unknown`;
- no SMTP side effect from normal report generation or the normal scan API;
- explicit CLI handoff and token-protected known-report API delivery only;
- secret redaction in Markdown, JSON, HTML, prepared attachments, captured messages, and logs.

## Fake-server end-to-end proof

Command:

```text
python -m pytest tests/test_smtp_e2e.py -q
```

Result: `1 passed`, exit code 0.

Injected scenario and observed state sequence:

1. A redacted report artifact was prepared from a scan state containing synthetic URL-token and cookie values.
2. Two enqueue calls with case-different versions of the same allowlisted recipient returned the same item ID; pending count stayed at one.
3. The first SMTP send raised a synthetic disconnect. The outbox persisted `retryable` with attempt count one.
4. The second send negotiated TLS, authenticated, and was accepted. The outbox persisted `delivered`.
5. A third delivery call returned the existing `delivered` state without connecting or sending.

Captured transport totals:

```text
connections=2
tls_negotiations=2
logins=2
send_attempts=2
accepted_messages=1
duplicate_acceptances=0
```

The fake connection asserted that the SSL context had hostname checking enabled and certificate verification active. Exactly one captured message contained the allowlisted recipient and expected subject. The synthetic SMTP password, URL token, and cookie were absent from the captured MIME message and captured logs.

This is an injected transport test, not a real provider handshake. It proves production code requests verified STARTTLS in the required sequence without weakening TLS for tests; it does not prove a particular provider's DNS, certificate, credentials, quotas, or delivery behavior.

## Complete regression suite

Command:

```text
python -m pytest -q
```

Result: `255 passed`, progress reached 100%, process exit code 0, duration `1,151.1 seconds`.

The run included the foundation scanner/recovery suite, v1 and v2 RL suites, async AI tests, three benchmarks, and all SMTP configuration, transport, outbox, entrypoint, and end-to-end tests. Captured benchmark means were approximately:

- state encoding: 13.38 microseconds;
- action choice: 68.67 microseconds;
- observation/update: 46.28 milliseconds.

Deprecation warnings remain for legacy `datetime.utcnow()` calls and a legacy event-loop path. They did not fail this gate and remain tracked as cleanup work.

## Security and operational limitations

- No credential supplied in conversation was used or stored. Any app password previously exposed in chat should be revoked and replaced before real configuration.
- A real password belongs only in ignored `.env.local` or an operating-system secret provider. `.env.local.example` contains empty values only.
- Agent-Hunter is outbound-only. It cannot read an inbox, retrieve Bugcrowd/HackerOne OTPs, bypass MFA/CAPTCHA, automate platform login, or submit a report.
- The API email route requires `HUNTER_LOCAL_API_TOKEN` and accepts only a report ID registered by the running process. That registry is currently in-memory, so process restart requires regenerating or re-registering the report.
- `delivery_unknown` is intentionally not retried automatically. A human must inspect provider state because SMTP acceptance may have occurred before the local acknowledgement was persisted.
- The outbox prevents duplicate local retries after a recorded delivery. SMTP itself does not provide universal exactly-once semantics, so the ambiguous crash boundary is handled conservatively rather than claimed as exactly-once delivery.
- Normal scan completion does not send email. Delivery requires `--email-report`, `--retry-email-outbox`, or the explicit authenticated local API endpoint.
- This acceptance record does not authorize live bug-bounty testing. Modern scanner and constrained-RL plans must still pass before a same-day program-policy dry run can be considered.
