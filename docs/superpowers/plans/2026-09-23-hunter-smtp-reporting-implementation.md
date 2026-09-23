# Agent-Hunter Outbound SMTP Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicit, TLS-only, allowlisted outbound report delivery that never reads email or duplicates messages after a failure.

**Architecture:** The existing reporter produces a redacted artifact; a separate email integration places a message envelope into an atomic outbox before a transport attempts delivery. CLI/API commands request delivery explicitly, while scan completion itself never implies sending.

**Tech Stack:** Python `smtplib`, `ssl`, `email.message`, dataclasses, environment configuration, `pytest`, local fake SMTP transport.

**Spec:** `docs/superpowers/specs/2026-09-23-agent-hunter-modernization-resilience-design.md`

## Global Constraints

- SMTP is outbound-only; no IMAP, inbox, OTP, MFA, CAPTCHA, or platform-login feature is permitted.
- No real app password is used in tests, logs, examples, commits, reports, or checkpoints.
- TLS certificate verification is mandatory, recipients are allowlisted, and sending is opt-in.
- A delivery failure does not rerun a scan and an outbox retry does not duplicate a delivered message.
- `SMTP_REPORT_TO` is runtime configuration; no account address is hardcoded.

## Review Focus

- Comma-separated recipients with whitespace, case differences, IDNA, or header injection must be normalized or rejected; Task 1 pins parsing.
- A server that advertises STARTTLS but fails negotiation must fail closed; Task 2 pins transport behavior.
- A crash after SMTP acceptance but before local acknowledgement must not silently claim certainty; Task 3 records `delivery_unknown` for manual review.
- Oversized or secret-bearing attachments must be rejected before entering the outbox; Task 3 pins both cases.
- API and CLI defaults must remain report-only with no email side effect; Task 4 uses transport spies.

---

### Task 1: SMTP configuration and recipient policy

**Files:**
- Modify: `config/settings.py`
- Modify: `.env.local.example`
- Create: `integrations/email/__init__.py`
- Create: `integrations/email/config.py`
- Create: `tests/test_email_config.py`

**Interfaces:**
- Produces: `SmtpSettings.from_env()`, `normalize_mailbox()`, `validate_recipients()`.
- Consumes: environment variables defined in the design.

- [ ] **Step 1: Write failing environment and allowlist tests**

```python
def test_password_never_appears_in_repr(monkeypatch):
    monkeypatch.setenv("SMTP_PASSWORD", "synthetic-secret")
    settings = SmtpSettings.from_env(required=True)
    assert "synthetic-secret" not in repr(settings)


def test_recipient_outside_allowlist_is_rejected():
    with pytest.raises(EmailPolicyError, match="not allowlisted"):
        validate_recipients(["other@example.com"], ["owner@example.com"])
```

Also test CR/LF injection, empty host, invalid port, `SMTP_STARTTLS=false`, malformed addresses, duplicate recipients, and normalized case.

- [ ] **Step 2: Run tests and verify imports fail**

Run: `python -m pytest tests/test_email_config.py -q`

Expected: import failure for `integrations.email.config`.

- [ ] **Step 3: Implement immutable secret-safe configuration**

```python
@dataclass(frozen=True, repr=False)
class SmtpSettings:
    host: str
    port: int
    username: str
    password: SecretStr
    starttls: bool
    report_from: str
    report_to: tuple[str, ...]
    recipient_allowlist: tuple[str, ...]
    max_attachment_bytes: int
```

Reject insecure settings rather than silently correcting them. Extend `.env.local.example` with empty values only.

- [ ] **Step 4: Run tests and commit**

Run: `python -m pytest tests/test_email_config.py -q`

```powershell
git add config/settings.py .env.local.example integrations/email/__init__.py integrations/email/config.py tests/test_email_config.py
git commit -m "feat: add secure SMTP configuration"
```

### Task 2: TLS-only message transport

**Files:**
- Create: `integrations/email/client.py`
- Create: `tests/test_email_client.py`

**Interfaces:**
- Produces: `SmtpClient.send(message: EmailMessage) -> TransportReceipt`.
- Consumes: `SmtpSettings` and an injectable SMTP factory.

- [ ] **Step 1: Write failing TLS sequence tests**

Use a fake SMTP object and assert the exact sequence is connect, EHLO, STARTTLS with `ssl.create_default_context()`, EHLO, login, send message, quit. Assert login and send are never called if TLS fails.

- [ ] **Step 2: Run and verify failure**

Run: `python -m pytest tests/test_email_client.py -q`

Expected: import failure for `integrations.email.client`.

- [ ] **Step 3: Implement bounded transport**

```python
class SmtpClient:
    def __init__(self, settings: SmtpSettings, smtp_factory=smtplib.SMTP): ...

    def send(self, message: EmailMessage) -> TransportReceipt:
        # Use a finite timeout, mandatory STARTTLS, verified SSL context,
        # authenticated delivery, sanitized exception text, and no secret logging.
```

Map authentication, TLS, timeout, and recipient failures to typed errors without including server text that could echo credentials.

- [ ] **Step 4: Run tests and commit**

Run: `python -m pytest tests/test_email_client.py -q`

```powershell
git add integrations/email/client.py tests/test_email_client.py
git commit -m "feat: add TLS-only SMTP transport"
```

### Task 3: Durable idempotent outbox

**Files:**
- Create: `integrations/email/outbox.py`
- Create: `tests/test_email_outbox.py`
- Modify: `reporting/reporter.py`

**Interfaces:**
- Produces: `EmailOutbox.enqueue(report, recipients) -> OutboxItem`, `deliver(item_id) -> DeliveryState`, `retry_due(now) -> list[DeliveryState]`.
- Consumes: `AtomicJsonStore`, `Redactor`, `SmtpClient`, and existing report artifacts.

- [ ] **Step 1: Write failing idempotency and attachment tests**

```python
def test_same_report_and_recipients_reuse_idempotency_key(outbox, report):
    first = outbox.enqueue(report, ["owner@example.com"])
    second = outbox.enqueue(report, ["owner@example.com"])
    assert first.idempotency_key == second.idempotency_key
    assert outbox.pending_count == 1


def test_secret_bearing_attachment_is_rejected(outbox, tmp_path):
    report = tmp_path / "report.json"
    report.write_text('{"Authorization":"Bearer synthetic"}')
    with pytest.raises(AttachmentRejected, match="redaction"):
        outbox.enqueue(report, ["owner@example.com"])
```

- [ ] **Step 2: Add crash-boundary tests**

Simulate failure before send, during send, after acceptance, and after local acknowledgement. Require `pending`, `retryable`, `delivery_unknown`, and `delivered` states with bounded attempts and no automatic resend from `delivery_unknown`.

- [ ] **Step 3: Run tests and verify failure**

Run: `python -m pytest tests/test_email_outbox.py -q`

Expected: import failure for `integrations.email.outbox`.

- [ ] **Step 4: Implement the outbox state machine**

Generate idempotency keys from report SHA-256, normalized recipient set, and message template version. Persist before transport. Apply exponential backoff with jitter and a configured maximum attempt count. Reject oversize and redaction-failed attachments.

- [ ] **Step 5: Add reporter handoff**

Expose `Reporter.prepare_email_artifact()` that returns a redacted immutable artifact and manifest. It must not initiate delivery.

- [ ] **Step 6: Run tests and commit**

Run: `python -m pytest tests/test_email_outbox.py tests/test_report_evidence_states.py -q`

```powershell
git add integrations/email/outbox.py reporting/reporter.py tests/test_email_outbox.py
git commit -m "feat: add durable report email outbox"
```

### Task 4: Explicit CLI and API delivery controls

**Files:**
- Modify: `main.py`
- Modify: `api_server.py`
- Create: `tests/test_email_entrypoints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: `EmailOutbox`.
- Produces: explicit `--email-report` behavior and authenticated local API delivery endpoint.

- [ ] **Step 1: Write no-side-effect default tests**

Invoke normal report generation and the normal scan API with a transport spy. Assert no outbox item and no SMTP call. Invoke the explicit send command and assert one queued item.

- [ ] **Step 2: Write API validation tests**

Assert the endpoint accepts a known local report ID only, rejects arbitrary file paths, applies recipient allowlisting, returns queued/delivered state, and never returns SMTP credentials.

- [ ] **Step 3: Run tests and verify failure**

Run: `python -m pytest tests/test_email_entrypoints.py -q`

- [ ] **Step 4: Add explicit entry points**

Add `--email-report` and `--retry-email-outbox` commands or equivalent existing Click options. Add an API route under the existing report API ownership; require the same local authorization mechanism as other mutating routes.

- [ ] **Step 5: Document secret setup without a real secret**

Document creating a replacement app password, setting it only in a local ignored environment file or OS secret provider, recipient allowlisting, revocation, and the fact that Agent-Hunter cannot read OTPs or submit platform reports.

- [ ] **Step 6: Run tests and commit**

Run: `python -m pytest tests/test_email_entrypoints.py -q`

```powershell
git add main.py api_server.py tests/test_email_entrypoints.py README.md
git commit -m "feat: add explicit report email controls"
```

### Task 5: Fake-server integration and acceptance evidence

**Files:**
- Create: `tests/test_smtp_e2e.py`
- Create: `docs/verification/smtp-acceptance.md`

**Interfaces:**
- Consumes: complete SMTP path.
- Produces: proof of one redacted, allowlisted, TLS-negotiated delivery in a controlled environment.

- [ ] **Step 1: Build a synthetic local transport fixture**

Use an injectable fake SMTP server/transport; do not weaken production TLS rules. Capture message headers, body, attachments, and call count.

- [ ] **Step 2: Test delivery, retry, duplicate suppression, and secret absence**

Run: `python -m pytest tests/test_smtp_e2e.py -q`

Expected: exactly one accepted message after a retry scenario, zero duplicated deliveries, and no synthetic password/token/cookie in captured content or logs.

- [ ] **Step 3: Run the complete suite**

Run: `python -m pytest -q`

Expected: all tests pass.

- [ ] **Step 4: Record current evidence and commit**

Record exact commands, pass counts, transport states, and limitations in `docs/verification/smtp-acceptance.md`.

```powershell
git add tests/test_smtp_e2e.py docs/verification/smtp-acceptance.md
git commit -m "test: verify outbound report delivery"
```
