# Agent-Hunter

## Description

Agent-Hunter is a sophisticated autonomous security scanning agent for web applications and APIs. It combines reconnaissance, adaptive scanner orchestration, reinforcement learning (RL), finding validation, reporting, and live operational interfaces.

This project is not a bug-bounty-only scanner. Bug bounty programs are one authorized usage context among broader security engineering use cases (for example, internal application security testing and authorized external assessments).

Important legal notice: Running this tool against systems without explicit written authorization is illegal in many jurisdictions and may lead to civil claims, criminal prosecution, financial penalties, and account or infrastructure termination. Only scan assets you own or are contractually authorized to test.

## Features

* Autonomous multi-stage scan pipeline: pre-engagement -> recon -> strategy -> scan -> validate -> reflect
* RL-driven adaptive module selection and reward-based learning across scans
* 25 registered scanner modules covering injection, authorization, authentication, files, configuration, transport, and reconnaissance checks
* Policy, scope, and safety enforcement before and during active testing
* Real-time dashboard with live logs, findings stream, and scan progress
* API-first architecture with FastAPI endpoints and SSE streaming
* Evidence-calibrated Markdown, JSON, and HTML reports with separate confirmed, suspected, unresolved, refuted, and coverage states
* Checksummed, versioned checkpoints with last-known-good recovery and policy-drift protection

## Tech Stack

Frontend:

* React (Vite)
* JavaScript
* HTML/CSS

Backend:

* Python
* FastAPI
* Uvicorn

Database:

* SQLite (runtime local data)

Version Control:

* Git
* GitHub

## Project Structure

project-name/
|
|- api_server.py
|- main.py
|- startservers.py
|- core/
|  |- orchestrator.py
|  |- Hunter_brain.py
|  |- models.py
|- scanners/
|  |- injection/
|  |- auth/
|  |- authz/
|  |- misconfig/
|  |- redirect/
|  |- recon/
|  |- ssrf/
|  |- xss/
|- recon/
|- dashboard/
|  |- src/
|  |- package.json
|- reports/
|- tests/
|- requirements.txt
|- README.md

## Installation

1. Clone the repository
   git clone https://github.com/Anantha-236/Agent-Hunter.git

2. Navigate to the project directory
   cd Agent-Hunter

3. Install dependencies
   pip install -r requirements.txt

4. Install dashboard dependencies
   cd dashboard
   npm install
   cd ..

## Usage

Run backend API server:

python -m uvicorn api_server:app --host 0.0.0.0 --port 8888 --reload

Run dashboard:

cd dashboard
npm run dev

Run a CLI scan only against a locally controlled or explicitly authorized target, with a current policy profile:

python main.py --target http://127.0.0.1:8000 --policy policies/authorized-local.json --yes --no-tui

Open in browser:
http://localhost:5173

## Evidence and coverage meanings

Findings use explicit evidence states: `observed`, `suspected`, `confirmed`, `refuted`, `unresolved`, and `not_tested`. A finding is not considered confirmed merely because a response changed; confirmation requires the scanner's declared validator evidence and controls.

Coverage is reported independently as `tested`, `not_applicable`, `blocked`, `deferred`, `failed`, or `not_tested`. “No finding” is not proof that a vulnerability class was fully tested. Reports include the decision reason and policy snapshot hash, while secret-bearing values are redacted before serialization.

Interrupted scans are stored under `reports/checkpoints/<scan-id>/checkpoint.json`. Resume accepts only a matching target and policy snapshot. A corrupt active checkpoint may recover from the newest valid checksummed backup. An unfinished non-idempotent action is escalated for human review and is never replayed automatically.

## Outbound report email

Email is outbound-only and opt-in. Ordinary scans and report generation never create an outbox item or contact an SMTP server. Agent-Hunter does not read inboxes, retrieve OTPs, solve MFA/CAPTCHAs, log in to Bugcrowd or HackerOne, or submit vulnerability reports.

If an app password has ever been pasted into chat, a terminal command, a log, or a committed file, revoke it at the provider before doing anything else. Create a new app-specific password and place it only in the ignored `.env.local` file or an operating-system secret provider. Never put a real credential in `.env.local.example`.

Install development dependencies for the complete test suite with `pip install -r requirements-dev.txt`. Copy the empty SMTP keys from `.env.local.example` into `.env.local` and configure:

```text
SMTP_HOST=smtp.provider.example
SMTP_PORT=587
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-new-app-password
SMTP_STARTTLS=true
SMTP_REPORT_FROM=your-verified-sender@example.com
SMTP_REPORT_TO=your-allowed-recipient@example.com
SMTP_RECIPIENT_ALLOWLIST=your-allowed-recipient@example.com
SMTP_MAX_ATTACHMENT_BYTES=5242880
HUNTER_LOCAL_API_TOKEN=a-long-random-local-token
```

`SMTP_STARTTLS` must be true. Recipient values are normalized and must be present in the allowlist. Reports that exceed the size limit, contain unredacted secret fields, or are not UTF-8 text are rejected before they enter the outbox.

To send the redacted JSON artifact after an authorized scan, add `--email-report` to the CLI command. To process retryable outbox items without running a scan, use `python main.py --retry-email-outbox`. Delivered and `delivery_unknown` items are never automatically resent.

The local API supports `POST /api/reports/{report_id}/email` only for a report ID already generated by the running API process. Supply `X-Agent-Hunter-Token` with the value of `HUNTER_LOCAL_API_TOKEN`. The endpoint does not accept filesystem paths and does not return SMTP credentials.

## API Endpoints (Optional for backend projects)

GET    /api/scans                 - List scans
POST   /api/scan                  - Start a new scan
GET    /api/scan/{scan_id}        - Get scan details
GET    /api/scan/{scan_id}/findings - Get findings
GET    /api/scan/{scan_id}/stream - Stream live scan events (SSE)
POST   /api/reports/{report_id}/email - Explicitly queue/deliver a known local report
GET    /api/settings              - Get settings
PUT    /api/settings              - Update settings

## Screenshots

Add screenshots of your project here.

## Contributing

1. Open an issue describing the proposed change.
2. Wait for written approval from the repository owner.
3. Create a branch and submit a pull request.
4. All pull requests require explicit owner review and approval.
5. Unauthorized modifications or redistribution are not permitted.

## License

Proprietary - All Rights Reserved.

No part of this repository may be copied, modified, distributed, sublicensed, or used for commercial or personal derivative work without explicit written permission from the repository owner.

## Author

Anantha
GitHub: https://github.com/Anantha-236
Email: [ananthagunde@gmail.com](mailto:ananthagunde@gmail.com)
