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

## API Endpoints (Optional for backend projects)

GET    /api/scans                 - List scans
POST   /api/scan                  - Start a new scan
GET    /api/scan/{scan_id}        - Get scan details
GET    /api/scan/{scan_id}/findings - Get findings
GET    /api/scan/{scan_id}/stream - Stream live scan events (SSE)
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
