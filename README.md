# Agent-Hunter

## Description

Agent-Hunter is an autonomous security testing and vulnerability scanning platform for web applications and APIs. It combines reconnaissance, scanner orchestration, validation, reporting, and a live dashboard so security teams can identify and prioritize vulnerabilities quickly.

Important legal notice: Running this tool against systems without explicit written authorization is illegal in many jurisdictions and may lead to civil claims, criminal prosecution, financial penalties, and account or infrastructure termination. Only scan assets you own or are contractually authorized to test.

## Features

* Multi-module vulnerability scanning (SQLi, XSS, SSRF, XXE, IDOR, CSRF, misconfig, and more)
* Real-time dashboard with live logs, findings stream, and scan progress
* API-first architecture with FastAPI endpoints and SSE streaming
* Automated report generation in Markdown and JSON formats

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

Run CLI scan:

python main.py --target http://testphp.vulnweb.com --yes --no-tui

Open in browser:
http://localhost:5173

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
Email: [your-email@example.com](mailto:your-email@example.com)
