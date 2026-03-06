# Agent-Hunter Test Suite

A self-contained, Docker-based test environment covering all four scan categories:
**Web App (XSS/SQLi)** · **Network/Port Scanning** · **Dependency/CVE** · **SAST**

---

## Quick Start

### 1. Prerequisites
- Docker + Docker Compose
- Python 3.8+ (for the validator script)

```bash
pip install pyyaml
```

### 2. Spin up all targets

```bash
docker-compose up -d
```

Wait ~30 seconds for all containers to initialize.

### 3. Verify targets are live

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8010   # DVWA          → 200
curl -s -o /dev/null -w "%{http_code}" http://localhost:8011   # Juice Shop    → 200
curl -s -o /dev/null -w "%{http_code}" http://localhost:8012/WebGoat  # WebGoat → 200
curl -s http://localhost:8030/package.json | head -3            # NPM manifest
curl -s http://localhost:8040/vuln_app.py | head -3             # SAST target
```

---

## Target URLs

| Category        | Target             | URL                                    | What to find                        |
|-----------------|--------------------|----------------------------------------|-------------------------------------|
| Web App         | DVWA               | `http://localhost:8010`                | SQLi, XSS, RCE, LFI, CSRF          |
| Web App         | OWASP Juice Shop   | `http://localhost:8011`                | SQLi, XSS, IDOR, SSRF, Broken Auth |
| Web App         | WebGoat            | `http://localhost:8012/WebGoat`        | Full OWASP Top 10                   |
| Network         | Metasploitable     | `172.30.0.20`                          | Open ports, outdated services       |
| Dependency/CVE  | NPM manifest       | `http://localhost:8030/package.json`   | 7 known CVE packages                |
| Dependency/CVE  | Python manifest    | `http://localhost:8030/requirements.txt` | 5 known CVE packages              |
| SAST            | Python code        | `http://localhost:8040/vuln_app.py`    | Secrets, SQLi, RCE, weak crypto     |
| SAST            | JS/Node.js code    | `http://localhost:8040/vuln_app.js`    | Secrets, XSS, eval, prototype poll  |

---

## Running Your Agent

Point Agent-Hunter at each target URL and collect output as JSON:

```bash
# Example — adjust to your agent's CLI
agent-hunter scan --url http://localhost:8010 --output results-dvwa.json
agent-hunter scan --url http://localhost:8011 --output results-juice.json
agent-hunter scan --url http://localhost:8030/package.json --mode dependency --output results-npm.json
agent-hunter scan --url http://localhost:8040/vuln_app.py --mode sast --output results-sast.json
```

Your agent's JSON output should follow this schema:
```json
[
  {
    "type": "SQLi",
    "url": "http://localhost:8010/vulnerabilities/sqli/",
    "category": "web",
    "severity": "CRITICAL",
    "description": "Optional details..."
  }
]
```

---

## Validating Results

Run the validator against the ground-truth findings:

```bash
python3 scripts/validate_results.py --agent-output results-dvwa.json
```

**Example output:**
```
════════════════════════════════════════════════════════════
  AGENT-HUNTER VALIDATION SCORECARD
════════════════════════════════════════════════════════════

  ✅ [WEB]
     True Positives  : 6
     False Positives : 1
     False Negatives : 1
     Precision       : 86%
     Recall          : 86%
     F1 Score        : 0.86

  ⚠️  [NETWORK]
     ...

────────────────────────────────────────────────────────────
  OVERALL  —  Precision: 80%  |  Recall: 78%  |  F1: 0.79
════════════════════════════════════════════════════════════
```

---

## Ground Truth

All expected findings with line numbers, CVE IDs, and severity levels are in:
```
expected-findings/findings.yaml
```

Edit this file to add more test cases as your agent evolves.

---

## Teardown

```bash
docker-compose down
```

> ⚠️ **Security reminder:** These containers are intentionally vulnerable.
> Run them only on a local or isolated network. Never expose their ports publicly.
