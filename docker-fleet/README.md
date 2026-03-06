# Agent-Hunter · Docker Scanner Fleet

A complete scanning infrastructure that runs as Docker containers and exposes a single REST API your Agent-Hunter backend calls.

---

## Architecture

```
Agent-Hunter Backend
        │
        ▼  POST /scan
┌─────────────────────┐
│   Orchestrator API  │  :8888  (FastAPI)
│   orchestrator/     │
└──────┬──────────────┘
       │  spawns / calls
  ┌────┴──────────────────────────┐
  │                               │
  ▼                               ▼
ZAP :8090          Nmap / Trivy / Semgrep
(Web scanner)      (run on demand)
```

| Container            | Tool    | Scans for                                          |
|----------------------|---------|----------------------------------------------------|
| hunter-orchestrator  | FastAPI | Central API — Agent-Hunter calls this               |
| hunter-zap           | ZAP     | XSS, SQLi, CSRF, SSRF, command injection            |
| hunter-nmap          | Nmap    | Open ports, service versions, vuln scripts          |
| hunter-trivy         | Trivy   | CVEs in npm/pip/go/maven packages                   |
| hunter-semgrep       | Semgrep | Hardcoded secrets, weak crypto, injection patterns  |

---

## Quick Start

```bash
cd docker-fleet
chmod +x start.sh
./start.sh
```

---

## API Reference

### Start a scan
```http
POST http://localhost:8888/scan
Content-Type: application/json

{
  "url": "https://testphp.vulnweb.com",
  "modules": ["web", "network", "dependency", "sast"],
  "depth": "medium",
  "auth_cookie": null
}
```

**Response:**
```json
{ "scan_id": "a3f7c2b1", "status": "queued" }
```

### Poll for results
```http
GET http://localhost:8888/scan/a3f7c2b1
```

### Live log stream (SSE)
```http
GET http://localhost:8888/scan/a3f7c2b1/stream
```

### List all scans
```http
GET http://localhost:8888/scans
```

### Delete a scan
```http
DELETE http://localhost:8888/scan/a3f7c2b1
```

---

## Integrate with Agent-Hunter Backend

### Python
```python
import httpx
import time

ORCHESTRATOR = "http://localhost:8888"

def run_scan(url: str, modules: list[str], depth: str = "medium") -> dict:
    # Start scan
    r = httpx.post(f"{ORCHESTRATOR}/scan", json={
        "url": url,
        "modules": modules,
        "depth": depth,
    }, timeout=10)
    scan_id = r.json()["scan_id"]
    print(f"Scan started: {scan_id}")

    # Poll until complete
    while True:
        r = httpx.get(f"{ORCHESTRATOR}/scan/{scan_id}", timeout=10)
        data = r.json()
        status = data["status"]
        print(f"  Status: {status} | Findings so far: {len(data['findings'])}")
        if status in ("complete", "failed"):
            break
        time.sleep(5)

    return data

# Usage
result = run_scan("https://testphp.vulnweb.com", ["web", "network"])
print(f"Total findings: {result['summary']['total']}")
print(f"Critical: {result['summary']['by_severity']['CRITICAL']}")
```

### Live streaming (Python + SSE)
```python
import httpx
import json

with httpx.stream("GET", f"http://localhost:8888/scan/{scan_id}/stream") as r:
    for line in r.iter_lines():
        if line.startswith("data:"):
            event = json.loads(line[5:])
            print(f"[{event['ts']}] [{event['module']}] {event['message']}")
```

---

## Why WebGoat returned 0 findings

WebGoat **requires authentication** — its vulnerable pages are behind login. To scan it properly:

1. Open http://localhost:8012/WebGoat in your browser
2. Log in (default: guest / guest)
3. Open DevTools → Application → Cookies
4. Copy the `JSESSIONID` value
5. Pass it to the scan:

```json
{
  "url": "http://localhost:8012/WebGoat",
  "auth_cookie": "JSESSIONID=YOUR_SESSION_ID_HERE",
  "modules": ["web"]
}
```

For public targets that don't need auth (good for testing):
- `http://testphp.vulnweb.com` — Acunetix PHP test site
- `http://testaspnet.vulnweb.com` — Acunetix ASP.NET test site
- `http://scanme.nmap.org` — Nmap official test target

---

## Scan Depth Options

| Depth  | Speed  | Coverage |
|--------|--------|----------|
| light  | ~1 min | Surface only, no aggressive tests |
| medium | ~5 min | Balanced — recommended default |
| deep   | ~20min | Full vuln scripts, all attack vectors |

---

## Teardown
```bash
docker compose down
```
