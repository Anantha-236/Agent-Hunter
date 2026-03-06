"""
Agent-Hunter Orchestrator API
==============================
Agent-Hunter backend calls:
  POST /scan          — start a full scan, returns scan_id
  GET  /scan/{id}     — get status + results
  GET  /scan/{id}/stream — SSE stream of live log events
  GET  /scans         — list all past scans
  DELETE /scan/{id}   — delete scan record
"""

import asyncio
import json
import os
import uuid
from datetime import datetime
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from scanners.web import run_web_scan
from scanners.network import run_network_scan
from scanners.dependency import run_dependency_scan
from scanners.sast import run_sast_scan

app = FastAPI(title="Agent-Hunter Orchestrator", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory scan store (replace with DB for production) ──
SCANS: dict[str, dict] = {}


# ── Request / Response models ──────────────────────────────

class ScanRequest(BaseModel):
    url: str
    modules: list[str] = ["web", "network", "dependency", "sast"]
    depth: str = "medium"           # light | medium | deep
    threads: int = 4
    auth_cookie: str | None = None  # optional session cookie for authenticated scans


class Finding(BaseModel):
    id: str
    type: str
    severity: str                   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str                   # web | network | dependency | sast
    location: str
    description: str
    cve: str | None = None
    remediation: str | None = None
    raw: dict | None = None


class ScanResult(BaseModel):
    scan_id: str
    url: str
    status: str                     # queued | running | complete | failed
    started_at: str | None = None
    completed_at: str | None = None
    modules_requested: list[str]
    modules_completed: list[str]
    findings: list[dict]
    summary: dict
    logs: list[dict]


# ── Helpers ────────────────────────────────────────────────

def make_summary(findings: list[dict]) -> dict:
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    cats = {"web": 0, "network": 0, "dependency": 0, "sast": 0}
    for f in findings:
        s = f.get("severity", "INFO")
        if s in sev:
            sev[s] += 1
        c = f.get("category", "web")
        if c in cats:
            cats[c] += 1
    return {"by_severity": sev, "by_category": cats, "total": len(findings)}


def log_event(scan_id: str, level: str, module: str, message: str):
    entry = {
        "ts": datetime.now().strftime("%H:%M:%S"),
        "level": level,         # INFO | WARN | CRITICAL | ERROR
        "module": module,
        "message": message,
    }
    if scan_id in SCANS:
        SCANS[scan_id]["logs"].append(entry)
    return entry


# ── Background scan runner ─────────────────────────────────

async def run_scan(scan_id: str, request: ScanRequest):
    scan = SCANS[scan_id]
    scan["status"] = "running"
    scan["started_at"] = datetime.now().isoformat()
    findings = []

    log_event(scan_id, "INFO", "orchestrator", f"Scan started → {request.url}")
    log_event(scan_id, "INFO", "orchestrator", f"Modules: {', '.join(request.modules)}")

    module_runners = {
        "web":        (run_web_scan,        "ZAP"),
        "network":    (run_network_scan,    "Nmap"),
        "dependency": (run_dependency_scan, "Trivy"),
        "sast":       (run_sast_scan,       "Semgrep"),
    }

    for module in request.modules:
        if module not in module_runners:
            log_event(scan_id, "WARN", "orchestrator", f"Unknown module '{module}' — skipping")
            continue

        runner, tool_name = module_runners[module]
        log_event(scan_id, "INFO", module, f"Starting {tool_name} scan…")
        scan["status_module"] = module

        try:
            results = await runner(
                url=request.url,
                depth=request.depth,
                auth_cookie=request.auth_cookie,
                scan_id=scan_id,
                log_fn=lambda lvl, msg, m=module: log_event(scan_id, lvl, m, msg),
            )
            findings.extend(results)
            scan["modules_completed"].append(module)
            log_event(scan_id, "INFO", module, f"{tool_name} complete — {len(results)} findings")

        except Exception as e:
            log_event(scan_id, "ERROR", module, f"{tool_name} failed: {str(e)}")

    scan["findings"] = findings
    scan["summary"] = make_summary(findings)
    scan["status"] = "complete"
    scan["completed_at"] = datetime.now().isoformat()

    log_event(scan_id, "INFO", "orchestrator",
              f"Scan complete — {len(findings)} findings total · "
              f"{scan['summary']['by_severity']['CRITICAL']} critical")

    # Persist to /results
    results_path = os.path.join(os.getenv("RESULTS_DIR", "/results"), f"{scan_id}.json")
    try:
        with open(results_path, "w") as f:
            json.dump(scan, f, indent=2)
    except Exception:
        pass


# ── API Routes ─────────────────────────────────────────────

@app.get("/")
async def health():
    return {"status": "ok", "service": "agent-hunter-orchestrator", "version": "2.1.0"}


@app.post("/scan", response_model=dict)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())[:8]
    SCANS[scan_id] = {
        "scan_id":           scan_id,
        "url":               request.url,
        "status":            "queued",
        "status_module":     None,
        "started_at":        None,
        "completed_at":      None,
        "modules_requested": request.modules,
        "modules_completed": [],
        "findings":          [],
        "summary":           {},
        "logs":              [],
    }
    background_tasks.add_task(run_scan, scan_id, request)
    return {"scan_id": scan_id, "status": "queued",
            "message": f"Scan queued. Poll /scan/{scan_id} for results."}


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    return SCANS[scan_id]


@app.get("/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """SSE endpoint — Agent-Hunter frontend connects here for live logs."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator() -> AsyncGenerator[str, None]:
        sent = 0
        while True:
            scan = SCANS.get(scan_id, {})
            logs = scan.get("logs", [])

            # Send any new log lines
            while sent < len(logs):
                entry = logs[sent]
                yield f"data: {json.dumps(entry)}\n\n"
                sent += 1

            if scan.get("status") in ("complete", "failed"):
                # Send final summary event then close
                yield f"data: {json.dumps({'type': 'done', 'summary': scan.get('summary', {})})}\n\n"
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/scans")
async def list_scans():
    return [
        {"scan_id": s["scan_id"], "url": s["url"], "status": s["status"],
         "started_at": s["started_at"], "total_findings": len(s["findings"])}
        for s in SCANS.values()
    ]


@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    del SCANS[scan_id]
    return {"deleted": scan_id}
