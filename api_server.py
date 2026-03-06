"""
Agent-Hunter API Server
Wraps the Orchestrator with a FastAPI REST + SSE interface for the dashboard.

Run:
    uvicorn api_server:app --reload --port 8888
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from config.settings import ENABLED_MODULES
from core.models import Finding, Scope, Target, ScanState

logger = logging.getLogger(__name__)

app = FastAPI(title="Agent-Hunter API", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory scan store (single-process; swap for Redis in prod) ──
_scans: Dict[str, Dict[str, Any]] = {}


def _model_to_dict(model: BaseModel) -> Dict[str, Any]:
    """Support both Pydantic v1 (.dict) and v2 (.model_dump)."""
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


# ── Request / Response Schemas ─────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    modules: Optional[List[str]] = None
    depth: str = "medium"
    threads: int = 4
    in_scope: Optional[List[str]] = None
    out_scope: Optional[List[str]] = None
    verify_ssl: bool = True

class ScanSummary(BaseModel):
    scan_id: str
    status: str
    target: str
    started_at: str
    ended_at: Optional[str] = None
    finding_count: int = 0

class FindingOut(BaseModel):
    id: str
    title: str
    vuln_type: str
    severity: str
    url: str
    parameter: str
    description: str
    cwe_id: str
    module: str
    confirmed: bool
    confidence: float
    discovered_at: str

class SettingsPayload(BaseModel):
    timeout: int = 30
    user_agent: str = "AgentHunter/2.1"
    rate_limit: int = 10
    proxy: str = ""
    output_dir: str = "./results"
    auto_report: bool = True
    verify_ssl: bool = True
    follow_redirects: bool = True
    save_logs: bool = True

# Global mutable settings (demo-grade; use a DB / config file in prod)
_settings: Dict[str, Any] = _model_to_dict(SettingsPayload())


# ── Helpers ────────────────────────────────────────────────────

def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "vuln_type": f.vuln_type,
        "severity": f.severity,
        "url": f.url,
        "parameter": f.parameter,
        "description": f.description,
        "cwe_id": f.cwe_id,
        "module": f.module,
        "confirmed": f.confirmed,
        "confidence": f.confidence,
        "discovered_at": f.discovered_at.isoformat(),
    }


async def _run_scan(scan_id: str, req: ScanRequest):
    """Background task: run the orchestrator and push events into the store."""
    entry = _scans[scan_id]
    entry["status"] = "running"

    # Lazy-import the scanner stack so API health endpoints still work if
    # heavy scanner dependencies are missing or misconfigured.
    try:
        from core.orchestrator import Orchestrator
    except Exception as exc:
        logger.exception("Unable to load orchestrator")
        entry["status"] = "error"
        entry["errors"].append(f"orchestrator import failed: {exc}")
        entry["ended_at"] = datetime.utcnow().isoformat()
        entry["logs"].append({
            "ts": datetime.utcnow().strftime("%H:%M:%S"),
            "msg": f"Failed to start scan engine: {exc}",
        })
        return

    scope = None
    if req.in_scope:
        scope = Scope(
            allowed_domains=req.in_scope,
            excluded_domains=req.out_scope or [],
        )

    target = Target(url=req.url, scope=scope)
    modules = req.modules or list(ENABLED_MODULES)

    try:
        async with Orchestrator(
            target=target,
            modules=modules,
            use_tui=False,
            verify_ssl=req.verify_ssl,
            auto_confirm=True,
        ) as orch:
            # Monkey-patch log_thought so we can capture thoughts in real time
            _orig_log_thought = ScanState.log_thought

            def _patched_log_thought(self, thought: str):
                _orig_log_thought(self, thought)
                entry["logs"].append({
                    "ts": datetime.utcnow().strftime("%H:%M:%S"),
                    "msg": thought,
                })

            ScanState.log_thought = _patched_log_thought
            try:
                state = await orch.run()
            finally:
                ScanState.log_thought = _orig_log_thought

            entry["findings"] = [_finding_to_dict(f) for f in state.findings]
            entry["phase"] = state.phase
            entry["errors"] = state.errors
            entry["stats"] = state.stats()
            entry["status"] = "complete"
            entry["ended_at"] = datetime.utcnow().isoformat()

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        entry["status"] = "error"
        entry["errors"].append(str(exc))
        entry["ended_at"] = datetime.utcnow().isoformat()


# ── Endpoints ──────────────────────────────────────────────────

@app.post("/api/scan", response_model=ScanSummary, status_code=201)
async def start_scan(req: ScanRequest):
    """Launch a new scan. Returns immediately with a scan_id."""
    scan_id = str(uuid.uuid4())
    _scans[scan_id] = {
        "scan_id": scan_id,
        "status": "starting",
        "target": req.url,
        "started_at": datetime.utcnow().isoformat(),
        "ended_at": None,
        "findings": [],
        "logs": [],
        "errors": [],
        "phase": "init",
        "stats": {},
    }
    asyncio.create_task(_run_scan(scan_id, req))
    return ScanSummary(
        scan_id=scan_id,
        status="starting",
        target=req.url,
        started_at=_scans[scan_id]["started_at"],
    )


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get full scan state including findings."""
    if scan_id not in _scans:
        raise HTTPException(404, "Scan not found")
    return _scans[scan_id]


@app.get("/api/scan/{scan_id}/findings")
async def get_findings(scan_id: str):
    """Get findings for a scan."""
    if scan_id not in _scans:
        raise HTTPException(404, "Scan not found")
    return _scans[scan_id]["findings"]


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """
    SSE stream for live scan progress.
    Events: log, finding, phase, status, stats, error, done
    """
    if scan_id not in _scans:
        raise HTTPException(404, "Scan not found")

    async def event_generator():
        entry = _scans[scan_id]
        sent_logs = 0
        sent_findings = 0
        last_phase = None
        last_status = None

        while True:
            # Stream new log lines
            while sent_logs < len(entry["logs"]):
                log = entry["logs"][sent_logs]
                yield f"event: log\ndata: {json.dumps(log)}\n\n"
                sent_logs += 1

            # Stream new findings
            while sent_findings < len(entry["findings"]):
                finding = entry["findings"][sent_findings]
                yield f"event: finding\ndata: {json.dumps(finding)}\n\n"
                sent_findings += 1

            # Phase changes
            if entry["phase"] != last_phase:
                last_phase = entry["phase"]
                yield f"event: phase\ndata: {json.dumps({'phase': last_phase})}\n\n"

            # Status changes
            if entry["status"] != last_status:
                last_status = entry["status"]
                yield f"event: status\ndata: {json.dumps({'status': last_status})}\n\n"

                if last_status in ("complete", "error"):
                    yield f"event: stats\ndata: {json.dumps(entry.get('stats', {}))}\n\n"
                    if entry["errors"]:
                        yield f"event: error\ndata: {json.dumps({'errors': entry['errors']})}\n\n"
                    yield f"event: done\ndata: {json.dumps({'scan_id': scan_id})}\n\n"
                    return

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/scans")
async def list_scans():
    """List all scans (summary only)."""
    return [
        ScanSummary(
            scan_id=s["scan_id"],
            status=s["status"],
            target=s["target"],
            started_at=s["started_at"],
            ended_at=s.get("ended_at"),
            finding_count=len(s["findings"]),
        )
        for s in _scans.values()
    ]


@app.get("/api/settings")
async def get_settings():
    return _settings


@app.put("/api/settings")
async def update_settings(payload: SettingsPayload):
    global _settings
    _settings = _model_to_dict(payload)
    return _settings
