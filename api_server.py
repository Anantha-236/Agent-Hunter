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
from core.models import Finding, Scope, Target

logger = logging.getLogger(__name__)

app = FastAPI(title="Agent-Hunter API", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory stores (single-process; swap for Redis in prod) ──
_scans: Dict[str, Dict[str, Any]] = {}
_recons: Dict[str, Dict[str, Any]] = {}


def _model_to_dict(model: BaseModel) -> Dict[str, Any]:
    """Support both Pydantic v1 (.dict) and v2 (.model_dump)."""
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def normalize_settings_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Accept either camelCase or snake_case settings payloads."""
    return {
        "timeout": int(payload.get("timeout", 30)),
        "user_agent": payload.get("user_agent", payload.get("userAgent", "AgentHunter/2.1")),
        "rate_limit": int(payload.get("rate_limit", payload.get("rateLimit", 10))),
        "proxy": payload.get("proxy", ""),
        "output_dir": payload.get("output_dir", payload.get("outputDir", "./results")),
        "auto_report": bool(payload.get("auto_report", payload.get("autoReport", True))),
        "verify_ssl": bool(payload.get("verify_ssl", payload.get("verifySsl", True))),
        "follow_redirects": bool(payload.get("follow_redirects", payload.get("followRedirects", True))),
        "save_logs": bool(payload.get("save_logs", payload.get("saveLogs", True))),
    }


def _runtime_settings(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    settings = dict(_settings)
    settings.update(overrides or {})
    return settings


def _build_scope(
    in_scope: Optional[List[str]],
    out_scope: Optional[List[str]],
    selected_assets: Optional[List[str]] = None,
) -> Optional[Scope]:
    allowed_domains = list(in_scope or [])
    excluded_domains = list(out_scope or [])
    allowed_urls = list(selected_assets or [])
    if not allowed_domains and not excluded_domains and not allowed_urls:
        return None
    return Scope(
        allowed_domains=allowed_domains,
        allowed_urls=allowed_urls,
        excluded_domains=excluded_domains,
    )


# ── Request / Response Schemas ─────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    modules: Optional[List[str]] = None
    depth: str = "medium"
    threads: int = 4
    in_scope: Optional[List[str]] = None
    out_scope: Optional[List[str]] = None
    instructions: str = ""
    selected_assets: Optional[List[str]] = None
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

class ReconRequest(BaseModel):
    url: str
    in_scope: Optional[List[str]] = None
    out_scope: Optional[List[str]] = None
    instructions: str = ""

# Global mutable settings (demo-grade; use a DB / config file in prod)
_settings: Dict[str, Any] = _model_to_dict(SettingsPayload())


# ── Helpers ────────────────────────────────────────────────────

# Dashboard sends high-level groups; orchestrator needs concrete scanner IDs.
MODULE_GROUP_MAP: Dict[str, List[str]] = {
    "web": list(ENABLED_MODULES),
    "sast": ["misconfig_scanner"],
    "dependency": ["misconfig_scanner"],
    "network": ["subdomain_takeover", "host_header"],
}

DEPTH_TO_CRAWL = {
    "light": 1,
    "medium": 3,
    "deep": 5,
}


def _resolve_crawl_depth(depth: str) -> int:
    depth_key = (depth or "medium").strip().lower()
    if depth_key in DEPTH_TO_CRAWL:
        return DEPTH_TO_CRAWL[depth_key]
    try:
        return max(1, min(int(depth_key), 10))
    except ValueError:
        return DEPTH_TO_CRAWL["medium"]


def _resolve_modules(requested_modules: Optional[List[str]]) -> List[str]:
    """Resolve UI module groups and scanner IDs to a valid scanner list."""
    if not requested_modules:
        return list(ENABLED_MODULES)

    resolved: List[str] = []
    for module in requested_modules:
        key = (module or "").strip().lower()
        if key in MODULE_GROUP_MAP:
            resolved.extend(MODULE_GROUP_MAP[key])
        elif key in ENABLED_MODULES:
            resolved.append(key)

    # If request only had unknown groups, fail open to default scanners.
    if not resolved:
        return list(ENABLED_MODULES)

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(resolved))

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

    runtime_settings = _runtime_settings({"verify_ssl": req.verify_ssl})
    scope = _build_scope(req.in_scope, req.out_scope, req.selected_assets)

    target = Target(
        url=req.url,
        scope=scope,
        selected_assets=list(req.selected_assets or []),
        in_scope=list(req.in_scope or []),
        out_scope=list(req.out_scope or []),
    )
    if req.instructions:
        target.metadata["instructions"] = req.instructions
    if req.selected_assets:
        target.metadata["selected_assets"] = req.selected_assets
    modules = _resolve_modules(req.modules)
    crawl_depth = _resolve_crawl_depth(req.depth)
    max_threads = max(1, min(req.threads, 64))

    def _on_thought(thought: str) -> None:
        entry["logs"].append({
            "ts": datetime.utcnow().strftime("%H:%M:%S"),
            "msg": thought,
        })

    try:
        async with Orchestrator(
            target=target,
            modules=modules,
            use_tui=False,
            headers={"User-Agent": runtime_settings["user_agent"]},
            proxy=runtime_settings["proxy"] or None,
            verify_ssl=runtime_settings["verify_ssl"],
            auto_confirm=True,
            crawl_depth=crawl_depth,
            http_concurrency=max_threads,
            http_settings=runtime_settings,
        ) as orch:
            state = await orch.run(
                thought_callback=_on_thought,
                runtime_settings=runtime_settings,
            )

            entry["findings"] = [_finding_to_dict(f) for f in state.findings]
            entry["phase"] = state.phase
            entry["errors"] = state.errors
            entry["stats"] = state.stats()
            if state.phase == "complete":
                entry["status"] = "complete"
            elif state.phase == "aborted":
                entry["status"] = "aborted"
            else:
                entry["status"] = "error"
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
    Events: log, finding, phase, status, stats, scan_error, done
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

                if last_status in ("complete", "error", "aborted"):
                    yield f"event: stats\ndata: {json.dumps(entry.get('stats', {}))}\n\n"
                    if entry["errors"]:
                        yield f"event: scan_error\ndata: {json.dumps({'errors': entry['errors']})}\n\n"
                    yield f"event: done\ndata: {json.dumps({'scan_id': scan_id, 'status': last_status})}\n\n"
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


@app.get("/api/modules")
async def list_modules():
    """List available scanner module IDs for dashboard selection."""
    return list(ENABLED_MODULES)


@app.get("/api/settings")
async def get_settings():
    return _settings


@app.put("/api/settings")
async def update_settings(payload: Dict[str, Any]):
    global _settings
    normalized = normalize_settings_payload(payload)
    _settings = _model_to_dict(SettingsPayload(**normalized))
    return _settings


# ── Recon (Asset Discovery) ────────────────────────────────────

async def _run_recon(recon_id: str, req: ReconRequest):
    """Background task: run asset discovery and push events into the store."""
    entry = _recons[recon_id]
    try:
        from recon.asset_discovery import AssetDiscovery
        scope = _build_scope(req.in_scope, req.out_scope)
        runtime_settings = _runtime_settings()
        discovery = AssetDiscovery(
            scope=scope,
            verify_ssl=runtime_settings["verify_ssl"],
            follow_redirects=runtime_settings["follow_redirects"],
            user_agent=runtime_settings["user_agent"],
        )

        def on_event(event_type: str, data: dict):
            entry["logs"].append({
                "ts": datetime.utcnow().strftime("%H:%M:%S"),
                "type": event_type,
                "data": data,
            })
            if event_type == "subdomain":
                entry["subdomains"].append(data)
            elif event_type == "port":
                entry["ports"].append(data)
            elif event_type == "technology":
                tech = data.get("tech", "")
                if tech and tech not in entry["technologies"]:
                    entry["technologies"].append(tech)

        await discovery.discover(req.url, on_event=on_event)
        entry["status"] = "complete"
        entry["ended_at"] = datetime.utcnow().isoformat()
    except Exception as exc:
        logger.exception("Recon %s failed", recon_id)
        entry["status"] = "error"
        entry["errors"].append(str(exc))
        entry["ended_at"] = datetime.utcnow().isoformat()


@app.post("/api/recon", status_code=201)
async def start_recon(req: ReconRequest):
    """Start asset discovery for a target. Returns a recon_id."""
    recon_id = str(uuid.uuid4())
    _recons[recon_id] = {
        "recon_id": recon_id,
        "status": "running",
        "target": req.url,
        "in_scope": req.in_scope or [],
        "out_scope": req.out_scope or [],
        "instructions": req.instructions,
        "started_at": datetime.utcnow().isoformat(),
        "ended_at": None,
        "subdomains": [],
        "ports": [],
        "technologies": [],
        "logs": [],
        "errors": [],
    }
    asyncio.create_task(_run_recon(recon_id, req))
    return {"recon_id": recon_id, "status": "running"}


@app.get("/api/recon/{recon_id}")
async def get_recon(recon_id: str):
    """Get full recon result."""
    if recon_id not in _recons:
        raise HTTPException(404, "Recon not found")
    return _recons[recon_id]


@app.get("/api/recon/{recon_id}/stream")
async def stream_recon(recon_id: str):
    """SSE stream for live asset discovery events."""
    if recon_id not in _recons:
        raise HTTPException(404, "Recon not found")

    async def event_generator():
        entry = _recons[recon_id]
        sent_logs = 0

        while True:
            while sent_logs < len(entry["logs"]):
                log = entry["logs"][sent_logs]
                yield f"event: {log['type']}\ndata: {json.dumps(log['data'])}\n\n"
                sent_logs += 1

            if entry["status"] in ("complete", "error"):
                yield f"event: done\ndata: {json.dumps({'recon_id': recon_id, 'status': entry['status']})}\n\n"
                return

            await asyncio.sleep(0.3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
