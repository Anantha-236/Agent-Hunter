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
import os
import uuid
from collections import OrderedDict
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
MAX_SCANS = 50
_scans: OrderedDict[str, Dict[str, Any]] = OrderedDict()
_recons: Dict[str, Dict[str, Any]] = {}
REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


# ── Cyber Kill Chain Mapping ────────────────────────────────────

KILL_CHAIN_STAGES = [
    {
        "id": "reconnaissance",
        "name": "Reconnaissance",
        "number": 1,
        "icon": "🔍",
        "description": "Information gathering about the target — discovering subdomains, technologies, open ports, exposed services, and mapping the attack surface.",
        "modules": ["subdomain_takeover", "ssl_tls_scanner", "misconfig_scanner", "cors_scanner", "header_security", "sensitive_data_exposure"],
        "vuln_types": ["information_disclosure", "technology_detection", "subdomain_takeover", "ssl_weakness", "missing_headers", "cors_misconfiguration", "directory_listing"],
    },
    {
        "id": "weaponization",
        "name": "Weaponization",
        "number": 2,
        "icon": "⚔️",
        "description": "Crafting attack payloads — constructing SQL injection strings, XSS vectors, template injection payloads, and command injection sequences.",
        "modules": ["xss_scanner", "sql_injection", "ssti", "command_injection", "xxe_scanner", "graphql_scanner"],
        "vuln_types": ["xss", "sqli", "ssti", "command_injection", "xxe", "graphql_introspection"],
    },
    {
        "id": "delivery",
        "name": "Delivery",
        "number": 3,
        "icon": "📦",
        "description": "Delivering the attack to the victim — via CSRF tokens, open redirects, host header injection, CRLF response splitting, and phishing vectors.",
        "modules": ["csrf_scanner", "open_redirect", "host_header", "crlf_injection"],
        "vuln_types": ["csrf", "open_redirect", "host_header_injection", "crlf_injection", "http_response_splitting"],
    },
    {
        "id": "exploitation",
        "name": "Exploitation",
        "number": 4,
        "icon": "💥",
        "description": "Exploiting discovered vulnerabilities — triggering SQL injection, executing XSS, exploiting SSRF, achieving path traversal to exfiltrate data or gain access.",
        "modules": ["sql_injection", "xss_scanner", "ssti", "command_injection", "xxe_scanner", "ssrf", "path_traversal", "lfi_rfi_scanner"],
        "vuln_types": ["sqli", "xss", "ssti", "command_injection", "xxe", "ssrf", "path_traversal", "lfi", "rfi", "file_inclusion"],
    },
    {
        "id": "installation",
        "name": "Installation",
        "number": 5,
        "icon": "🔧",
        "description": "Establishing persistence — uploading web shells via file inclusion, writing files through path traversal, or planting backdoors via command injection.",
        "modules": ["path_traversal", "lfi_rfi_scanner", "command_injection", "xxe_scanner"],
        "vuln_types": ["file_upload", "file_write", "rfi", "webshell", "path_traversal", "lfi"],
    },
    {
        "id": "command_control",
        "name": "Command & Control",
        "number": 6,
        "icon": "📡",
        "description": "Establishing outbound communication — leveraging SSRF for internal network access, open redirects for data exfiltration, and host header poisoning for C2 channels.",
        "modules": ["ssrf", "open_redirect", "host_header"],
        "vuln_types": ["ssrf", "open_redirect", "host_header_injection", "dns_rebinding"],
    },
    {
        "id": "actions_on_objectives",
        "name": "Actions on Objectives",
        "number": 7,
        "icon": "🎯",
        "description": "Achieving the attacker's goal — data exfiltration via IDOR, privilege escalation through broken access control, account takeover, and sensitive data exposure.",
        "modules": ["idor_scanner", "auth_scanner", "jwt_scanner", "broken_access_control", "rate_limit_scanner", "race_condition", "sensitive_data_exposure"],
        "vuln_types": ["idor", "broken_access_control", "authentication_bypass", "jwt_weakness", "privilege_escalation", "rate_limiting", "race_condition", "data_exposure", "account_takeover"],
    },
]


def _map_finding_to_kill_chain(finding: Dict[str, Any]) -> str:
    """Map a single finding to its primary kill chain stage."""
    module = (finding.get("module") or "").lower()
    vuln_type = (finding.get("vuln_type") or finding.get("title") or "").lower().replace(" ", "_")
    severity = (finding.get("severity") or "").lower()

    # Score each stage — higher score = better match
    best_stage = "exploitation"  # default fallback
    best_score = 0

    for stage in KILL_CHAIN_STAGES:
        score = 0
        # Module match (strong signal)
        if module in stage["modules"]:
            score += 10
        # Vuln type substring match
        for vt in stage["vuln_types"]:
            if vt in vuln_type or vuln_type in vt:
                score += 8
                break
        # Partial module name match
        for sm in stage["modules"]:
            if sm in module or module in sm:
                score += 3
                break

        if score > best_score:
            best_score = score
            best_stage = stage["id"]

    return best_stage


def _build_kill_chain_report(scan_entry: Dict[str, Any]) -> Dict[str, Any]:
    """Build a full Cyber Kill Chain structured report from a scan entry."""
    findings = scan_entry.get("findings", [])
    target = scan_entry.get("target", "")

    # Map findings to stages
    stage_findings: Dict[str, List[Dict[str, Any]]] = {s["id"]: [] for s in KILL_CHAIN_STAGES}
    for f in findings:
        stage_id = _map_finding_to_kill_chain(f)
        f_copy = dict(f)
        f_copy["kill_chain_stage"] = stage_id
        stage_findings[stage_id].append(f_copy)

    # Build stage summaries
    stages = []
    total_findings = len(findings)
    stages_with_findings = 0
    max_severity_overall = "info"
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for stage in KILL_CHAIN_STAGES:
        stage_f = stage_findings[stage["id"]]
        if stage_f:
            stages_with_findings += 1

        # Compute stage risk level
        stage_max_sev = "info"
        for f in stage_f:
            sev = (f.get("severity") or "info").lower()
            if severity_rank.get(sev, 0) > severity_rank.get(stage_max_sev, 0):
                stage_max_sev = sev
        if severity_rank.get(stage_max_sev, 0) > severity_rank.get(max_severity_overall, 0):
            max_severity_overall = stage_max_sev

        # Architecture location analysis
        arch_locations = []
        for f in stage_f:
            url = f.get("url", "")
            param = f.get("parameter", "")
            module = f.get("module", "")
            loc = _infer_architecture_location(url, param, module, f.get("vuln_type", ""))
            if loc and loc not in arch_locations:
                arch_locations.append(loc)

        stages.append({
            "id": stage["id"],
            "name": stage["name"],
            "number": stage["number"],
            "icon": stage["icon"],
            "description": stage["description"],
            "finding_count": len(stage_f),
            "risk_level": stage_max_sev,
            "findings": stage_f,
            "architecture_locations": arch_locations,
        })

    # Executive summary
    confirmed_count = sum(1 for f in findings if f.get("confirmed"))
    sev_counts = {}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Kill chain coverage percentage
    coverage = round((stages_with_findings / 7) * 100)

    # Build attack paths (chains of findings across stages)
    attack_paths = _build_attack_paths(stage_findings)

    return {
        "scan_id": scan_entry.get("scan_id", ""),
        "target": target,
        "status": scan_entry.get("status", ""),
        "started_at": scan_entry.get("started_at", ""),
        "ended_at": scan_entry.get("ended_at", ""),
        "executive_summary": {
            "total_findings": total_findings,
            "confirmed_findings": confirmed_count,
            "severity_counts": sev_counts,
            "kill_chain_coverage": coverage,
            "stages_with_findings": stages_with_findings,
            "max_severity": max_severity_overall,
            "risk_posture": _risk_posture(max_severity_overall, coverage, confirmed_count),
        },
        "kill_chain_stages": stages,
        "attack_paths": attack_paths,
        "raw_findings": findings,
    }


def _infer_architecture_location(url: str, parameter: str, module: str, vuln_type: str) -> str:
    """Infer where in the target's architecture a vulnerability exists."""
    vt = (vuln_type or "").lower()
    mod = (module or "").lower()
    param = (parameter or "").lower()

    if "sql" in vt or "sql" in mod:
        return f"Database Layer → Query Handler (param: {parameter or 'N/A'})"
    if "xss" in vt or "xss" in mod:
        return f"Frontend → Output Rendering (param: {parameter or 'N/A'})"
    if "ssti" in vt:
        return f"Template Engine → Server-side Rendering"
    if "command" in vt or "command" in mod:
        return f"Backend → OS Command Execution"
    if "ssrf" in vt or "ssrf" in mod:
        return f"Backend → HTTP Client / URL Fetcher"
    if "path_traversal" in vt or "lfi" in vt or "rfi" in vt:
        return f"File System → File Inclusion Handler"
    if "xxe" in vt:
        return f"XML Parser → Entity Processing"
    if "csrf" in vt:
        return f"Session Management → Token Validation"
    if "redirect" in vt:
        return f"Routing → Redirect Handler"
    if "host_header" in vt or "host" in mod:
        return f"Web Server → Host Header Processing"
    if "cors" in vt or "cors" in mod:
        return f"Web Server → CORS Policy Configuration"
    if "crlf" in vt:
        return f"Web Server → HTTP Response Headers"
    if "idor" in vt or "idor" in mod:
        return f"Authorization Layer → Object Access Control"
    if "auth" in mod or "jwt" in mod:
        return f"Authentication Layer → Credential Validation"
    if "access_control" in vt or "access_control" in mod:
        return f"Authorization Layer → Role-Based Access"
    if "ssl" in mod or "tls" in vt:
        return f"Transport Layer → TLS Configuration"
    if "misconfig" in mod or "header" in mod:
        return f"Web Server → Security Configuration"
    if "subdomain" in mod:
        return f"DNS → Subdomain Configuration"
    if "race" in vt or "race" in mod:
        return f"Backend → Concurrency Handling"
    if "sensitive" in mod or "data_exposure" in vt:
        return f"Application → Data Protection Layer"
    if "graphql" in mod:
        return f"API Layer → GraphQL Endpoint"

    return f"Application → {module or 'Unknown Component'}"


def _risk_posture(max_severity: str, coverage: int, confirmed: int) -> str:
    """Compute an overall risk posture label."""
    if max_severity == "critical" and confirmed > 0:
        return "CRITICAL — Immediate remediation required"
    if max_severity == "critical":
        return "HIGH — Critical vulnerabilities detected, confirmation pending"
    if max_severity == "high" and confirmed > 0:
        return "HIGH — Confirmed high-severity vulnerabilities"
    if max_severity == "high":
        return "ELEVATED — High-severity vulnerabilities detected"
    if max_severity == "medium":
        return "MODERATE — Medium-risk issues found"
    if coverage > 40:
        return "MODERATE — Wide attack surface exposed"
    return "LOW — Minimal vulnerabilities detected"


def _build_attack_paths(stage_findings: Dict[str, List[Dict]]) -> List[Dict[str, Any]]:
    """Build potential attack paths chaining findings across kill chain stages."""
    paths = []
    stage_order = [s["id"] for s in KILL_CHAIN_STAGES]

    # Look for multi-stage chains
    active_stages = [sid for sid in stage_order if stage_findings.get(sid)]
    if len(active_stages) >= 2:
        # Build a chain from the findings
        chain_steps = []
        for sid in active_stages:
            top_finding = stage_findings[sid][0]  # highest priority finding in each stage
            stage_meta = next((s for s in KILL_CHAIN_STAGES if s["id"] == sid), {})
            chain_steps.append({
                "stage": sid,
                "stage_name": stage_meta.get("name", sid),
                "stage_number": stage_meta.get("number", 0),
                "finding_title": top_finding.get("title", "Unknown"),
                "finding_severity": top_finding.get("severity", "INFO"),
                "url": top_finding.get("url", ""),
            })

        paths.append({
            "name": "Primary Attack Chain",
            "description": f"Spans {len(chain_steps)} kill chain stages from {chain_steps[0]['stage_name']} to {chain_steps[-1]['stage_name']}",
            "risk": "critical" if any(s.get("finding_severity", "").upper() == "CRITICAL" for s in chain_steps) else "high",
            "steps": chain_steps,
        })

    return paths


def _save_report_to_disk(scan_id: str, report: Dict[str, Any]) -> None:
    """Persist a completed scan report to the reports directory."""
    try:
        target = (report.get("target") or "").replace("https://", "").replace("http://", "").replace("/", "_")[:40]
        filename = f"killchain_{target}_{scan_id[:8]}.json"
        path = os.path.join(REPORT_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"Kill chain report saved: {path}")
    except Exception as exc:
        logger.warning(f"Failed to save report to disk: {exc}")


def _register_scan(scan_id: str, entry: Dict[str, Any]) -> None:
    """Store a scan entry, evicting the oldest when at capacity."""
    _scans[scan_id] = entry
    while len(_scans) > MAX_SCANS:
        _scans.popitem(last=False)


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
    "network": ["subdomain_takeover", "host_header", "ssl_tls_scanner"],
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
        "method": f.method,
        "payload": f.payload,
        "evidence": f.evidence,
        "description": f.description,
        "remediation": f.remediation,
        "request": f.request,
        "response": f.response,
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

    def _on_phase(phase: str) -> None:
        entry["phase"] = phase

    def _on_finding(finding) -> None:
        entry["findings"].append(_finding_to_dict(finding))

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
                phase_callback=_on_phase,
                finding_callback=_on_finding,
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

            # Auto-save kill chain report on completion
            if entry["status"] == "complete":
                try:
                    report = _build_kill_chain_report(entry)
                    _save_report_to_disk(scan_id, report)
                except Exception as report_exc:
                    logger.warning(f"Report auto-save failed: {report_exc}")

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        entry["status"] = "error"
        entry["errors"].append(str(exc))
        entry["ended_at"] = datetime.utcnow().isoformat()


# ── Endpoints ──────────────────────────────────────────────────


@app.get("/api/scan/active")
async def get_active_scan():
    """Return the currently running / starting scan, if any.

    The frontend calls this on load to detect in-progress or recently
    completed scans and auto-reconnect instead of showing the home page.
    """
    # Look for running/starting scans first
    for scan_id in reversed(_scans):
        entry = _scans[scan_id]
        if entry["status"] in ("running", "starting", "paused"):
            return {
                "active": True,
                "scan_id": entry["scan_id"],
                "status": entry["status"],
                "target": entry["target"],
                "phase": entry.get("phase", "init"),
                "started_at": entry["started_at"],
                "finding_count": len(entry.get("findings", [])),
                "log_count": len(entry.get("logs", [])),
            }

    # No running scan — check for recently completed (within 10 min)
    for scan_id in reversed(_scans):
        entry = _scans[scan_id]
        if entry["status"] in ("complete", "error", "aborted") and entry.get("ended_at"):
            try:
                ended = datetime.fromisoformat(entry["ended_at"])
                elapsed = (datetime.utcnow() - ended).total_seconds()
                if elapsed < 600:  # 10 minutes
                    return {
                        "active": False,
                        "recent": True,
                        "scan_id": entry["scan_id"],
                        "status": entry["status"],
                        "target": entry["target"],
                        "phase": entry.get("phase", "complete"),
                        "started_at": entry["started_at"],
                        "ended_at": entry["ended_at"],
                        "finding_count": len(entry.get("findings", [])),
                    }
            except (ValueError, TypeError):
                pass

    return {"active": False, "recent": False}


@app.get("/api/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """Get a Cyber Kill Chain structured report for a scan."""
    if scan_id not in _scans:
        raise HTTPException(404, "Scan not found")
    return _build_kill_chain_report(_scans[scan_id])


@app.post("/api/scan", response_model=ScanSummary, status_code=201)
async def start_scan(req: ScanRequest):
    """Launch a new scan. Returns immediately with a scan_id."""
    scan_id = str(uuid.uuid4())
    entry = {
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
    _register_scan(scan_id, entry)
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


@app.get("/api/scanners")
async def list_scanners():
    """List all scanner modules with metadata for the dashboard."""
    MODULE_META = {
        # 1. Reconnaissance
        "subdomain_takeover": {"name": "Subdomain Takeover",   "description": "Dangling DNS to 20+ services (S3, GitHub, Azure, Heroku, etc.)", "engine": "python", "category": "Reconnaissance"},
        "ssl_tls_scanner":    {"name": "SSL/TLS Scanner",      "description": "Certificate issues, legacy TLS 1.0/1.1, weak ciphers & expiry", "engine": "python", "category": "Reconnaissance"},
        # 2. Discovery
        "misconfig_scanner":  {"name": "Misconfiguration",     "description": "95+ sensitive paths, exposed endpoints, robots.txt & error pages", "engine": "python", "category": "Discovery"},
        "sensitive_data_exposure": {"name": "Sensitive Data",   "description": "Exposed .env, .git, backups, actuator endpoints & leaked secrets", "engine": "python", "category": "Discovery"},
        "graphql_scanner":    {"name": "GraphQL Scanner",      "description": "Introspection, schema exposure, batch queries & depth DoS", "engine": "python", "category": "Discovery"},
        # 3. Vulnerability Assessment
        "sql_injection":      {"name": "SQL Injection",        "description": "Error-based, time-based, boolean, UNION & NoSQL injection", "engine": "python", "category": "Vulnerability Assessment"},
        "xss_scanner":        {"name": "XSS Scanner",          "description": "Reflected, stored & DOM-based XSS with context-aware detection", "engine": "python", "category": "Vulnerability Assessment"},
        "command_injection":  {"name": "Command Injection",    "description": "OS command execution via shell operators & encoding bypass", "engine": "python", "category": "Vulnerability Assessment"},
        "ssti":               {"name": "SSTI",                 "description": "Server-side template injection across 10+ engines with RCE POCs", "engine": "python", "category": "Vulnerability Assessment"},
        "ssrf":               {"name": "SSRF",                 "description": "Internal network, cloud metadata (AWS/GCP/Azure/DO), URL schemes", "engine": "python", "category": "Vulnerability Assessment"},
        "xxe_scanner":        {"name": "XXE Scanner",          "description": "XML External Entity — file read, SSRF, XInclude, SVG & SOAP", "engine": "python", "category": "Vulnerability Assessment"},
        "path_traversal":     {"name": "Path Traversal",       "description": "Directory traversal (Linux + Windows), null bytes & PHP wrappers", "engine": "python", "category": "Vulnerability Assessment"},
        "lfi_rfi_scanner":    {"name": "LFI / RFI",            "description": "Local/Remote File Inclusion via PHP filter wrappers & encoding", "engine": "python", "category": "Vulnerability Assessment"},
        "crlf_injection":     {"name": "CRLF Injection",       "description": "HTTP header injection, response splitting & cache poisoning", "engine": "python", "category": "Vulnerability Assessment"},
        # 4. Authentication Audit
        "auth_scanner":       {"name": "Auth Scanner",         "description": "JWT alg:none, default credentials, password reset & OAuth flaws", "engine": "python", "category": "Authentication Audit"},
        "jwt_scanner":        {"name": "JWT Scanner",          "description": "Weak signing secrets, missing expiration & alg:none bypass", "engine": "python", "category": "Authentication Audit"},
        "csrf_scanner":       {"name": "CSRF Scanner",         "description": "Missing CSRF tokens on forms & token validation bypass testing", "engine": "python", "category": "Authentication Audit"},
        "rate_limit_scanner": {"name": "Rate Limit Scanner",   "description": "Missing rate limiting & X-Forwarded-For header bypass detection", "engine": "python", "category": "Authentication Audit"},
        # 5. Authorization Audit
        "idor_scanner":       {"name": "IDOR Scanner",         "description": "Insecure Direct Object Reference, write-IDOR, HPP & path IDOR", "engine": "python", "category": "Authorization Audit"},
        "broken_access_control": {"name": "Broken Access Control", "description": "Unauthenticated admin access, horizontal privesc & method exposure", "engine": "python", "category": "Authorization Audit"},
        # 6. Configuration Audit
        "cors_scanner":       {"name": "CORS Scanner",         "description": "Origin reflection, null origin trust & wildcard+credentials", "engine": "python", "category": "Configuration Audit"},
        "header_security":    {"name": "Header Security",      "description": "Missing/weak CSP, HSTS, X-Frame-Options & Referrer-Policy", "engine": "python", "category": "Configuration Audit"},
        "host_header":        {"name": "Host Header",          "description": "Host header injection, password reset poisoning & cache poisoning", "engine": "python", "category": "Configuration Audit"},
        # 7. Advanced Testing
        "open_redirect":      {"name": "Open Redirect",        "description": "32 payloads including encoding bypass, meta-refresh & JS redirect", "engine": "python", "category": "Advanced Testing"},
        "race_condition":     {"name": "Race Condition",       "description": "TOCTOU via concurrent requests — coupon reuse, double payments", "engine": "python", "category": "Advanced Testing"},
    }
    result = []
    for mod_id in ENABLED_MODULES:
        meta = MODULE_META.get(mod_id, {
            "name": mod_id.replace("_", " ").title(),
            "description": "Vulnerability scanner module",
            "engine": "python",
            "category": "Vulnerability Assessment",
        })
        result.append({"id": mod_id, **meta})
    return result


@app.post("/api/scan/{scan_id}/pause")
async def pause_scan(scan_id: str):
    """Pause or resume a running scan."""
    if scan_id not in _scans:
        raise HTTPException(404, "Scan not found")
    entry = _scans[scan_id]
    if entry["status"] not in ("running", "paused"):
        raise HTTPException(400, f"Cannot pause scan in status: {entry['status']}")
    if entry["status"] == "paused":
        entry["status"] = "running"
        return {"status": "running"}
    else:
        entry["status"] = "paused"
        return {"status": "paused"}


@app.post("/api/scan/{scan_id}/abort")
async def abort_scan(scan_id: str):
    """Abort a running scan."""
    if scan_id not in _scans:
        raise HTTPException(404, "Scan not found")
    entry = _scans[scan_id]
    if entry["status"] in ("complete", "aborted", "error"):
        raise HTTPException(400, f"Scan already in terminal state: {entry['status']}")
    entry["status"] = "aborted"
    entry["ended_at"] = datetime.utcnow().isoformat()
    entry["logs"].append({
        "ts": datetime.utcnow().strftime("%H:%M:%S"),
        "msg": "Scan aborted by user",
    })
    return {"status": "aborted"}


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
