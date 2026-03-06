"""
Report Generator — produces Markdown, JSON, and HTML reports.
"""
from __future__ import annotations
import json
import os
from datetime import datetime
from typing import List

from config.settings import OUTPUT_DIR, SEVERITY_ORDER, Severity
from core.models import Finding, ScanState


SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#e74c3c",
    Severity.HIGH:     "#e67e22",
    Severity.MEDIUM:   "#f1c40f",
    Severity.LOW:      "#3498db",
    Severity.INFO:     "#95a5a6",
}


class Reporter:
    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_markdown(self, state: ScanState, executive_summary: str = "") -> str:
        confirmed = [f for f in state.findings if f.confirmed]
        all_findings = sorted(
            state.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
            reverse=True,
        )

        lines = [
            f"# Bug Bounty Scan Report",
            f"",
            f"**Target:** {state.target.url}  ",
            f"**Scan ID:** {state.scan_id}  ",
            f"**Date:** {state.started_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Duration:** {self._duration(state)}  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            executive_summary or "_AI summary not generated._",
            f"",
            f"---",
            f"",
            f"## Statistics",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| URLs Tested | {len(state.target.discovered_urls)} |",
            f"| Parameters Tested | {sum(len(v) for v in state.target.discovered_params.values())} |",
            f"| Modules Run | {len(state.modules_run)} |",
            f"| Total Findings | {len(all_findings)} |",
            f"| Confirmed | {len(confirmed)} |",
            f"| Critical | {sum(1 for f in confirmed if f.severity == Severity.CRITICAL)} |",
            f"| High | {sum(1 for f in confirmed if f.severity == Severity.HIGH)} |",
            f"| Medium | {sum(1 for f in confirmed if f.severity == Severity.MEDIUM)} |",
            f"| Low | {sum(1 for f in confirmed if f.severity == Severity.LOW)} |",
            f"",
            f"---",
            f"",
            f"## Technologies Detected",
            f"",
            f"{', '.join(state.target.technologies) or 'None identified'}",
            f"",
            f"---",
            f"",
            f"## Findings",
            f"",
        ]

        for i, f in enumerate(all_findings, 1):
            status = "✅ CONFIRMED" if f.confirmed else "⚠️ UNCONFIRMED"
            emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
            lines += [
                f"### {i}. {emoji} {f.title}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Status** | {status} |",
                f"| **Severity** | {f.severity.upper()} |",
                f"| **Type** | {f.vuln_type} |",
                f"| **URL** | `{f.url}` |",
                f"| **Parameter** | `{f.parameter}` |",
                f"| **Method** | {f.method} |",
                f"| **CVSS** | {f.cvss_score} |",
                f"| **CWE** | {f.cwe_id} |",
                f"| **OWASP** | {f.owasp_category} |",
                f"| **Module** | {f.module} |",
                f"",
                f"**Description:**  ",
                f"{f.description or 'N/A'}",
                f"",
            ]

            if f.payload:
                lines += [f"**Payload:**", f"```", f.payload, f"```", f""]
            if f.evidence:
                lines += [f"**Evidence:**  ", f"{f.evidence}", f""]
            if f.request:
                lines += [f"**HTTP Request:**", f"```http", f.request[:600], f"```", f""]
            if f.poc_steps:
                lines += [f"**Proof of Concept Steps:**", f""]
                for step in f.poc_steps:
                    lines.append(f"- {step}")
                lines.append("")
            if f.remediation:
                lines += [f"**Remediation:**  ", f"{f.remediation}", f""]
            if f.ai_analysis:
                lines += [f"**AI Analysis:**  ", f"_{f.ai_analysis}_", f""]
            lines += ["---", ""]

        if state.errors:
            lines += ["## Scan Errors", ""]
            for err in state.errors:
                lines.append(f"- {err}")
            lines.append("")

        lines += ["## Agent Reasoning Log", ""]
        for thought in state.agent_thoughts:
            lines.append(f"- {thought}")

        return "\n".join(lines)

    def generate_json(self, state: ScanState, executive_summary: str = "") -> dict:
        return {
            "scan_id": state.scan_id,
            "target": state.target.url,
            "started_at": state.started_at.isoformat(),
            "ended_at": state.ended_at.isoformat() if state.ended_at else None,
            "duration": self._duration(state),
            "executive_summary": executive_summary,
            "statistics": state.stats(),
            "technologies": state.target.technologies,
            "findings": [f.to_dict() for f in state.findings],
            "errors": state.errors,
            "modules_run": state.modules_run,
        }

    def generate_html(self, state: ScanState, executive_summary: str = "") -> str:
        """Generate a styled HTML report."""
        confirmed = [f for f in state.findings if f.confirmed]
        all_findings = sorted(
            state.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
            reverse=True,
        )
        stats = state.stats()

        # Severity chart data
        sev_counts = stats.get("by_severity", {})

        findings_html = ""
        for i, f in enumerate(all_findings, 1):
            status = "CONFIRMED ✅" if f.confirmed else "UNCONFIRMED ⚠️"
            color = SEVERITY_COLORS.get(f.severity, "#95a5a6")
            poc_html = ""
            if f.poc_steps:
                poc_html = "<ol>" + "".join(f"<li>{s}</li>" for s in f.poc_steps) + "</ol>"

            findings_html += f"""
            <div class="finding-card" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="severity-badge" style="background:{color};">{f.severity.upper()}</span>
                    <h3>{i}. {_esc(f.title)}</h3>
                    <span class="status">{status}</span>
                </div>
                <div class="finding-body">
                    <table>
                        <tr><td>URL</td><td><code>{_esc(f.url)}</code></td></tr>
                        <tr><td>Parameter</td><td><code>{_esc(f.parameter)}</code></td></tr>
                        <tr><td>Module</td><td>{_esc(f.module)}</td></tr>
                        <tr><td>CVSS</td><td>{f.cvss_score}</td></tr>
                        <tr><td>CWE</td><td>{_esc(f.cwe_id)}</td></tr>
                    </table>
                    {f'<p class="desc">{_esc(f.description)}</p>' if f.description else ''}
                    {f'<div class="payload"><strong>Payload:</strong><pre>{_esc(f.payload)}</pre></div>' if f.payload else ''}
                    {f'<div class="evidence"><strong>Evidence:</strong> {_esc(f.evidence)}</div>' if f.evidence else ''}
                    {f'<div class="poc"><strong>PoC Steps:</strong>{poc_html}</div>' if poc_html else ''}
                    {f'<div class="remediation"><strong>Remediation:</strong> {_esc(f.remediation)}</div>' if f.remediation else ''}
                    {f'<div class="ai-analysis"><strong>AI Analysis:</strong> <em>{_esc(f.ai_analysis)}</em></div>' if f.ai_analysis else ''}
                </div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bug Bounty Report — {_esc(state.target.url)}</title>
<style>
:root {{ --bg: #0f0f1a; --card: #1a1a2e; --text: #e0e0e0; --accent: #00d4ff; --border: #2a2a3e; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--text); font-family: 'Inter', 'Segoe UI', sans-serif; padding: 2rem; line-height: 1.6; }}
h1 {{ color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }}
h2 {{ color: var(--accent); font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
h3 {{ font-size: 1.1rem; margin: 0; display: inline; }}
.header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 2rem; border-radius: 12px; margin-bottom: 2rem; border: 1px solid var(--border); }}
.header .meta {{ color: #888; font-size: 0.9rem; margin-top: 0.5rem; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 1rem 0; }}
.stat-card {{ background: var(--card); padding: 1.2rem; border-radius: 8px; text-align: center; border: 1px solid var(--border); }}
.stat-card .value {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
.stat-card .label {{ font-size: 0.85rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; }}
.severity-bar {{ display: flex; gap: 0.5rem; margin: 1rem 0; height: 8px; border-radius: 4px; overflow: hidden; }}
.severity-bar span {{ display: block; height: 100%; border-radius: 4px; transition: width 0.3s; }}
.finding-card {{ background: var(--card); border-radius: 8px; margin: 1rem 0; overflow: hidden; border: 1px solid var(--border); }}
.finding-header {{ display: flex; align-items: center; gap: 1rem; padding: 1rem 1.5rem; background: rgba(0,0,0,0.2); }}
.severity-badge {{ padding: 0.25rem 0.75rem; border-radius: 4px; color: #fff; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; }}
.status {{ margin-left: auto; font-size: 0.85rem; }}
.finding-body {{ padding: 1.5rem; }}
.finding-body table {{ width: 100%; border-collapse: collapse; margin-bottom: 1rem; }}
.finding-body td {{ padding: 0.4rem 0.8rem; border-bottom: 1px solid var(--border); }}
.finding-body td:first-child {{ color: #888; width: 120px; font-size: 0.9rem; }}
code, pre {{ background: rgba(0,212,255,0.1); padding: 0.2rem 0.4rem; border-radius: 3px; font-family: 'Fira Code', monospace; font-size: 0.85rem; color: var(--accent); }}
pre {{ padding: 1rem; margin: 0.5rem 0; overflow-x: auto; display: block; }}
.desc, .evidence, .remediation, .ai-analysis, .poc {{ margin: 0.8rem 0; font-size: 0.95rem; }}
.poc ol {{ padding-left: 1.5rem; }}
.executive-summary {{ background: var(--card); padding: 1.5rem; border-radius: 8px; border: 1px solid var(--border); white-space: pre-wrap; }}
.tech-list {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
.tech-tag {{ background: rgba(0,212,255,0.15); color: var(--accent); padding: 0.3rem 0.8rem; border-radius: 20px; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="header">
    <h1>🔍 Bug Bounty Scan Report</h1>
    <div class="meta">
        Target: <strong>{_esc(state.target.url)}</strong> &nbsp;|&nbsp;
        Scan ID: {state.scan_id} &nbsp;|&nbsp;
        Date: {state.started_at.strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
        Duration: {self._duration(state)}
    </div>
</div>

<h2>📊 Statistics</h2>
<div class="stats-grid">
    <div class="stat-card"><div class="value">{len(state.target.discovered_urls)}</div><div class="label">URLs Tested</div></div>
    <div class="stat-card"><div class="value">{len(state.modules_run)}</div><div class="label">Modules Run</div></div>
    <div class="stat-card"><div class="value">{len(all_findings)}</div><div class="label">Total Findings</div></div>
    <div class="stat-card"><div class="value" style="color:#e74c3c;">{len(confirmed)}</div><div class="label">Confirmed</div></div>
    <div class="stat-card"><div class="value">{sev_counts.get('critical',0)}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="value">{sev_counts.get('high',0)}</div><div class="label">High</div></div>
</div>

<div class="severity-bar">
    <span style="background:#e74c3c; width:{max(sev_counts.get('critical',0)*20, 2)}px;" title="Critical"></span>
    <span style="background:#e67e22; width:{max(sev_counts.get('high',0)*20, 2)}px;" title="High"></span>
    <span style="background:#f1c40f; width:{max(sev_counts.get('medium',0)*20, 2)}px;" title="Medium"></span>
    <span style="background:#3498db; width:{max(sev_counts.get('low',0)*20, 2)}px;" title="Low"></span>
</div>

<h2>🛠️ Technologies</h2>
<div class="tech-list">
    {''.join(f'<span class="tech-tag">{_esc(t)}</span>' for t in state.target.technologies) or '<span style="color:#888">None identified</span>'}
</div>

<h2>📝 Executive Summary</h2>
<div class="executive-summary">{_esc(executive_summary) or '<em>AI summary not generated.</em>'}</div>

<h2>🚨 Findings ({len(all_findings)})</h2>
{findings_html}

</body>
</html>"""

    def save(self, state: ScanState, executive_summary: str = "") -> tuple[str, str]:
        """Save Markdown, JSON, and HTML reports. Returns (md_path, json_path)."""
        ts = state.started_at.strftime("%Y%m%d_%H%M%S")
        slug = state.target.url.replace("https://", "").replace("http://", "").replace("/", "_")[:40]
        base = os.path.join(self.output_dir, f"scan_{slug}_{ts}")

        md_path = base + ".md"
        json_path = base + ".json"
        html_path = base + ".html"

        md_content = self.generate_markdown(state, executive_summary)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        json_content = self.generate_json(state, executive_summary)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_content, f, indent=2, default=str)

        html_content = self.generate_html(state, executive_summary)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return md_path, json_path

    def _duration(self, state: ScanState) -> str:
        if state.ended_at:
            delta = state.ended_at - state.started_at
            m, s = divmod(int(delta.total_seconds()), 60)
            h, m = divmod(m, 60)
            return f"{h}h {m}m {s}s" if h else f"{m}m {s}s"
        return "in progress"


def _esc(text: str) -> str:
    """Escape HTML entities."""
    if not text:
        return ""
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))
