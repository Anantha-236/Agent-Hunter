"""
SAST Scanner — Semgrep
Covers: hardcoded secrets, SQL injection patterns, weak crypto,
        command injection, path traversal, XSS sinks, insecure deserialization
"""

import asyncio
import json
import httpx
from pathlib import Path


SEMGREP_SEVERITY_MAP = {
    "ERROR":   "HIGH",
    "WARNING": "MEDIUM",
    "INFO":    "LOW",
}

CRITICAL_RULE_PATTERNS = [
    "hardcoded",
    "secret",
    "private-key",
    "api-key",
    "password",
    "sql-injection",
    "command-injection",
    "rce",
    "deserialization",
    "xxe",
]

RULESETS = {
    "light":  ["p/default"],
    "medium": ["p/default", "p/secrets", "p/owasp-top-ten"],
    "deep":   ["p/default", "p/secrets", "p/owasp-top-ten",
               "p/python", "p/javascript", "p/java",
               "p/sql-injection", "p/command-injection"],
}


def bump_severity(rule_id: str, base_sev: str) -> str:
    rule_lower = rule_id.lower()
    for pattern in CRITICAL_RULE_PATTERNS:
        if pattern in rule_lower:
            return "CRITICAL"
    return base_sev


def parse_semgrep_output(raw: str) -> list[dict]:
    findings = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return findings

    for result in data.get("results", []):
        rule_id  = result.get("check_id", "unknown")
        path     = result.get("path", "")
        start    = result.get("start", {})
        line     = start.get("line", 0)
        message  = result.get("extra", {}).get("message", "")
        metadata = result.get("extra", {}).get("metadata", {})
        sev_raw  = result.get("extra", {}).get("severity", "WARNING")
        base_sev = SEMGREP_SEVERITY_MAP.get(sev_raw, "MEDIUM")
        sev      = bump_severity(rule_id, base_sev)

        cve = metadata.get("cve", "") or metadata.get("cwe", "")
        refs = metadata.get("references", [])
        fix = metadata.get("fix", "") or (refs[0] if refs else "")

        findings.append({
            "id":          f"sast-{len(findings)+1}",
            "type":        rule_id.split(".")[-1].replace("-", " ").title(),
            "severity":    sev,
            "category":    "sast",
            "location":    f"{path}:{line}",
            "description": message[:400],
            "remediation": fix[:200] if fix else "Review flagged code and apply secure coding pattern.",
            "cve":         cve or None,
            "raw": {
                "rule_id":  rule_id,
                "path":     path,
                "line":     line,
                "severity": sev_raw,
                "metadata": metadata,
            }
        })
    return findings


async def fetch_source_files(url: str, log_fn) -> list[tuple[str, bytes]]:
    """Try to fetch source code files exposed at common paths."""
    base = url.rstrip("/")
    common_paths = [
        "/src/app.py", "/app.py", "/main.py", "/server.py",
        "/src/app.js", "/app.js", "/index.js", "/server.js",
        "/src/App.jsx", "/src/index.js",
        "/src/main.go", "/main.go",
        "/app/views.py", "/views.py",
        "/src/auth.py", "/auth.py",
        "/src/database.py", "/database.py",
    ]
    fetched = []
    async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
        for path in common_paths:
            try:
                r = await client.get(f"{base}{path}")
                if r.status_code == 200 and len(r.content) > 50:
                    log_fn("INFO", f"Fetched source: {path}")
                    fetched.append((path.lstrip("/"), r.content))
            except Exception:
                pass
    return fetched


async def run_sast_scan(url: str, depth: str, auth_cookie: str | None,
                        scan_id: str, log_fn) -> list[dict]:
    findings = []
    rulesets = RULESETS.get(depth, RULESETS["medium"])

    # ── Try to fetch exposed source files ──────────────────
    source_files = await fetch_source_files(url, log_fn)

    if not source_files:
        log_fn("WARN", "No source files accessible at the target URL. "
                       "For best SAST results, mount your code directory: "
                       "docker run -v /your/code:/src returntocorp/semgrep semgrep /src")
        return []

    # Write files to temp dir
    tmp_dir = f"/tmp/{scan_id}_sast"
    Path(tmp_dir).mkdir(parents=True, exist_ok=True)

    for rel_path, content in source_files:
        out_path = Path(tmp_dir) / Path(rel_path).name
        try:
            out_path.write_bytes(content)
        except Exception as e:
            log_fn("WARN", f"Could not write {rel_path}: {e}")

    # ── Run Semgrep ─────────────────────────────────────────
    for ruleset in rulesets:
        log_fn("INFO", f"Running Semgrep ruleset: {ruleset}")
        cmd = [
            "semgrep",
            "--config", ruleset,
            "--json",
            "--quiet",
            "--no-git-ignore",
            tmp_dir,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            results = parse_semgrep_output(stdout.decode())
            findings.extend(results)
            log_fn("INFO", f"{ruleset} → {len(results)} findings")

        except asyncio.TimeoutError:
            log_fn("ERROR", f"Semgrep timed out on ruleset {ruleset}")
        except FileNotFoundError:
            log_fn("ERROR", "semgrep binary not found — is returntocorp/semgrep running?")
            break
        except Exception as e:
            log_fn("ERROR", f"Semgrep error: {e}")

    # Deduplicate by location
    seen = set()
    deduped = []
    for f in findings:
        key = (f["type"], f["location"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    log_fn("INFO", f"SAST scan done — {len(deduped)} findings (deduped from {len(findings)})")
    return deduped
