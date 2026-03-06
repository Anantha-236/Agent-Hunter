"""
Web Scanner — OWASP ZAP
Covers: XSS, SQLi, CSRF, SSRF, open redirect, path traversal, command injection
"""

import os
import asyncio
import httpx

ZAP_HOST    = os.getenv("ZAP_HOST", "zap")
ZAP_PORT    = os.getenv("ZAP_PORT", "8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
ZAP_BASE    = f"http://{ZAP_HOST}:{ZAP_PORT}"

DEPTH_SETTINGS = {
    "light":  {"maxChildren": 5,  "attackStrength": "LOW",    "alertThreshold": "MEDIUM"},
    "medium": {"maxChildren": 15, "attackStrength": "MEDIUM", "alertThreshold": "LOW"},
    "deep":   {"maxChildren": 50, "attackStrength": "HIGH",   "alertThreshold": "LOW"},
}

ZAP_SEVERITY_MAP = {
    "High":          "HIGH",
    "Medium":        "MEDIUM",
    "Low":           "LOW",
    "Informational": "INFO",
}

CRITICAL_PLUGIN_IDS = {
    "90018",  # SQL Injection
    "40018",  # SQL Injection (MySQL)
    "40019",  # SQL Injection (Hypersonic)
    "40020",  # SQL Injection (Oracle)
    "40021",  # SQL Injection (SQLite)
    "40022",  # Blind SQL Injection
    "90019",  # Server Side Code Injection
    "20018",  # Remote OS Command Injection
}


def zap_sev_to_hunter(zap_risk: str) -> str:
    return ZAP_SEVERITY_MAP.get(zap_risk, "INFO")


async def wait_for_zap(log_fn, timeout=60):
    """Wait until ZAP daemon is ready."""
    async with httpx.AsyncClient() as client:
        for _ in range(timeout):
            try:
                r = await client.get(f"{ZAP_BASE}/JSON/core/view/version/",
                                     params={"apikey": ZAP_API_KEY}, timeout=3)
                if r.status_code == 200:
                    log_fn("INFO", "ZAP daemon is ready")
                    return True
            except Exception:
                pass
            await asyncio.sleep(1)
    log_fn("ERROR", "ZAP daemon did not respond in time")
    return False


async def run_web_scan(url: str, depth: str, auth_cookie: str | None,
                       scan_id: str, log_fn) -> list[dict]:
    findings = []
    settings = DEPTH_SETTINGS.get(depth, DEPTH_SETTINGS["medium"])

    async with httpx.AsyncClient(timeout=300) as client:
        params = {"apikey": ZAP_API_KEY}

        if not await wait_for_zap(log_fn):
            return []

        # ── 1. Spider the target ──────────────────────────
        log_fn("INFO", f"Spidering {url} (maxChildren={settings['maxChildren']})")
        try:
            r = await client.get(f"{ZAP_BASE}/JSON/spider/action/scan/",
                                 params={**params, "url": url,
                                         "maxChildren": settings["maxChildren"],
                                         "recurse": "true"})
            spider_id = r.json().get("scan")
            log_fn("INFO", f"Spider started (id={spider_id})")

            while True:
                r = await client.get(f"{ZAP_BASE}/JSON/spider/view/status/",
                                     params={**params, "scanId": spider_id})
                progress = int(r.json().get("status", 0))
                log_fn("INFO", f"Spider progress: {progress}%")
                if progress >= 100:
                    break
                await asyncio.sleep(3)

            log_fn("INFO", "Spider complete")
        except Exception as e:
            log_fn("WARN", f"Spider error: {e} — continuing with active scan anyway")

        # ── 2. Ajax spider (for JS-heavy apps like WebGoat) ───
        log_fn("INFO", "Starting Ajax spider (JS rendering)…")
        try:
            await client.get(f"{ZAP_BASE}/JSON/ajaxSpider/action/scan/",
                             params={**params, "url": url, "inScope": "true"})
            for _ in range(30):
                r = await client.get(f"{ZAP_BASE}/JSON/ajaxSpider/view/status/",
                                     params=params)
                if r.json().get("status") == "stopped":
                    break
                await asyncio.sleep(2)
            log_fn("INFO", "Ajax spider complete")
        except Exception as e:
            log_fn("WARN", f"Ajax spider error: {e}")

        # ── 3. Active scan ────────────────────────────────
        log_fn("INFO", f"Starting active scan (strength={settings['attackStrength']})")
        try:
            r = await client.get(f"{ZAP_BASE}/JSON/ascan/action/scan/",
                                 params={**params, "url": url, "recurse": "true",
                                         "scanPolicyName": "",
                                         "method": "", "postData": ""})
            ascan_id = r.json().get("scan")

            while True:
                r = await client.get(f"{ZAP_BASE}/JSON/ascan/view/status/",
                                     params={**params, "scanId": ascan_id})
                progress = int(r.json().get("status", 0))
                log_fn("INFO", f"Active scan progress: {progress}%")
                if progress >= 100:
                    break
                await asyncio.sleep(5)

            log_fn("INFO", "Active scan complete")
        except Exception as e:
            log_fn("ERROR", f"Active scan error: {e}")
            return findings

        # ── 4. Collect alerts ─────────────────────────────
        log_fn("INFO", "Collecting alerts…")
        try:
            r = await client.get(f"{ZAP_BASE}/JSON/core/view/alerts/",
                                 params={**params, "baseurl": url,
                                         "start": "0", "count": "500"})
            alerts = r.json().get("alerts", [])
            log_fn("INFO", f"Raw alerts from ZAP: {len(alerts)}")

            for alert in alerts:
                plugin_id = str(alert.get("pluginId", ""))
                risk      = alert.get("risk", "Low")
                sev = "CRITICAL" if plugin_id in CRITICAL_PLUGIN_IDS else zap_sev_to_hunter(risk)

                findings.append({
                    "id":          f"web-{len(findings)+1}",
                    "type":        alert.get("name", "Unknown"),
                    "severity":    sev,
                    "category":    "web",
                    "location":    alert.get("url", url),
                    "description": alert.get("description", ""),
                    "remediation": alert.get("solution", ""),
                    "cve":         alert.get("cweid", "") or alert.get("cve", ""),
                    "raw": {
                        "pluginId":   plugin_id,
                        "param":      alert.get("param", ""),
                        "evidence":   alert.get("evidence", ""),
                        "risk":       risk,
                        "confidence": alert.get("confidence", ""),
                    }
                })
        except Exception as e:
            log_fn("ERROR", f"Alert collection error: {e}")

    log_fn("INFO", f"Web scan done — {len(findings)} findings")
    return findings
