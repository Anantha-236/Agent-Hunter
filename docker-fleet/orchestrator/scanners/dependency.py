"""
Dependency Scanner — Trivy
Covers: CVE lookup for npm, pip, maven, go, ruby gems, cargo
"""

import asyncio
import json
import httpx


CVSS_TO_SEVERITY = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "UNKNOWN":  "INFO",
}

MANIFEST_FILES = [
    "package.json", "package-lock.json", "yarn.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
    "pom.xml", "build.gradle", "go.mod", "Gemfile", "Gemfile.lock",
    "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock",
]


async def fetch_manifest(url: str, log_fn) -> list[tuple[str, bytes]]:
    """Try to fetch known manifest files from the target URL."""
    base = url.rstrip("/")
    fetched = []
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for filename in MANIFEST_FILES:
            try:
                r = await client.get(f"{base}/{filename}")
                if r.status_code == 200 and len(r.content) > 10:
                    log_fn("INFO", f"Found manifest: /{filename}")
                    fetched.append((filename, r.content))
            except Exception:
                pass
    return fetched


def parse_trivy_json(trivy_output: str) -> list[dict]:
    findings = []
    try:
        data = json.loads(trivy_output)
    except json.JSONDecodeError:
        return findings

    results = data.get("Results", [])
    for result in results:
        target = result.get("Target", "")
        vulns  = result.get("Vulnerabilities") or []
        for v in vulns:
            sev = CVSS_TO_SEVERITY.get(v.get("Severity", "UNKNOWN"), "INFO")

            pkg     = v.get("PkgName", "")
            ver     = v.get("InstalledVersion", "")
            fix_ver = v.get("FixedVersion", "")
            cve_id  = v.get("VulnerabilityID", "")
            title   = v.get("Title", v.get("Description", ""))[:120]
            desc    = v.get("Description", "")[:400]

            remediation = (
                f"Upgrade {pkg} from {ver} to {fix_ver}." if fix_ver
                else f"No fix available yet for {pkg}@{ver} — consider an alternative."
            )

            findings.append({
                "id":          f"dep-{len(findings)+1}",
                "type":        f"{cve_id} — {pkg}",
                "severity":    sev,
                "category":    "dependency",
                "location":    f"{target} → {pkg}@{ver}",
                "description": title or desc,
                "remediation": remediation,
                "cve":         cve_id,
                "raw": {
                    "package":           pkg,
                    "installed_version": ver,
                    "fixed_version":     fix_ver,
                    "cvss":              v.get("CVSS", {}),
                    "references":        v.get("References", [])[:3],
                }
            })
    return findings


async def run_dependency_scan(url: str, depth: str, auth_cookie: str | None,
                              scan_id: str, log_fn) -> list[dict]:
    findings = []

    # ── Step 1: Try to fetch manifest files from the target ──
    manifests = await fetch_manifest(url, log_fn)

    if not manifests:
        log_fn("WARN", "No manifest files found at target URL. "
                       "Tip: expose package.json / requirements.txt at the root "
                       "or mount your code directory for SAST+dep scans.")
        return []

    for filename, content in manifests:
        tmp_path = f"/tmp/{scan_id}_{filename}"

        try:
            with open(tmp_path, "wb") as f:
                f.write(content)
        except Exception as e:
            log_fn("ERROR", f"Could not write {filename}: {e}")
            continue

        log_fn("INFO", f"Scanning {filename} with Trivy…")

        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
            tmp_path,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

            if proc.returncode not in (0, 1):  # Trivy exits 1 when vulnerabilities found
                log_fn("WARN", f"Trivy warning: {stderr.decode()[:200]}")

            results = parse_trivy_json(stdout.decode())
            findings.extend(results)
            log_fn("INFO", f"{filename} → {len(results)} CVEs found")

        except asyncio.TimeoutError:
            log_fn("ERROR", f"Trivy timed out on {filename}")
        except FileNotFoundError:
            log_fn("ERROR", "trivy binary not found — is aquasec/trivy container running?")
            break
        except Exception as e:
            log_fn("ERROR", f"Trivy error on {filename}: {e}")

    log_fn("INFO", f"Dependency scan done — {len(findings)} findings")
    return findings
