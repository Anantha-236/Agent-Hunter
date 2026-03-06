"""HackerOne-Ready Report Generator — generates copy-paste bug bounty reports.

Also provides integration with HackerOneClient for automated API submission.
"""
from __future__ import annotations
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from core.models import Finding, ScanState
from config.settings import Severity, H1_SEVERITY_CVSS, H1_AUTO_SUBMIT

logger = logging.getLogger(__name__)

# ── CVSS scores — augmented with config-driven ranges ─────────
CVSS_SCORES = {
    Severity.CRITICAL: {"score": 9.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    Severity.HIGH:     {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    Severity.MEDIUM:   {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    Severity.LOW:      {"score": 3.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    Severity.INFO:     {"score": 0.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
}

# Map from config severity_cvss_map ranges to midpoint scores
def _cvss_midpoint(severity: str) -> Optional[float]:
    """Return CVSS midpoint from config range for a severity level."""
    rng = H1_SEVERITY_CVSS.get(severity)
    if rng and isinstance(rng, (list, tuple)) and len(rng) == 2:
        return round((rng[0] + rng[1]) / 2, 1)
    return None

REMEDIATION_MAP = {
    "sql_injection": "Use parameterized queries/prepared statements. Apply input validation and output encoding.",
    "reflected_xss": "Implement Content-Security-Policy headers. Sanitize and encode all user input before reflection.",
    "dom_xss": "Avoid dangerous sinks (innerHTML, eval). Use textContent instead. Implement DOMPurify.",
    "ssrf": "Use allowlists for outbound URLs. Block internal/private IP ranges. Validate URL schemes.",
    "ssti": "Avoid passing user input to template engines. Use sandboxed/logic-less templates.",
    "csrf": "Implement anti-CSRF tokens. Use SameSite cookie attribute. Validate Origin/Referer headers.",
    "path_traversal": "Use allowlists for file paths. Canonicalize paths. Avoid direct file access from user input.",
    "command_injection": "Avoid OS commands entirely. Use language-native APIs. If necessary, use strict allowlists.",
    "xxe": "Disable external entity processing in XML parsers. Use JSON instead of XML where possible.",
    "idor": "Implement proper authorization checks. Use indirect object references (UUIDs instead of sequential IDs).",
    "host_header_injection": "Use a hardcoded server name for URL generation. Validate Host header against allowlist.",
    "open_redirect": "Use allowlists for redirect targets. Avoid user-controlled redirect URLs.",
    "race_condition": "Implement database-level locking. Use atomic operations. Add idempotency keys.",
    "missing_security_header": "Add recommended security headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options.",
    "default_credentials": "Force password change on first login. Use strong password policies. Remove default accounts.",
}


def generate_hackerone_report(finding: Finding) -> str:
    """Generate a HackerOne-ready vulnerability report."""
    cvss = CVSS_SCORES.get(finding.severity, CVSS_SCORES[Severity.MEDIUM])
    remediation = finding.remediation or _get_remediation(finding.vuln_type)

    report = f"""## Summary
{finding.title}

A {finding.severity.upper()} severity {_vuln_type_readable(finding.vuln_type)} vulnerability was identified at `{finding.url}`.

## Vulnerability Details

- **Type:** {_vuln_type_readable(finding.vuln_type)}
- **Severity:** {finding.severity.upper()}
- **CVSS Score:** {cvss['score']} ({cvss['vector']})
- **CWE:** {finding.cwe_id or 'N/A'}
- **OWASP:** {finding.owasp_category or 'N/A'}
- **Parameter:** `{finding.parameter}`
- **Method:** {finding.method}

## Description

{finding.description or f'The parameter `{finding.parameter}` at `{finding.url}` is vulnerable to {_vuln_type_readable(finding.vuln_type)}. An attacker can exploit this to compromise the application.'}

## Steps to Reproduce

{_format_poc_steps(finding)}

## Proof of Concept

**Request:**
```http
{finding.request or f'{finding.method} {finding.url} HTTP/1.1'}
```

**Payload Used:**
```
{finding.payload}
```

**Evidence:**
```
{finding.evidence[:500] if finding.evidence else 'See response below'}
```

## Impact

{_generate_impact(finding)}

## Remediation

{remediation}

## References

{_generate_references(finding)}
"""
    return report.strip()


def generate_batch_report(findings: List[Finding], target_url: str) -> str:
    """Generate a summary report for multiple findings (for bulk submission)."""
    grouped = {}
    for f in findings:
        if f.confirmed and not f.false_positive:
            grouped.setdefault(f.severity, []).append(f)

    report = f"""# Security Assessment Report — {target_url}
**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}
**Total Confirmed Findings:** {sum(len(v) for v in grouped.values())}

"""
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if severity in grouped:
            report += f"\n## {severity.upper()} Severity ({len(grouped[severity])})\n\n"
            for i, f in enumerate(grouped[severity], 1):
                cvss = CVSS_SCORES.get(f.severity, CVSS_SCORES[Severity.MEDIUM])
                report += f"""### {i}. {f.title}
- **URL:** `{f.url}`
- **Parameter:** `{f.parameter}`
- **CVSS:** {cvss['score']}
- **CWE:** {f.cwe_id or 'N/A'}
- **Payload:** `{f.payload[:100]}`
- **Evidence:** {f.evidence[:200]}

"""
    return report


def _vuln_type_readable(vuln_type: str) -> str:
    return vuln_type.replace("_", " ").title()


def _format_poc_steps(finding: Finding) -> str:
    if finding.poc_steps:
        return "\n".join(finding.poc_steps)
    return f"""1. Navigate to `{finding.url}`
2. Inject the payload `{finding.payload}` in the `{finding.parameter}` parameter
3. Observe the vulnerability evidence in the response
4. Verify the security impact"""


def _generate_impact(finding: Finding) -> str:
    impact_map = {
        "sql_injection": "An attacker can extract, modify, or delete database contents. In severe cases, this can lead to complete server compromise via command execution.",
        "reflected_xss": "An attacker can execute arbitrary JavaScript in a victim's browser, leading to session hijacking, credential theft, and phishing.",
        "ssrf": "An attacker can access internal services, cloud metadata (AWS/GCP credentials), and potentially pivot to internal networks.",
        "command_injection": "An attacker can execute arbitrary OS commands on the server, leading to complete system compromise.",
        "xxe": "An attacker can read server-side files, perform SSRF attacks, and potentially achieve remote code execution.",
        "csrf": "An attacker can trick authenticated users into performing unwanted actions (password change, fund transfer, etc.).",
        "path_traversal": "An attacker can read arbitrary files from the server, potentially exposing source code, configuration files, and credentials.",
        "idor": "An attacker can access or modify other users' data by manipulating object references.",
        "race_condition": "An attacker can exploit timing windows to duplicate actions (double spending, coupon reuse).",
    }
    base_type = finding.vuln_type.split("_")[0] if "_" in finding.vuln_type else finding.vuln_type
    for key, desc in impact_map.items():
        if key in finding.vuln_type:
            return desc
    return f"This {finding.severity} severity vulnerability can be exploited to compromise the security of the application."


def _generate_references(finding: Finding) -> str:
    refs = []
    if finding.cwe_id:
        cwe_num = finding.cwe_id.replace("CWE-", "")
        refs.append(f"- [{finding.cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
    if finding.owasp_category:
        refs.append(f"- [OWASP {finding.owasp_category}](https://owasp.org/Top10/)")
    refs.append(f"- [HackerOne Vulnerability Taxonomy](https://www.hackerone.com/vulnerability-management)")
    return "\n".join(refs)


def _get_remediation(vuln_type: str) -> str:
    for key, remedy in REMEDIATION_MAP.items():
        if key in vuln_type:
            return remedy
    return "Review the vulnerable component and apply appropriate security controls."


# ── H1 API Submission Integration ─────────────────────────────

async def submit_finding_to_h1(
    finding: Finding,
    program_handle: str,
    *,
    auto_submit: bool | None = None,
) -> Optional[Dict]:
    """
    Submit a single finding to HackerOne via the API client.

    Respects H1_AUTO_SUBMIT config unless overridden.
    Returns the API response dict or None on failure / skip.
    """
    from reporting.hackerone_api import HackerOneClient   # lazy to avoid circular

    should_submit = auto_submit if auto_submit is not None else H1_AUTO_SUBMIT
    if not should_submit:
        logger.info(f"Auto-submit disabled — skipping H1 submission for '{finding.title}'")
        return None

    client = HackerOneClient()
    if not await client.is_authenticated():
        logger.warning("Cannot submit to H1 — authentication failed")
        return None

    payload = client.build_report(finding, program_handle)
    result = await client.submit_report(payload)
    if result:
        report_id = result.get("data", {}).get("id", "unknown")
        logger.info(f"Submitted to HackerOne — report ID: {report_id}")
    else:
        logger.warning(f"H1 submission failed for '{finding.title}'")
    return result


async def submit_findings_batch(
    findings: List[Finding],
    program_handle: str,
    *,
    auto_submit: bool | None = None,
) -> List[Dict]:
    """Submit multiple findings to HackerOne, returning results for each."""
    results = []
    for finding in findings:
        if finding.confirmed and not finding.false_positive:
            r = await submit_finding_to_h1(
                finding, program_handle, auto_submit=auto_submit
            )
            if r:
                results.append(r)
    return results

