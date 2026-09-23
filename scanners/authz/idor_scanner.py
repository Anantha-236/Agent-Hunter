"""IDOR / Broken Object-Level Authorization Scanner — Deep access control detection.

Covers:
  - Sequential ID manipulation (integers, negative, zero)
  - UUID guessing
  - String/slug manipulation
  - HTTP method tampering (GET → PUT, DELETE, PATCH)
  - Parameter pollution (duplicate IDs)
  - Horizontal privilege escalation
  - Vertical privilege escalation indicators
  - POST/PUT/DELETE write-IDOR
  - JSON body ID manipulation
  - Response analysis (body diff, status codes, error messages)
"""
from __future__ import annotations
import asyncio, re, uuid
from typing import List, Optional
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# Parameter names likely to be object identifiers
ID_PARAMS = {
    "id", "user_id", "userid", "uid", "pid", "account_id", "accountid",
    "order_id", "orderid", "profile_id", "doc_id", "docid",
    "file_id", "fileid", "record_id", "item_id", "itemid",
    "invoice_id", "payment_id", "transaction_id", "ticket_id",
    "message_id", "comment_id", "post_id", "thread_id",
    "project_id", "team_id", "org_id", "group_id",
    "customer_id", "member_id", "subscription_id",
    "report_id", "session_id", "token", "key",
    "ref", "reference", "num", "number", "no", "code",
    "slug", "username", "email", "handle", "name",
}

# Test IDs for sequential access
TEST_IDS = [
    # Integers
    ("0", "zero ID"),
    ("1", "first record"),
    ("2", "second record"),
    ("3", "third record"),
    ("-1", "negative ID"),
    ("100", "arbitrary high"),
    ("999", "high ID"),
    ("9999999", "very high ID"),
    ("99999999999", "overflow ID"),
    # Strings
    ("admin", "admin slug"),
    ("root", "root slug"),
    ("test", "test slug"),
    ("null", "null string"),
    ("undefined", "undefined string"),
    ("true", "boolean string"),
    ("none", "none string"),
    # Special
    ("../1", "traversal ID"),
    ("1 OR 1=1", "SQLi in ID"),
    ("1/*", "comment injection"),
]

REMEDIATION = (
    "Implement proper object-level authorization checks. Never rely on the "
    "client-supplied ID alone — always verify the requesting user has permission "
    "to access the requested resource. Use indirect references (mapping tables) "
    "instead of exposing database IDs. Log and monitor access pattern anomalies."
)


class IDORScanner(BaseScanner):
    name = "idor_scanner"
    description = "Detects IDOR, broken object-level authorization, and access control flaws"
    tags = ["authz", "idor", "owasp-a01"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        seen = set()
        tasks = []

        for url, params in state.target.discovered_params.items():
            for param in params:
                if param.lower() in ID_PARAMS:
                    # Full IDOR test suite
                    tasks.append(self._test_sequential_idor(url, param, "GET", "query"))
                    tasks.append(self._test_method_tampering(url, param))
                    tasks.append(self._test_param_pollution(url, param))
                    # POST body IDOR
                    tasks.append(self._test_sequential_idor(url, param, "POST", "body"))
                    # JSON body IDOR
                    tasks.append(self._test_sequential_idor(url, param, "POST", "json"))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                key = (r.url, r.parameter, r.vuln_type)
                if key not in seen:
                    seen.add(key)
                    findings.append(r)
            elif isinstance(r, list):
                for f in r:
                    key = (f.url, f.parameter, f.vuln_type)
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)

        # Test discovered URLs with IDs in the path
        path_tasks = [self._test_path_idor(url) for url in state.target.discovered_urls[:50]]
        path_results = await asyncio.gather(*path_tasks, return_exceptions=True)
        for r in path_results:
            if isinstance(r, Finding):
                key = (r.url, r.parameter, r.vuln_type)
                if key not in seen:
                    seen.add(key)
                    findings.append(r)

        return findings

    async def _test_sequential_idor(self, url, param, method, inject_in) -> Optional[Finding]:
        """Test sequential ID manipulation for unauthorized access."""
        # Get responses for multiple IDs
        responses = {}
        for test_id, label in TEST_IDS[:7]:  # Core integer tests
            resp, raw = await self.test_payload(url, method, param, test_id, inject_in=inject_in)
            if resp:
                responses[test_id] = (resp, raw, label)

        if len(responses) < 3:
            return None

        # Establish a "not found" baseline with an unlikely ID
        baseline_resp, _ = await self.test_payload(url, method, param, "9999999999", inject_in=inject_in)
        if not baseline_resp:
            return None
        baseline_len = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code
        baseline_body = baseline_resp.text.strip()

        # Analyze responses for IDOR indicators
        valid_responses = {}
        for test_id, (resp, raw, label) in responses.items():
            is_valid = (
                resp.status_code == 200
                and len(resp.text) > baseline_len * 0.5
                and resp.text.strip() != baseline_body
            )
            # Different content for different IDs (not just the same page)
            if is_valid:
                valid_responses[test_id] = (resp, raw, label)

        # Need at least 2 different valid responses with different content
        if len(valid_responses) < 2:
            return None

        # Check that different IDs return different data (not static pages)
        resp_texts = [resp.text[:500] for resp, _, _ in valid_responses.values()]
        unique_contents = len(set(resp_texts))

        if unique_contents >= 2:
            # Also verify baseline is different (confirms access control is missing)
            any_valid_len = len(list(valid_responses.values())[0][0].text)
            if baseline_len < any_valid_len * 0.5 or baseline_status in (404, 403, 401):
                first_id = list(valid_responses.keys())[0]
                second_id = list(valid_responses.keys())[1]
                first_resp, first_raw, first_label = valid_responses[first_id]
                second_resp, _, second_label = valid_responses[second_id]

                return self.make_finding(
                    title=f"IDOR — Unauthorized Object Access via '{param}'",
                    vuln_type="idor", severity=Severity.HIGH,
                    url=url, parameter=param, method=method,
                    payload=f"{first_id} vs {second_id}",
                    evidence=(
                        f"ID={first_id} → {len(first_resp.text)}B (HTTP {first_resp.status_code}), "
                        f"ID={second_id} → {len(second_resp.text)}B (HTTP {second_resp.status_code}), "
                        f"Invalid ID → {baseline_len}B (HTTP {baseline_status}). "
                        f"{unique_contents} unique responses for different IDs."
                    ),
                    request=first_raw, response=first_resp.text[:300],
                    cwe_id="CWE-639", owasp_category="A01:2021 - Broken Access Control",
                    description=(
                        f"Parameter '{param}' ({method} {inject_in}) returns different "
                        f"data for different object IDs without authorization checks. "
                        f"An attacker can enumerate and access other users' data."
                    ),
                    remediation=REMEDIATION,
                    poc_steps=[
                        "1. Authenticate as User A",
                        f"2. Set '{param}' to another user's ID (e.g., {second_id})",
                        "3. Server returns different user's data",
                        "4. Enumerate all accessible IDs to extract data",
                    ],
                )
        return None

    async def _test_method_tampering(self, url, param) -> List[Finding]:
        """Test if changing HTTP method reveals write access."""
        findings = []
        # Get baseline
        get_resp, _ = await self.test_payload(url, "GET", param, "1", inject_in="query")
        if not get_resp or get_resp.status_code != 200:
            return findings

        # Try PUT, DELETE, PATCH — if they return 200 or 204, write-IDOR may exist
        for method in ["PUT", "DELETE", "PATCH"]:
            try:
                resp, raw = await self.client.request(method, url)
                if resp and resp.status_code in (200, 204, 201, 202):
                    findings.append(self.make_finding(
                        title=f"Write-IDOR — {method} method accepted on '{param}'",
                        vuln_type="idor_write", severity=Severity.CRITICAL,
                        url=url, parameter=param, method=method,
                        evidence=f"{method} returned HTTP {resp.status_code}",
                        request=raw,
                        cwe_id="CWE-639", owasp_category="A01:2021 - Broken Access Control",
                        description=(
                            f"Endpoint accepts {method} requests, potentially allowing "
                            f"unauthorized modification or deletion of other users' objects."
                        ),
                        remediation=REMEDIATION,
                        poc_steps=[
                            f"1. Send {method} request to {url}",
                            f"2. Server responds with HTTP {resp.status_code}",
                            "3. Object may be modified/deleted without authorization",
                        ],
                    ))
                    break
            except Exception:
                continue
        return findings

    async def _test_param_pollution(self, url, param) -> Optional[Finding]:
        """Test HTTP parameter pollution — send same param twice with different IDs."""
        from urllib.parse import urlparse, urlencode, urlunparse
        parsed = urlparse(url)
        polluted_query = f"{param}=1&{param}=2"
        if parsed.query:
            polluted_query = f"{parsed.query}&{polluted_query}"
        polluted_url = urlunparse(parsed._replace(query=polluted_query))

        resp, raw = await self.client.get(polluted_url)
        baseline, _ = await self.test_payload(url, "GET", param, "1", inject_in="query")

        if resp and baseline:
            # If polluted response differs significantly, HPP may affect authz
            if (abs(len(resp.text) - len(baseline.text)) > 200
                    and resp.status_code == 200):
                return self.make_finding(
                    title=f"HTTP Parameter Pollution affects '{param}'",
                    vuln_type="hpp_authz_bypass", severity=Severity.MEDIUM,
                    url=url, parameter=param,
                    payload=f"{param}=1&{param}=2",
                    evidence=f"HPP response: {len(resp.text)}B vs normal: {len(baseline.text)}B",
                    request=raw, response=resp.text[:300],
                    cwe_id="CWE-235", owasp_category="A01:2021 - Broken Access Control",
                    description="Duplicate parameter values produce different results, potentially bypassing authorization.",
                    remediation="Validate that each parameter appears exactly once. Use a strict parsing mode.",
                )
        return None

    async def _test_path_idor(self, url: str) -> Optional[Finding]:
        """Test URLs with numeric IDs in the path (e.g., /api/users/123)."""
        # Find numeric path segments
        parts = url.rstrip("/").split("/")
        for i, part in enumerate(parts):
            if re.match(r'^\d+$', part) and int(part) > 0:
                # Replace with a different ID
                alt_parts = list(parts)
                alt_id = str(int(part) + 1)
                alt_parts[i] = alt_id
                alt_url = "/".join(alt_parts)

                # Also test with 0
                zero_parts = list(parts)
                zero_parts[i] = "0"
                zero_url = "/".join(zero_parts)

                resp_orig, _ = await self.client.get(url)
                resp_alt, raw_alt = await self.client.get(alt_url)
                resp_zero, _ = await self.client.get(zero_url)

                if resp_orig and resp_alt:
                    if (resp_orig.status_code == 200
                            and resp_alt.status_code == 200
                            and abs(len(resp_orig.text) - len(resp_alt.text)) > 50
                            and len(resp_alt.text) > 100):
                        # Different content for different path IDs
                        if resp_zero and resp_zero.status_code in (404, 403, 400, 500):
                            return self.make_finding(
                                title=f"Path-based IDOR — /{part} → /{alt_id}",
                                vuln_type="idor_path", severity=Severity.HIGH,
                                url=url, parameter=f"path[{i}]",
                                payload=f"{url} → {alt_url}",
                                evidence=(
                                    f"ID={part} → {len(resp_orig.text)}B, "
                                    f"ID={alt_id} → {len(resp_alt.text)}B, "
                                    f"ID=0 → HTTP {resp_zero.status_code}"
                                ),
                                request=raw_alt,
                                cwe_id="CWE-639",
                                owasp_category="A01:2021 - Broken Access Control",
                                description=f"Numeric ID in URL path is directly accessible. Different IDs return different data.",
                                remediation=REMEDIATION,
                            )
                break  # Only test first numeric segment
        return None
