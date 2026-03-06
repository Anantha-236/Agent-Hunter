"""GraphQL Scanner — detects GraphQL-specific vulnerabilities."""
from __future__ import annotations
import asyncio
import json
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

INTROSPECTION_QUERY = """{"query": "{ __schema { types { name fields { name args { name type { name } } } } } }"}"""

GRAPHQL_PATHS = [
    "/graphql", "/graphql/v1", "/graphql/v2",
    "/api/graphql", "/api/v1/graphql",
    "/gql", "/query", "/graphiql",
]

SQLI_PAYLOADS = [
    """{"query":"{ user(id:\\\"1' OR 1=1--\\\") { id name } }"}""",
    """{"query":"{ user(id:\\\"1\\\") { id name email } }"}""",
]

IDOR_QUERIES = [
    '{"query":"{ user(id:1) { id name email role } }"}',
    '{"query":"{ user(id:2) { id name email role } }"}',
    '{"query":"{ users { id name email role } }"}',
    '{"query":"{ orders(userId:1) { id total status } }"}',
]

DEPTH_BOMB = '{"query":"{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } } }"}'

BATCH_QUERY = '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'


class GraphQLScanner(BaseScanner):
    name = "graphql_scanner"
    description = "Detects GraphQL-specific vulnerabilities"
    tags = ["graphql", "api", "injection"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        graphql_url = None

        # Discover GraphQL endpoint
        for path in GRAPHQL_PATHS:
            from urllib.parse import urljoin
            url = urljoin(state.target.url, path)
            try:
                resp, _ = await self.client.post(
                    url, json={"query": "{ __typename }"},
                    extra_headers={"Content-Type": "application/json"},
                )
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            graphql_url = url
                            break
                    except Exception:
                        pass
            except Exception:
                pass

        # Also check discovered URLs
        if not graphql_url:
            for url in state.target.discovered_urls:
                if "graphql" in url.lower() or "gql" in url.lower():
                    graphql_url = url
                    break

        if not graphql_url:
            return findings

        # Run all checks
        tasks = [
            self._check_introspection(graphql_url),
            self._check_idor(graphql_url),
            self._check_dos(graphql_url),
            self._check_batch(graphql_url),
            self._check_injection(graphql_url),
            self._check_field_suggestions(graphql_url),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)
            elif isinstance(r, list):
                findings.extend(r)

        return findings

    async def _check_introspection(self, url: str) -> Finding | None:
        """Check if introspection is enabled (information disclosure)."""
        try:
            resp, raw_req = await self.client.post(
                url, content=INTROSPECTION_QUERY,
                extra_headers={"Content-Type": "application/json"},
            )
            if not resp:
                return None

            data = resp.json()
            if "data" in data and "__schema" in data.get("data", {}):
                types = data["data"]["__schema"].get("types", [])
                type_names = [t["name"] for t in types if not t["name"].startswith("__")]

                return self.make_finding(
                    title="GraphQL Introspection Enabled",
                    vuln_type="graphql_introspection",
                    severity=Severity.MEDIUM,
                    url=url, parameter="__schema",
                    method="POST",
                    payload=INTROSPECTION_QUERY[:100],
                    evidence=f"Exposed {len(type_names)} types: {type_names[:10]}",
                    request=raw_req,
                    response=resp.text[:500],
                    cwe_id="CWE-200",
                    owasp_category="A01:2021 - Broken Access Control",
                    description=(
                        "GraphQL introspection is enabled, exposing the entire API schema. "
                        "Attackers can discover all queries, mutations, types, and fields."
                    ),
                    poc_steps=[
                        f"1. Send introspection query to {url}",
                        "2. Full schema returned with all types and fields",
                        f"3. {len(type_names)} custom types exposed",
                        "4. Use schema to discover sensitive queries/mutations",
                    ],
                )
        except Exception as exc:
            self.logger.debug(f"GraphQL introspection check error: {exc}")
        return None

    async def _check_idor(self, url: str) -> List[Finding]:
        """Check for IDOR via sequential ID enumeration."""
        findings = []
        for query_str in IDOR_QUERIES:
            try:
                resp, raw_req = await self.client.post(
                    url, content=query_str,
                    extra_headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue

                data = resp.json()
                if "data" in data and data["data"]:
                    # Check if we got data without auth
                    result = data["data"]
                    for key, value in result.items():
                        if value and isinstance(value, (dict, list)):
                            # Check for sensitive fields
                            sensitive = ["email", "phone", "address", "role", "password", "ssn", "credit"]
                            str_val = json.dumps(value).lower()
                            exposed = [s for s in sensitive if s in str_val]
                            if exposed:
                                findings.append(self.make_finding(
                                    title=f"GraphQL BOLA - {key} exposes {', '.join(exposed)}",
                                    vuln_type="graphql_bola",
                                    severity=Severity.HIGH,
                                    url=url, parameter=key,
                                    method="POST",
                                    payload=query_str,
                                    evidence=f"Sensitive data exposed: {exposed}. Response: {str_val[:200]}",
                                    request=raw_req,
                                    response=resp.text[:500],
                                    cwe_id="CWE-639",
                                    owasp_category="A01:2021 - Broken Access Control",
                                    description=f"GraphQL query '{key}' exposes sensitive fields ({', '.join(exposed)}) without authorization.",
                                ))
            except Exception as exc:
                self.logger.debug(f"GraphQL IDOR check error: {exc}")
        return findings

    async def _check_dos(self, url: str) -> Finding | None:
        """Check for depth/complexity DoS."""
        try:
            resp, raw_req = await self.client.post(
                url, content=DEPTH_BOMB,
                extra_headers={"Content-Type": "application/json"},
            )
            if not resp:
                return None

            data = resp.json()
            if "data" in data and data.get("data"):
                return self.make_finding(
                    title="GraphQL Depth Limit Missing (DoS Risk)",
                    vuln_type="graphql_dos",
                    severity=Severity.MEDIUM,
                    url=url,
                    method="POST",
                    payload=DEPTH_BOMB[:100],
                    evidence="Deep nested query accepted without depth limiting",
                    request=raw_req,
                    response=resp.text[:500],
                    cwe_id="CWE-400",
                    owasp_category="A04:2021 - Insecure Design",
                    description="GraphQL server processes deeply nested queries without depth limiting, enabling DoS.",
                )
        except Exception as exc:
            self.logger.debug(f"GraphQL DoS check error: {exc}")
        return None

    async def _check_batch(self, url: str) -> Finding | None:
        """Check if batch queries are allowed (amplification attack)."""
        try:
            resp, raw_req = await self.client.post(
                url, content=BATCH_QUERY,
                extra_headers={"Content-Type": "application/json"},
            )
            if not resp:
                return None

            data = resp.json()
            if isinstance(data, list) and len(data) >= 10:
                return self.make_finding(
                    title="GraphQL Batch Query Allowed (Brute-Force Risk)",
                    vuln_type="graphql_batch",
                    severity=Severity.LOW,
                    url=url,
                    method="POST",
                    payload=BATCH_QUERY[:100],
                    evidence=f"Batch of 10 queries accepted, response count: {len(data)}",
                    request=raw_req,
                    response=resp.text[:500],
                    cwe_id="CWE-307",
                    owasp_category="A04:2021 - Insecure Design",
                    description="GraphQL accepts batched queries, enabling brute-force and amplification attacks.",
                )
        except Exception as exc:
            self.logger.debug(f"GraphQL batch check error: {exc}")
        return None

    async def _check_injection(self, url: str) -> Finding | None:
        """Check for SQL injection via GraphQL arguments."""
        for payload in SQLI_PAYLOADS:
            try:
                resp, raw_req = await self.client.post(
                    url, content=payload,
                    extra_headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue

                body = resp.text.lower()
                sql_errors = ["sql syntax", "mysql", "postgresql", "sqlite", "sqlstate", "odbc"]
                if any(err in body for err in sql_errors):
                    return self.make_finding(
                        title="SQL Injection via GraphQL",
                        vuln_type="graphql_sqli",
                        severity=Severity.CRITICAL,
                        url=url,
                        method="POST",
                        payload=payload[:100],
                        evidence=f"SQL error in GraphQL response: {resp.text[:300]}",
                        request=raw_req,
                        response=resp.text[:500],
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 - Injection",
                        description="GraphQL arguments are vulnerable to SQL injection.",
                    )
            except Exception as exc:
                self.logger.debug(f"GraphQL injection check error: {exc}")
        return None

    async def _check_field_suggestions(self, url: str) -> Finding | None:
        """Check if GraphQL suggests valid field names (info leak)."""
        try:
            resp, raw_req = await self.client.post(
                url,
                content='{"query":"{ __typenameXYZ }"}',
                extra_headers={"Content-Type": "application/json"},
            )
            if not resp:
                return None

            body = resp.text.lower()
            if "did you mean" in body or "suggestions" in body:
                return self.make_finding(
                    title="GraphQL Field Suggestions Enabled",
                    vuln_type="graphql_suggestions",
                    severity=Severity.LOW,
                    url=url,
                    method="POST",
                    payload='{"query":"{ __typenameXYZ }"}',
                    evidence=f"GraphQL suggests field names: {resp.text[:300]}",
                    request=raw_req,
                    response=resp.text[:500],
                    cwe_id="CWE-200",
                    owasp_category="A01:2021 - Broken Access Control",
                    description="GraphQL field suggestion is enabled, leaking valid field names.",
                )
        except Exception as exc:
            self.logger.debug(f"GraphQL field suggestions check error: {exc}")
        return None
