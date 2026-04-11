"""SSL/TLS Scanner (single-host, low-impact transport checks)."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from config.settings import Severity
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState


class SSLTLSScanner(BaseScanner):
    name = "ssl_tls_scanner"
    description = "Detects weak TLS posture: legacy protocol support, weak ciphers, cert issues"
    tags = ["tls", "ssl", "transport", "owasp-a02"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings: List[Finding] = []

        parsed = urlparse(state.target.url)
        host = parsed.hostname
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)

        if not host:
            return findings

        if scheme != "https":
            findings.append(self.make_finding(
                title="Target does not use HTTPS",
                vuln_type="tls_missing_https",
                severity=Severity.MEDIUM,
                url=state.target.url,
                evidence="Primary target URL is not HTTPS",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
            ))
            return findings

        handshake = await asyncio.to_thread(self._handshake_info, host, port)
        if not handshake:
            return findings

        cert, tls_version, cipher = handshake

        cert_findings = self._check_certificate(state.target.url, cert)
        findings.extend(cert_findings)

        if cipher and any(x in cipher.upper() for x in ("RC4", "3DES", "DES", "NULL", "MD5", "EXPORT")):
            findings.append(self.make_finding(
                title="Weak TLS cipher negotiated",
                vuln_type="tls_weak_cipher",
                severity=Severity.HIGH,
                url=state.target.url,
                evidence=f"Negotiated cipher: {cipher}",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
            ))

        legacy = await asyncio.to_thread(self._legacy_protocol_support, host, port)
        if legacy:
            findings.append(self.make_finding(
                title="Legacy TLS protocol support detected",
                vuln_type="tls_legacy_protocol",
                severity=Severity.HIGH,
                url=state.target.url,
                evidence=f"Server accepted deprecated versions: {', '.join(legacy)}",
                cwe_id="CWE-326",
                owasp_category="A02:2021 - Cryptographic Failures",
                description="TLS 1.0/1.1 support increases downgrade and cryptographic risk.",
            ))

        # Record modern protocol for context when no issues were found.
        if tls_version and not legacy:
            findings.append(self.make_finding(
                title="TLS baseline observed",
                vuln_type="tls_baseline",
                severity=Severity.INFO,
                url=state.target.url,
                evidence=f"Negotiated TLS version: {tls_version}; cipher: {cipher}",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
            ))

        return findings

    def _handshake_info(self, host: str, port: int) -> Optional[Tuple[Dict, str, str]]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
                    version = ssock.version() or "unknown"
                    cipher = (ssock.cipher() or ("unknown", "", 0))[0]
                    return cert, version, cipher
        except Exception:
            return None

    def _legacy_protocol_support(self, host: str, port: int) -> List[str]:
        supported: List[str] = []
        versions = []

        if hasattr(ssl, "TLSVersion"):
            versions = [
                ("TLSv1", ssl.TLSVersion.TLSv1),
                ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ]

        for label, version in versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        supported.append(label)
            except Exception:
                continue

        return supported

    def _check_certificate(self, url: str, cert: Dict) -> List:
        findings = []
        if not cert:
            return findings

        subject = cert.get("subject", ())
        issuer = cert.get("issuer", ())
        if subject and issuer and subject == issuer:
            findings.append(self.make_finding(
                title="Self-signed TLS certificate",
                vuln_type="tls_self_signed",
                severity=Severity.MEDIUM,
                url=url,
                evidence="Certificate subject equals issuer",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
            ))

        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                delta_days = int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)
                if delta_days < 0:
                    findings.append(self.make_finding(
                        title="TLS certificate expired",
                        vuln_type="tls_expired_cert",
                        severity=Severity.HIGH,
                        url=url,
                        evidence=f"Certificate expired {abs(delta_days)} day(s) ago",
                        cwe_id="CWE-295",
                        owasp_category="A02:2021 - Cryptographic Failures",
                    ))
                elif delta_days <= 14:
                    findings.append(self.make_finding(
                        title="TLS certificate expiring soon",
                        vuln_type="tls_expiring_cert",
                        severity=Severity.MEDIUM,
                        url=url,
                        evidence=f"Certificate expires in {delta_days} day(s)",
                        cwe_id="CWE-295",
                        owasp_category="A02:2021 - Cryptographic Failures",
                    ))
            except Exception:
                pass

        return findings
