"""
Asset Discovery Engine
Discovers subdomains, open ports, and services for a given target.
Used as the first phase in the Hunter workflow before scanning.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set
from urllib.parse import urlparse

from core.models import Scope

logger = logging.getLogger(__name__)

# ── Subdomain wordlist (common prefixes) ─────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "ns1", "ns2", "mx", "webmail", "remote", "vpn", "portal",
    "blog", "shop", "store", "app", "cdn", "static", "img",
    "media", "docs", "wiki", "support", "help", "status",
    "m", "mobile", "beta", "alpha", "demo", "internal",
    "git", "gitlab", "jenkins", "ci", "build", "monitor",
    "grafana", "kibana", "elastic", "db", "database", "sql",
    "redis", "smtp", "pop", "imap", "proxy", "gateway",
    "auth", "sso", "login", "accounts", "dashboard", "panel",
    "cpanel", "whm", "plesk", "backup", "old", "new", "v2",
]

# ── Ports to scan ────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 2083, 2087, 3000,
    3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
    9090, 9200, 27017,
]

PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpc",
    135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2083: "cpanel", 2087: "whm", 3000: "dev-server",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt2",
    9090: "web-console", 9200: "elasticsearch", 27017: "mongodb",
}


@dataclass
class DiscoveredSubdomain:
    hostname: str
    ip: str = ""
    resolved: bool = False


@dataclass
class DiscoveredPort:
    host: str
    port: int
    service: str = ""
    state: str = "open"


@dataclass
class ReconResult:
    target: str
    subdomains: List[DiscoveredSubdomain] = field(default_factory=list)
    ports: List[DiscoveredPort] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class AssetDiscovery:
    """Discovers subdomains, open ports, and services for a target."""

    def __init__(
        self,
        timeout: float = 2.0,
        port_concurrency: int = 50,
        scope: Optional[Scope] = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        user_agent: Optional[str] = None,
    ):
        self.timeout = timeout
        self.port_concurrency = port_concurrency
        self.scope = scope
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.user_agent = user_agent or "AgentHunter/2.1"

    @staticmethod
    def extract_domain(url_or_ip: str) -> str:
        """Extract the base domain from a URL or return IP as-is."""
        if url_or_ip.startswith(("http://", "https://")):
            parsed = urlparse(url_or_ip)
            return parsed.hostname or url_or_ip
        return url_or_ip.split(":")[0].strip()

    async def discover(
        self,
        target: str,
        on_event: Optional[Callable] = None,
    ) -> ReconResult:
        """Run full asset discovery: subdomains → ports → tech detection."""
        domain = self.extract_domain(target)
        result = ReconResult(target=domain)

        if on_event:
            on_event("status", {"msg": f"Starting asset discovery for {domain}"})

        # Phase 1: Subdomain enumeration
        if on_event:
            on_event("status", {"msg": "Enumerating subdomains..."})
        result.subdomains = await self._enumerate_subdomains(domain, on_event)

        # Phase 2: Port scanning on all resolved hosts
        if on_event:
            on_event("status", {"msg": "Scanning ports on discovered hosts..."})
        hosts_to_scan = [domain] if self._host_is_in_scope(domain, on_event) else []
        for sub in result.subdomains:
            if sub.resolved and sub.hostname != domain and self._host_is_in_scope(sub.hostname, on_event):
                hosts_to_scan.append(sub.hostname)

        for host in hosts_to_scan:
            ports = await self._scan_ports(host, on_event)
            result.ports.extend(ports)

        # Phase 3: Technology detection on web ports
        if on_event:
            on_event("status", {"msg": "Detecting technologies on web services..."})
        result.technologies = await self._detect_technologies(result.ports, on_event)

        if on_event:
            on_event("status", {"msg": f"Discovery complete — {len(result.subdomains)} hosts, {len(result.ports)} open ports"})

        return result

    # ── Subdomain enumeration ─────────────────────────────────

    async def _enumerate_subdomains(
        self, domain: str, on_event: Optional[Callable] = None
    ) -> List[DiscoveredSubdomain]:
        found: List[DiscoveredSubdomain] = []

        # Resolve main domain first
        main_ip = await self._resolve_host(domain)
        if main_ip and self._host_is_in_scope(domain, on_event):
            found.append(DiscoveredSubdomain(hostname=domain, ip=main_ip, resolved=True))
            if on_event:
                on_event("subdomain", {"hostname": domain, "ip": main_ip})

        # Try common subdomain prefixes concurrently
        tasks = [self._check_subdomain(f"{prefix}.{domain}") for prefix in COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for sub_result in results:
            if (
                isinstance(sub_result, DiscoveredSubdomain)
                and sub_result.resolved
                and self._host_is_in_scope(sub_result.hostname, on_event)
            ):
                found.append(sub_result)
                if on_event:
                    on_event("subdomain", {"hostname": sub_result.hostname, "ip": sub_result.ip})

        return found

    async def _check_subdomain(self, hostname: str) -> DiscoveredSubdomain:
        ip = await self._resolve_host(hostname)
        return DiscoveredSubdomain(hostname=hostname, ip=ip or "", resolved=bool(ip))

    async def _resolve_host(self, hostname: str) -> Optional[str]:
        try:
            loop = asyncio.get_event_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, family=socket.AF_INET),
                timeout=self.timeout,
            )
            if infos:
                return infos[0][4][0]
        except (socket.gaierror, asyncio.TimeoutError, OSError):
            pass
        return None

    # ── Port scanning ─────────────────────────────────────────

    async def _scan_ports(
        self, host: str, on_event: Optional[Callable] = None
    ) -> List[DiscoveredPort]:
        open_ports: List[DiscoveredPort] = []
        semaphore = asyncio.Semaphore(self.port_concurrency)

        async def check_port(port: int):
            async with semaphore:
                service = PORT_SERVICE_MAP.get(port, "unknown")
                candidate_url = self._port_url(host, port, service)
                if not self._url_is_in_scope(candidate_url):
                    self._emit_out_of_scope(candidate_url, on_event)
                    return
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self.timeout,
                    )
                    writer.close()
                    await writer.wait_closed()

                    dp = DiscoveredPort(host=host, port=port, service=service)
                    open_ports.append(dp)

                    if on_event:
                        on_event("port", {"host": host, "port": port, "service": service})
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

        await asyncio.gather(*[check_port(p) for p in COMMON_PORTS])
        return sorted(open_ports, key=lambda p: p.port)

    # ── Technology detection (HTTP fingerprinting) ────────────

    async def _detect_technologies(
        self, ports: List[DiscoveredPort], on_event: Optional[Callable] = None
    ) -> List[str]:
        technologies: Set[str] = set()
        web_services = {"http", "https", "http-alt", "http-proxy", "https-alt", "http-alt2", "dev-server", "web-console"}
        web_ports = [p for p in ports if p.service in web_services]

        for port_info in web_ports:
            scheme = "https" if port_info.service in ("https", "https-alt") else "http"
            port_suffix = f":{port_info.port}" if port_info.port not in (80, 443) else ""
            url = f"{scheme}://{port_info.host}{port_suffix}"
            if not self._url_is_in_scope(url):
                self._emit_out_of_scope(url, on_event)
                continue

            try:
                import httpx
                async with httpx.AsyncClient(
                    verify=self.verify_ssl,
                    timeout=5.0,
                    headers={"User-Agent": self.user_agent},
                ) as client:
                    resp = await client.get(url, follow_redirects=self.follow_redirects)

                from recon.fingerprint import Fingerprinter
                fp = Fingerprinter().analyse(resp)
                for tech in fp.get("technologies", []):
                    if tech not in technologies:
                        technologies.add(tech)
                        if on_event:
                            on_event("technology", {"tech": tech, "source": url})
            except Exception:
                pass

        return list(technologies)

    def _host_is_in_scope(self, host: str, on_event: Optional[Callable] = None) -> bool:
        if not self.scope:
            return True
        if self.scope.is_host_in_scope(host):
            return True
        self._emit_out_of_scope(host, on_event)
        return False

    def _url_is_in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        return self.scope.is_in_scope(url)

    def _emit_out_of_scope(self, candidate: str, on_event: Optional[Callable] = None) -> None:
        logger.info("Skipping out-of-scope asset: %s", candidate)
        if on_event:
            on_event("status", {"msg": f"Skipped out-of-scope asset: {candidate}"})

    @staticmethod
    def _port_url(host: str, port: int, service: str) -> str:
        scheme = "https" if service in ("https", "https-alt") or port in (443, 8443) else "http"
        port_suffix = f":{port}" if port not in (80, 443) else ""
        return f"{scheme}://{host}{port_suffix}"
