"""Subdomain Takeover Scanner — detects dangling DNS / unclaimed services."""
from __future__ import annotations
import asyncio, re, logging
from typing import List, Optional
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

logger = logging.getLogger(__name__)

# Service fingerprints: (CNAME pattern, response signature, service name)
TAKEOVER_FINGERPRINTS = [
    # AWS S3
    (r"\.s3\.amazonaws\.com", "NoSuchBucket", "Amazon S3"),
    (r"\.s3-website.*\.amazonaws\.com", "NoSuchBucket", "Amazon S3 Website"),
    # GitHub Pages
    (r"\.github\.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    # Heroku
    (r"\.herokuapp\.com", "No such app", "Heroku"),
    (r"\.herokudns\.com", "No such app", "Heroku DNS"),
    # Shopify
    (r"\.myshopify\.com", "Sorry, this shop is currently unavailable", "Shopify"),
    # Tumblr
    (r"\.tumblr\.com", "There's nothing here", "Tumblr"),
    # WordPress.com
    (r"\.wordpress\.com", "Do you want to register", "WordPress.com"),
    # Azure
    (r"\.azurewebsites\.net", "404 Web Site not found", "Azure Web App"),
    (r"\.cloudapp\.net", "404 Web Site not found", "Azure Cloud App"),
    (r"\.azure-api\.net", "not found", "Azure API"),
    (r"\.blob\.core\.windows\.net", "BlobNotFound", "Azure Blob"),
    (r"\.trafficmanager\.net", "404 Web Site not found", "Azure Traffic Manager"),
    # Fastly
    (r"\.fastly\.net", "Fastly error: unknown domain", "Fastly"),
    # Pantheon
    (r"\.pantheonsite\.io", "404 error unknown site", "Pantheon"),
    # Zendesk
    (r"\.zendesk\.com", "Help Center Closed", "Zendesk"),
    # Unbounce
    (r"\.unbouncepages\.com", "The requested URL was not found", "Unbounce"),
    # Surge.sh
    (r"\.surge\.sh", "project not found", "Surge.sh"),
    # Bitbucket
    (r"\.bitbucket\.io", "Repository not found", "Bitbucket"),
    # Ghost
    (r"\.ghost\.io", "The thing you were looking for is no longer here", "Ghost"),
    # Netlify
    (r"\.netlify\.app", "Not Found - Request ID", "Netlify"),
    # Fly.io
    (r"\.fly\.dev", "404 Not Found", "Fly.io"),
    # Vercel
    (r"\.vercel\.app", "DEPLOYMENT_NOT_FOUND", "Vercel"),
]

# Common subdomain prefixes to enumerate
SUBDOMAIN_PREFIXES = [
    "staging", "dev", "test", "beta", "alpha", "demo", "sandbox",
    "api", "api-dev", "api-staging", "cdn", "mail", "blog", "docs",
    "status", "admin", "portal", "app", "m", "mobile", "shop",
    "store", "support", "help", "assets", "static", "media", "img",
    "old", "legacy", "backup", "ci", "jenkins", "git", "gitlab",
]


class SubdomainTakeoverScanner(BaseScanner):
    name = "subdomain_takeover"
    description = "Detects dangling DNS records vulnerable to subdomain takeover"
    tags = ["recon", "takeover", "owasp-a05"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        from urllib.parse import urlparse
        target_host = urlparse(state.target.url).hostname

        # Build list of subdomains to check
        subdomains = set()
        # From discovered URLs
        for url in state.target.discovered_urls:
            host = urlparse(url).hostname
            if host and host != target_host:
                subdomains.add(host)
        # Generate common subdomains (only if in scope)
        domain_parts = target_host.split(".")
        if len(domain_parts) >= 2:
            base_domain = ".".join(domain_parts[-2:])
            for prefix in SUBDOMAIN_PREFIXES:
                candidate = f"{prefix}.{base_domain}"
                # If scope is defined, only test in-scope subdomains
                if state.target.scope and not state.target.scope.is_in_scope(f"https://{candidate}"):
                    continue
                subdomains.add(candidate)

        self.logger.info(f"Checking {len(subdomains)} subdomains for takeover")

        tasks = [self._check_subdomain(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)

        return findings

    async def _check_subdomain(self, hostname: str) -> Optional[Finding]:
        """Check if a subdomain is vulnerable to takeover."""
        url = f"https://{hostname}"
        try:
            resp, raw_req = await self.client.get(url)
        except Exception:
            # Try HTTP if HTTPS fails
            try:
                url = f"http://{hostname}"
                resp, raw_req = await self.client.get(url)
            except Exception:
                return None

        if resp is None:
            return None

        body = resp.text

        # Resolve CNAME to validate the fingerprint match
        cname = await self._resolve_cname(hostname)

        for cname_pattern, signature, service in TAKEOVER_FINGERPRINTS:
            if signature.lower() in body.lower():
                # Verify: CNAME must match the service pattern
                cname_matches = False
                if cname:  # Got a CNAME record
                    cname_matches = bool(re.search(cname_pattern, cname, re.IGNORECASE))
                # If cname is None (DNS failure) or '' (no CNAME), don't match

                if cname_matches:
                    return self.make_finding(
                        title=f"Subdomain Takeover: {hostname} → {service}",
                        vuln_type="subdomain_takeover",
                        severity=Severity.HIGH,
                        url=url,
                        method="GET",
                        parameter="hostname",
                        payload=hostname,
                        evidence=(
                            f"Service '{service}' signature detected: '{signature}'"
                            f"{f' (CNAME: {cname})' if cname else ''}"
                        ),
                        request=raw_req,
                        response=body[:500],
                        cwe_id="CWE-284",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        description=(
                            f"Subdomain {hostname} points to {service} but the resource "
                            f"is unclaimed. An attacker can register the resource and serve "
                            f"arbitrary content on this domain."
                        ),
                        poc_steps=[
                            f"1. Confirm {hostname} has dangling CNAME to {service}",
                            f"2. Register the unclaimed resource on {service}",
                            f"3. Serve content at {hostname}",
                        ],
                    )
        return None

    async def _resolve_cname(self, hostname: str) -> Optional[str]:
        """Attempt CNAME resolution. Returns CNAME target, '' if no CNAME, or None on failure."""
        import subprocess
        import socket
        try:
            # Use nslookup for cross-platform CNAME resolution
            result = await asyncio.to_thread(
                subprocess.run,
                ["nslookup", "-type=cname", hostname],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout + result.stderr
            # Parse CNAME from nslookup output
            cname_match = re.search(
                r'canonical name\s*=\s*(\S+)', output, re.IGNORECASE
            )
            if cname_match:
                return cname_match.group(1).rstrip(".")
            return ""  # Resolved but no CNAME
        except Exception as exc:
            logger.debug(f"CNAME lookup failed for {hostname}: {exc}; falling back to A lookup")
            try:
                # Fallback keeps scanner functional on systems without nslookup.
                await asyncio.to_thread(socket.gethostbyname, hostname)
                return ""  # Host resolves but CNAME unknown
            except Exception:
                return None  # Lookup failed entirely
        return None
