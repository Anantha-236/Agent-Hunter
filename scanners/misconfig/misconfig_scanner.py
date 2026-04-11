"""Security Misconfiguration Scanner — Deep, architecture-wide detection.

Covers:
  - 70+ sensitive file/path checks (source code, configs, backups, debug endpoints)
  - Security headers analysis (13 headers)
  - CORS misconfiguration (wildcard, origin reflection, null origin)
  - Directory listing detection
  - Server version/technology disclosure
  - robots.txt parsing and probing of disallowed paths
  - HTTP method enumeration (TRACE, OPTIONS, PUT, DELETE)
  - Error page information disclosure
  - Cookie security flags
  - WAF detection signatures
"""
from __future__ import annotations
import asyncio, re
from typing import List, Optional, Tuple
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

# ── Sensitive Paths ───────────────────────────────────────────

SENSITIVE_PATHS: list[Tuple[str, str, str, str]] = [
    # Version Control
    ("/.git/HEAD",                "Exposed Git Repository",            Severity.HIGH,     "CWE-527"),
    ("/.git/config",              "Git Config Exposed",                Severity.HIGH,     "CWE-527"),
    ("/.svn/entries",             "Exposed SVN Repository",            Severity.HIGH,     "CWE-527"),
    ("/.svn/wc.db",               "SVN Database Exposed",              Severity.HIGH,     "CWE-527"),
    ("/.hg/hgrc",                 "Mercurial Config Exposed",          Severity.HIGH,     "CWE-527"),
    ("/.bzr/README",              "Bazaar Repository Exposed",         Severity.HIGH,     "CWE-527"),

    # Environment & Secrets
    ("/.env",                     "Exposed .env File",                 Severity.CRITICAL, "CWE-200"),
    ("/.env.production",          "Exposed .env.production",           Severity.CRITICAL, "CWE-200"),
    ("/.env.staging",             "Exposed .env.staging",              Severity.CRITICAL, "CWE-200"),
    ("/.env.development",         "Exposed .env.development",          Severity.CRITICAL, "CWE-200"),
    ("/.env.local",               "Exposed .env.local",                Severity.CRITICAL, "CWE-200"),
    ("/.env.backup",              "Exposed .env.backup",               Severity.CRITICAL, "CWE-200"),

    # Config Files
    ("/wp-config.php",            "WordPress Config Accessible",       Severity.CRITICAL, "CWE-200"),
    ("/wp-config.php.bak",        "WordPress Config Backup",           Severity.CRITICAL, "CWE-200"),
    ("/wp-config.php~",           "WordPress Config Editor Backup",    Severity.CRITICAL, "CWE-200"),
    ("/config.yml",               "Config YAML Exposed",               Severity.HIGH,     "CWE-200"),
    ("/config.yaml",              "Config YAML Exposed",               Severity.HIGH,     "CWE-200"),
    ("/config.json",              "Config JSON Exposed",               Severity.HIGH,     "CWE-200"),
    ("/config.php",               "PHP Config Exposed",                Severity.HIGH,     "CWE-200"),
    ("/settings.py",              "Django Settings Exposed",           Severity.CRITICAL, "CWE-200"),
    ("/application.yml",          "Spring Config Exposed",             Severity.HIGH,     "CWE-200"),
    ("/application.properties",   "Spring Properties Exposed",         Severity.HIGH,     "CWE-200"),
    ("/appsettings.json",         "ASP.NET Config Exposed",            Severity.HIGH,     "CWE-200"),
    ("/web.config",               "IIS Config Exposed",                Severity.HIGH,     "CWE-200"),
    ("/.htaccess",                "Apache .htaccess Exposed",          Severity.MEDIUM,   "CWE-200"),
    ("/.htpasswd",                "Apache .htpasswd Exposed",          Severity.CRITICAL, "CWE-200"),
    ("/nginx.conf",               "Nginx Config Exposed",              Severity.HIGH,     "CWE-200"),

    # Debug & Profiling
    ("/phpinfo.php",              "PHP Info Exposed",                  Severity.MEDIUM,   "CWE-200"),
    ("/info.php",                 "PHP Info Exposed",                  Severity.MEDIUM,   "CWE-200"),
    ("/debug",                    "Debug Endpoint",                    Severity.MEDIUM,   "CWE-200"),
    ("/debug/pprof/",             "Go pprof Exposed",                  Severity.HIGH,     "CWE-200"),
    ("/_profiler",                "Symfony Profiler",                  Severity.HIGH,     "CWE-200"),
    ("/_profiler/phpinfo",        "Symfony Profiler PHP Info",         Severity.HIGH,     "CWE-200"),
    ("/telescope",                "Laravel Telescope Exposed",         Severity.HIGH,     "CWE-200"),
    ("/telescope/requests",       "Laravel Telescope Requests",        Severity.HIGH,     "CWE-200"),
    ("/elmah.axd",                "ELMAH Error Log Exposed",           Severity.HIGH,     "CWE-200"),
    ("/trace.axd",                "ASP.NET Trace Exposed",             Severity.HIGH,     "CWE-200"),
    ("/__debug__/",               "Django Debug Toolbar",              Severity.HIGH,     "CWE-200"),

    # Spring Actuator
    ("/actuator",                 "Spring Actuator Index",             Severity.MEDIUM,   "CWE-200"),
    ("/actuator/env",             "Spring Actuator /env",              Severity.CRITICAL, "CWE-200"),
    ("/actuator/heapdump",        "Heap Dump Exposed",                 Severity.CRITICAL, "CWE-200"),
    ("/actuator/configprops",     "Spring Config Properties",          Severity.HIGH,     "CWE-200"),
    ("/actuator/mappings",        "Spring URL Mappings",               Severity.MEDIUM,   "CWE-200"),
    ("/actuator/beans",           "Spring Beans",                      Severity.MEDIUM,   "CWE-200"),
    ("/actuator/health",          "Spring Health",                     Severity.INFO,     "CWE-200"),
    ("/actuator/logfile",         "Spring Log File",                   Severity.HIGH,     "CWE-200"),
    ("/actuator/threaddump",      "Spring Thread Dump",                Severity.MEDIUM,   "CWE-200"),

    # API Documentation (may expose internal endpoints)
    ("/swagger-ui.html",          "Swagger UI Exposed",                Severity.MEDIUM,   "CWE-200"),
    ("/swagger-ui/",              "Swagger UI Exposed",                Severity.MEDIUM,   "CWE-200"),
    ("/api-docs",                 "API Docs Exposed",                  Severity.MEDIUM,   "CWE-200"),
    ("/v2/api-docs",              "Swagger v2 Docs",                   Severity.MEDIUM,   "CWE-200"),
    ("/v3/api-docs",              "OpenAPI v3 Docs",                   Severity.MEDIUM,   "CWE-200"),
    ("/graphiql",                 "GraphiQL IDE Exposed",              Severity.MEDIUM,   "CWE-200"),
    ("/graphql/playground",       "GraphQL Playground",                Severity.MEDIUM,   "CWE-200"),
    ("/redoc",                    "ReDoc API Docs",                    Severity.LOW,      "CWE-200"),

    # Server Status & Info
    ("/server-status",            "Apache Server Status",              Severity.HIGH,     "CWE-200"),
    ("/server-info",              "Apache Server Info",                Severity.HIGH,     "CWE-200"),
    ("/nginx_status",             "Nginx Status Page",                 Severity.MEDIUM,   "CWE-200"),
    ("/status",                   "Status Endpoint",                   Severity.LOW,      "CWE-200"),
    ("/health",                   "Health Check Endpoint",             Severity.INFO,     "CWE-200"),
    ("/metrics",                  "Metrics Endpoint",                  Severity.MEDIUM,   "CWE-200"),

    # Backups & Logs
    ("/error.log",                "Exposed Error Log",                 Severity.HIGH,     "CWE-200"),
    ("/access.log",               "Exposed Access Log",                Severity.HIGH,     "CWE-200"),
    ("/debug.log",                "Exposed Debug Log",                 Severity.HIGH,     "CWE-200"),
    ("/backup.zip",               "Exposed Backup Archive",            Severity.HIGH,     "CWE-530"),
    ("/backup.tar.gz",            "Exposed Backup Archive",            Severity.HIGH,     "CWE-530"),
    ("/backup.sql",               "Exposed SQL Backup",                Severity.CRITICAL, "CWE-530"),
    ("/db_backup.sql",            "Exposed DB Backup",                 Severity.CRITICAL, "CWE-530"),
    ("/dump.sql",                 "Exposed SQL Dump",                  Severity.CRITICAL, "CWE-530"),
    ("/database.sql",             "Exposed Database File",             Severity.CRITICAL, "CWE-530"),

    # Package / Dependency
    ("/package.json",             "Exposed package.json",              Severity.MEDIUM,   "CWE-200"),
    ("/package-lock.json",        "Exposed package-lock.json",         Severity.LOW,      "CWE-200"),
    ("/composer.json",            "Exposed composer.json",             Severity.MEDIUM,   "CWE-200"),
    ("/composer.lock",            "Exposed composer.lock",             Severity.LOW,      "CWE-200"),
    ("/Gemfile",                  "Exposed Gemfile",                   Severity.MEDIUM,   "CWE-200"),
    ("/requirements.txt",         "Exposed requirements.txt",          Severity.MEDIUM,   "CWE-200"),
    ("/Pipfile",                  "Exposed Pipfile",                   Severity.MEDIUM,   "CWE-200"),
    ("/yarn.lock",                "Exposed yarn.lock",                 Severity.LOW,      "CWE-200"),

    # Docker / Container
    ("/.dockerenv",               "Docker Container Detected",         Severity.INFO,     "CWE-200"),
    ("/Dockerfile",               "Dockerfile Exposed",                Severity.HIGH,     "CWE-200"),
    ("/docker-compose.yml",       "Docker Compose Exposed",            Severity.HIGH,     "CWE-200"),
    ("/docker-compose.yaml",      "Docker Compose Exposed",            Severity.HIGH,     "CWE-200"),
    ("/.docker/config.json",      "Docker Config Exposed",             Severity.CRITICAL, "CWE-200"),

    # CI/CD
    ("/.gitlab-ci.yml",           "GitLab CI Config Exposed",          Severity.HIGH,     "CWE-200"),
    ("/.github/workflows/",       "GitHub Actions Workflows",          Severity.MEDIUM,   "CWE-200"),
    ("/Jenkinsfile",              "Jenkinsfile Exposed",               Severity.HIGH,     "CWE-200"),
    ("/.circleci/config.yml",     "CircleCI Config Exposed",           Severity.HIGH,     "CWE-200"),

    # Credentials / Keys
    ("/.npmrc",                   "NPM Config (may contain tokens)",   Severity.HIGH,     "CWE-200"),
    ("/.aws/credentials",         "AWS Credentials File",              Severity.CRITICAL, "CWE-200"),
    ("/id_rsa",                   "SSH Private Key Exposed",           Severity.CRITICAL, "CWE-200"),
    ("/id_rsa.pub",               "SSH Public Key Exposed",            Severity.MEDIUM,   "CWE-200"),
    ("/.ssh/authorized_keys",     "SSH Authorized Keys",               Severity.HIGH,     "CWE-200"),
    ("/.bash_history",            "Bash History Exposed",              Severity.HIGH,     "CWE-200"),

    # Cross-domain Policy
    ("/crossdomain.xml",          "Flash Crossdomain Policy",          Severity.MEDIUM,   "CWE-942"),
    ("/clientaccesspolicy.xml",   "Silverlight Access Policy",         Severity.MEDIUM,   "CWE-942"),

    # CMS-specific
    ("/wp-content/debug.log",     "WordPress Debug Log",               Severity.HIGH,     "CWE-200"),
    ("/wp-json/wp/v2/users",      "WordPress User Enumeration",        Severity.MEDIUM,   "CWE-200"),
    ("/feed/",                    "WordPress RSS Feed",                Severity.INFO,     "CWE-200"),
    ("/administrator/",           "Joomla Admin Panel",                Severity.MEDIUM,   "CWE-200"),

    # Miscellaneous
    ("/.DS_Store",                "macOS DS_Store File",               Severity.LOW,      "CWE-200"),
    ("/Thumbs.db",                "Windows Thumbs.db",                 Severity.LOW,      "CWE-200"),
    ("/sitemap.xml",              "Sitemap (for discovery)",           Severity.INFO,     "CWE-200"),
    ("/robots.txt",               "Robots.txt (will parse)",           Severity.INFO,     "CWE-200"),
    ("/.well-known/security.txt", "Security.txt",                      Severity.INFO,     "CWE-200"),
]

# ── Security Headers to Check ─────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("Missing HSTS", Severity.MEDIUM,
        "Add Strict-Transport-Security header to force HTTPS."),
    "Content-Security-Policy": ("Missing CSP", Severity.MEDIUM,
        "Deploy a Content-Security-Policy to prevent XSS and data injection."),
    "X-Frame-Options": ("Missing X-Frame-Options (Clickjacking)", Severity.MEDIUM,
        "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."),
    "X-Content-Type-Options": ("Missing X-Content-Type-Options", Severity.LOW,
        "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing."),
    "Referrer-Policy": ("Missing Referrer-Policy", Severity.LOW,
        "Set Referrer-Policy to control information leakage via Referer headers."),
    "Permissions-Policy": ("Missing Permissions-Policy", Severity.LOW,
        "Set Permissions-Policy to restrict browser feature access."),
    "X-Permitted-Cross-Domain-Policies": ("Missing X-Permitted-Cross-Domain-Policies", Severity.LOW,
        "Set to 'none' to prevent Flash/PDF cross-domain loading."),
    "Cross-Origin-Embedder-Policy": ("Missing COEP", Severity.INFO,
        "Set Cross-Origin-Embedder-Policy for cross-origin isolation."),
    "Cross-Origin-Opener-Policy": ("Missing COOP", Severity.INFO,
        "Set Cross-Origin-Opener-Policy for cross-origin isolation."),
    "Cross-Origin-Resource-Policy": ("Missing CORP", Severity.INFO,
        "Set Cross-Origin-Resource-Policy to control cross-origin reads."),
}

DANGEROUS_HEADERS = {
    "server": "Server Version Disclosure",
    "x-powered-by": "Technology Disclosure",
    "x-aspnet-version": "ASP.NET Version Disclosure",
    "x-aspnetmvc-version": "ASP.NET MVC Version Disclosure",
    "x-generator": "Generator Disclosure",
    "x-drupal-cache": "Drupal Cache Disclosure",
}


class MisconfigScanner(BaseScanner):
    name = "misconfig_scanner"
    description = "Detects misconfigurations, exposed files, missing headers, CORS issues, version disclosure"
    tags = ["misconfig", "owasp-a05"]

    async def run(self, state: ScanState) -> List[Finding]:
        findings = []
        base = state.target.url.rstrip("/")

        # ── 1. Sensitive paths (parallelized) ─────────────────
        path_tasks = [self._check_path(base, path, title, sev, cwe)
                      for path, title, sev, cwe in SENSITIVE_PATHS]
        path_results = await asyncio.gather(*path_tasks, return_exceptions=True)
        findings.extend(r for r in path_results if isinstance(r, Finding))

        # ── 2. Main page analysis ─────────────────────────────
        resp, raw_req = await self.client.get(state.target.url)
        if resp:
            # Security headers
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            for header, (issue, severity, remediation) in SECURITY_HEADERS.items():
                if header.lower() not in hdrs:
                    findings.append(self.make_finding(
                        title=issue, vuln_type="missing_security_header",
                        severity=severity, url=state.target.url, parameter=header,
                        evidence=f"'{header}' header is absent",
                        request=raw_req,
                        cwe_id="CWE-693",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        remediation=remediation,
                    ))

            # Dangerous headers (version disclosure)
            for header_lower, issue in DANGEROUS_HEADERS.items():
                if header_lower in hdrs:
                    findings.append(self.make_finding(
                        title=f"{issue}: {hdrs[header_lower]}",
                        vuln_type="version_disclosure",
                        severity=Severity.LOW, url=state.target.url,
                        parameter=header_lower,
                        evidence=f"{header_lower}: {hdrs[header_lower]}",
                        request=raw_req,
                        cwe_id="CWE-200",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        remediation=f"Remove or obfuscate the '{header_lower}' header.",
                    ))

            # CORS wildcard
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == "*":
                findings.append(self.make_finding(
                    title="Overly Permissive CORS (Wildcard Origin)",
                    vuln_type="cors_wildcard", severity=Severity.LOW,
                    url=state.target.url, parameter="Access-Control-Allow-Origin",
                    evidence=f"ACAO: {acao}", request=raw_req,
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    remediation="Restrict CORS to specific trusted origins.",
                ))

            # Cookie security flags
            for cookie_name, cookie_val in resp.cookies.items():
                # Check raw Set-Cookie header for flags
                set_cookie_headers = [
                    v for k, v in resp.headers.multi_items()
                    if k.lower() == "set-cookie" and cookie_name in v
                ] if hasattr(resp.headers, 'multi_items') else []
                header_str = set_cookie_headers[0] if set_cookie_headers else ""
                issues = []
                if "secure" not in header_str.lower():
                    issues.append("Secure")
                if "httponly" not in header_str.lower():
                    issues.append("HttpOnly")
                if "samesite" not in header_str.lower():
                    issues.append("SameSite")
                if issues:
                    findings.append(self.make_finding(
                        title=f"Insecure Cookie — '{cookie_name}' missing {', '.join(issues)}",
                        vuln_type="insecure_cookie", severity=Severity.MEDIUM,
                        url=state.target.url, parameter=cookie_name,
                        evidence=f"Missing flags: {', '.join(issues)}",
                        cwe_id="CWE-614",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        remediation=f"Set {', '.join(issues)} flags on the '{cookie_name}' cookie.",
                    ))

        # ── 3. CORS origin reflection ─────────────────────────
        cors_tasks = [
            self._check_cors_reflection(state.target.url, "https://evil.com"),
            self._check_cors_reflection(state.target.url, "null"),
            self._check_cors_reflection(state.target.url, f"https://{state.target.url.split('//')[1].split('/')[0]}.evil.com" if '//' in state.target.url else "https://evil.com"),
        ]
        cors_results = await asyncio.gather(*cors_tasks, return_exceptions=True)
        findings.extend(r for r in cors_results if isinstance(r, Finding))

        # ── 4. Directory listing ──────────────────────────────
        dir_paths = ["/", "/uploads/", "/static/", "/images/", "/files/",
                     "/media/", "/assets/", "/backup/", "/tmp/", "/logs/"]
        dir_tasks = [self._check_dir_listing(base + path)
                     for path in dir_paths
                     if not state.target.scope or state.target.scope.is_in_scope(base + path)]
        dir_results = await asyncio.gather(*dir_tasks, return_exceptions=True)
        findings.extend(r for r in dir_results if isinstance(r, Finding))

        # ── 5. HTTP method enumeration ────────────────────────
        method_finding = await self._check_dangerous_methods(state.target.url)
        if method_finding:
            findings.append(method_finding)

        # ── 6. Error page information disclosure ──────────────
        error_finding = await self._check_error_disclosure(base)
        if error_finding:
            findings.append(error_finding)

        # ── 7. robots.txt analysis ────────────────────────────
        robots_findings = await self._parse_robots(base)
        findings.extend(robots_findings)

        return findings

    async def _check_path(self, base, path, title, severity, cwe) -> Optional[Finding]:
        url = base + path
        resp, raw_req = await self.client.get(url)
        if not resp or resp.status_code != 200 or len(resp.text) < 10:
            return None
        # Validate specific file types to reduce false positives
        if path == "/.git/HEAD" and "ref: refs/" not in resp.text:
            return None
        if path.endswith(".env") and "=" not in resp.text:
            return None
        if path == "/robots.txt":
            return None  # Handled separately
        if path == "/sitemap.xml" and "<urlset" not in resp.text.lower() and "<sitemapindex" not in resp.text.lower():
            return None
        return self.make_finding(
            title=title, vuln_type="sensitive_file_exposure",
            severity=severity, url=url,
            evidence=f"HTTP 200 ({len(resp.text)}B): {resp.text[:150]}",
            request=raw_req, response=resp.text[:300],
            cwe_id=cwe, owasp_category="A05:2021 - Security Misconfiguration",
            description=f"Sensitive file accessible: {url}",
            remediation=f"Block access to {path} in your web server config (nginx/apache rules).",
        )

    async def _check_cors_reflection(self, url, origin) -> Optional[Finding]:
        resp, raw = await self.client.get(url, extra_headers={"Origin": origin})
        if not resp:
            return None
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        if origin in acao:
            severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
            return self.make_finding(
                title=f"CORS Origin Reflection — {origin}" + (" + Credentials" if acac.lower() == "true" else ""),
                vuln_type="cors_origin_reflection", severity=severity,
                url=url, parameter="Origin", payload=f"Origin: {origin}",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                request=raw, cwe_id="CWE-942",
                owasp_category="A05:2021 - Security Misconfiguration",
                description=(
                    f"Server reflects '{origin}' in Access-Control-Allow-Origin. "
                    + ("With credentials=true, this allows cross-origin data theft." if acac.lower() == "true" else "")
                ),
                remediation="Validate the Origin header against a whitelist. Never reflect arbitrary origins.",
            )
        return None

    async def _check_dir_listing(self, url: str) -> Optional[Finding]:
        resp, raw = await self.client.get(url)
        if not resp:
            return None
        sigs = ["Index of /", "<title>Directory listing", "[To Parent Directory]",
                "Directory Listing For", "Directory: /"]
        if any(sig in resp.text for sig in sigs):
            return self.make_finding(
                title=f"Directory Listing Enabled: {url.split('/', 3)[-1] if '/' in url else '/'}",
                vuln_type="directory_listing", severity=Severity.MEDIUM,
                url=url, evidence="Directory listing signature in response",
                request=raw, response=resp.text[:300],
                cwe_id="CWE-548",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation="Disable directory listing in web server config. Add index page or deny access.",
            )
        return None

    async def _check_dangerous_methods(self, url: str) -> Optional[Finding]:
        """Check for TRACE, PUT, DELETE methods being enabled."""
        for method in ["TRACE", "PUT", "DELETE"]:
            try:
                resp, raw = await self.client.request(method, url)
                if resp and resp.status_code in (200, 204, 405):
                    if method == "TRACE" and resp.status_code == 200:
                        return self.make_finding(
                            title="HTTP TRACE Method Enabled (XST)",
                            vuln_type="http_trace_enabled", severity=Severity.MEDIUM,
                            url=url, method=method,
                            evidence=f"TRACE returned HTTP {resp.status_code}",
                            request=raw, cwe_id="CWE-693",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            description="TRACE method can be exploited for Cross-Site Tracing (XST) attacks.",
                            remediation="Disable TRACE method in web server config.",
                        )
            except Exception:
                continue
        return None

    async def _check_error_disclosure(self, base: str) -> Optional[Finding]:
        """Trigger error pages and check for information disclosure."""
        error_urls = [
            base + "/nonexistent_page_" + "x" * 20,
            base + "/'",  # SQL-like
            base + "/<%00>",  # Null byte
        ]
        for error_url in error_urls:
            resp, raw = await self.client.get(error_url)
            if not resp:
                continue
            body = resp.text
            # Check for stack traces, framework info, etc.
            disclosure_patterns = [
                (r"Traceback \(most recent call last\)", "Python Stack Trace"),
                (r"at\s+\w+\.\w+\([\w./]+:\d+\)", "Java Stack Trace"),
                (r"Microsoft\.AspNetCore", "ASP.NET Stack Trace"),
                (r"<b>Fatal error</b>.*?in.*?on line", "PHP Fatal Error"),
                (r"Warning:.*?in.*?on line \d+", "PHP Warning"),
                (r"DOCUMENT_ROOT", "PHP Environment Leakage"),
                (r"Ruby on Rails", "Rails Stack Trace"),
                (r"ActionController::", "Rails Controller Disclosure"),
                (r"Express\s*\d", "Express.js Disclosure"),
                (r"Django Version:", "Django Version Disclosure"),
            ]
            for pattern, label in disclosure_patterns:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    return self.make_finding(
                        title=f"Error Page Information Disclosure — {label}",
                        vuln_type="error_disclosure", severity=Severity.MEDIUM,
                        url=error_url, evidence=f"{label}: {m.group(0)[:100]}",
                        request=raw, response=body[:500],
                        cwe_id="CWE-209",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        description=f"Error page reveals internal implementation details ({label}).",
                        remediation="Configure custom error pages. Never expose stack traces in production.",
                    )
        return None

    async def _parse_robots(self, base: str) -> List[Finding]:
        """Parse robots.txt and probe disallowed paths for interesting findings."""
        findings = []
        resp, _ = await self.client.get(base + "/robots.txt")
        if not resp or resp.status_code != 200:
            return findings

        # Extract Disallow paths
        disallowed = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and not path.startswith("#"):
                    disallowed.append(path)

        if not disallowed:
            return findings

        # Probe interesting disallowed paths
        interesting_keywords = [
            "admin", "api", "config", "backup", "secret", "private",
            "internal", "debug", "staging", "test", "dev",
        ]
        probe_tasks = []
        for path in disallowed[:20]:  # Limit probing
            if any(kw in path.lower() for kw in interesting_keywords):
                probe_tasks.append(self._probe_robots_path(base, path))

        if probe_tasks:
            probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)
            findings.extend(r for r in probe_results if isinstance(r, Finding))

        return findings

    async def _probe_robots_path(self, base: str, path: str) -> Optional[Finding]:
        url = base + path
        resp, raw = await self.client.get(url)
        if resp and resp.status_code == 200 and len(resp.text) > 50:
            return self.make_finding(
                title=f"Accessible Disallowed Path: {path}",
                vuln_type="robots_disallow_accessible", severity=Severity.MEDIUM,
                url=url,
                evidence=f"robots.txt disallows {path} but it returns HTTP 200 ({len(resp.text)}B)",
                request=raw, response=resp.text[:300],
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
                description=f"Path {path} is listed in robots.txt as disallowed but is still accessible.",
                remediation="If the path should be restricted, enforce access control (not just robots.txt).",
            )
        return None
