"""
Technology fingerprinting and header analysis.
"""
from __future__ import annotations
import re
import logging
from typing import Dict, List

import httpx

logger = logging.getLogger(__name__)

# ── Simple tech fingerprints ──────────────────────────────────
TECH_SIGNATURES = {
    # Headers
    "X-Powered-By": {
        r"PHP/(\d[\d.]*)":        "PHP",
        r"ASP\.NET":              "ASP.NET",
        r"Express":               "Express.js",
        r"Next\.js":              "Next.js",
    },
    "Server": {
        r"nginx/?([\d.]*)":       "Nginx",
        r"Apache/?([\d.]*)":      "Apache",
        r"Microsoft-IIS/?([\d.]*)": "IIS",
        r"LiteSpeed":             "LiteSpeed",
        r"cloudflare":            "Cloudflare",
        r"AmazonS3":              "Amazon S3",
    },
    "X-Generator":   {r"(.+)": "{0}"},
    "X-Drupal-Cache": {r".*": "Drupal"},
    "X-WP-Nonce":    {r".*": "WordPress"},
}

# ── HTML body fingerprints ────────────────────────────────────
BODY_SIGNATURES = {
    r"wp-content/themes":    "WordPress",
    r"wp-includes":          "WordPress",
    r"Drupal.settings":      "Drupal",
    r"Joomla!":              "Joomla",
    r"shopify":              "Shopify",
    r"magento":              "Magento",
    r"laravel_session":      "Laravel",
    r"RAILS_ENV":            "Ruby on Rails",
    r"django":               "Django",
    r"__next":               "Next.js",
    r"react":                "React",
    r"vue\.js":              "Vue.js",
    r"angular":              "Angular",
    r"jquery":               "jQuery",
    r"bootstrap":            "Bootstrap",
    r"graphql":              "GraphQL",
    r"swagger-ui":           "Swagger UI",
}

# ── Security header checks ────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security":  "HSTS",
    "Content-Security-Policy":    "CSP",
    "X-Frame-Options":            "Clickjacking Protection",
    "X-Content-Type-Options":     "MIME Sniffing Protection",
    "Referrer-Policy":            "Referrer Policy",
    "Permissions-Policy":         "Permissions Policy",
    "X-XSS-Protection":           "XSS Filter (legacy)",
    "Cross-Origin-Opener-Policy": "COOP",
    "Cross-Origin-Resource-Policy": "CORP",
}


class Fingerprinter:
    """Identifies technologies, security headers, and risk signals from HTTP responses."""

    def analyse(self, response: httpx.Response) -> Dict:
        """
        Analyse an HTTP response.
        Returns a dict with 'technologies', 'missing_headers', 'interesting_headers'.
        """
        technologies: List[str] = []
        headers = dict(response.headers)
        body = response.text if hasattr(response, "text") else ""

        # Header-based detection
        for header_name, patterns in TECH_SIGNATURES.items():
            value = headers.get(header_name, "")
            if not value:
                continue
            for pattern, tech_label in patterns.items():
                m = re.search(pattern, value, re.IGNORECASE)
                if m:
                    label = tech_label.format(*m.groups()) if "{0}" in tech_label else tech_label
                    technologies.append(label)

        # Body-based detection
        for pattern, tech in BODY_SIGNATURES.items():
            if re.search(pattern, body, re.IGNORECASE):
                if tech not in technologies:
                    technologies.append(tech)

        # Cookie-based detection
        set_cookie = headers.get("set-cookie", "")
        if "PHPSESSID" in set_cookie:
            technologies.append("PHP")
        if "JSESSIONID" in set_cookie:
            technologies.append("Java EE")
        if "ASPSESSIONID" in set_cookie:
            technologies.append("ASP")
        if "laravel_session" in set_cookie:
            technologies.append("Laravel")

        # Security headers
        present_headers = [h for h in SECURITY_HEADERS if h.lower() in {k.lower() for k in headers}]
        missing_headers = [
            h for h in SECURITY_HEADERS if h.lower() not in {k.lower() for k in headers}
        ]

        # Interesting / risky headers
        interesting = {}
        for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                  "X-Generator", "X-Runtime", "X-Version", "Via", "X-Cache"]:
            if h.lower() in {k.lower(): v for k, v in headers.items()}:
                interesting[h] = headers.get(h, "")

        return {
            "technologies": list(set(technologies)),
            "missing_security_headers": missing_headers,
            "present_security_headers": present_headers,
            "interesting_headers": interesting,
            "status_code": response.status_code,
            "server": headers.get("server", headers.get("Server", "")),
            "content_type": headers.get("content-type", ""),
        }
