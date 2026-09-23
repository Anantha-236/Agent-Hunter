#!/usr/bin/env python3
"""
Scanner Detection Verification — Uses realistic mock HTTP responses
to verify that scanners actually DETECT the vulnerabilities they're supposed to find.
"""
import asyncio
import sys
import time
import traceback
import re
from typing import List
from unittest.mock import AsyncMock, MagicMock
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode

from core.models import Scope, Target, ScanState, Finding
from core.orchestrator import SCANNER_REGISTRY
from utils.http_client import HttpClient


@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = ""
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)


def make_vuln_client():
    """Create a mock HTTP client that simulates a VULNERABLE web app."""
    client = MagicMock(spec=HttpClient)
    client._policy_enforcer = None
    client._scope = None
    client.request_log = []
    
    raw_req = "GET / HTTP/1.1\r\nHost: vuln.test\r\n"
    
    async def mock_request(method, url, params=None, data=None, json=None, 
                           content=None, extra_headers=None, headers=None, retries=3):
        body = ""
        status = 200
        resp_headers = {"server": "Apache/2.4.49", "content-type": "text/html",
                        "x-powered-by": "PHP/7.4"}
        
        # Parse URL to check for injected payloads
        parsed = urlparse(url)
        query_str = parsed.query
        qs = parse_qs(query_str, keep_blank_values=True)
        all_vals = " ".join(v for vals in qs.values() for v in vals)
        
        # Also check POST body
        post_vals = ""
        if isinstance(data, dict):
            post_vals = " ".join(str(v) for v in data.values())
        if isinstance(json, dict):
            post_vals = " ".join(str(v) for v in json.values())
        
        all_input = all_vals + " " + post_vals
        
        # ─── Simulate XSS (reflection) — check FIRST (has specific HTML markers) ──
        if "<script>" in all_input or "onerror=" in all_input or "<img" in all_input or "<svg" in all_input or "<iframe" in all_input:
            body = f'<html><body>Search results for: {all_input}</body></html>'
        
        # ─── Simulate SQL Injection (error-based) ─────────────
        elif any(kw in all_input for kw in ["OR 1=1", "UNION", "SELECT", "AND 1=", "ORDER BY", "SLEEP(", "EXTRACTVALUE"]) or (all_input.strip() in ["'", '"', "''", "\\'", "\\"]):
            body = (
                '<html><body>Error: You have an error in your SQL syntax; '
                'check the manual that corresponds to your MySQL server version '
                'for the right syntax to use near &quot;\' at line 1</body></html>'
            )
        
        # ─── Simulate Path Traversal ──────────────────────────
        elif "etc/passwd" in all_input or "../" in all_input:
            body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        
        # ─── Simulate SSTI ────────────────────────────────────
        elif "{{79831*79832}}" in all_input or "79831*79832" in all_input:
            body = f'<html><body>Hello 6375624792!</body></html>'
        elif "${79831*79832}" in all_input:
            body = f'<html><body>Hello 6375624792!</body></html>'
        
        # ─── Simulate Command Injection (output-based) ────────
        elif "echo CMDINJ79831" in all_input:
            body = f'<html><body>CMDINJ79831</body></html>'
        elif ";id;" in all_input or "$(id)" in all_input or "`id`" in all_input:
            body = f'<html><body>uid=33(www-data) gid=33(www-data) groups=33(www-data)</body></html>'
        
        # ─── Simulate SSRF ────────────────────────────────────
        elif "169.254.169.254" in all_input:
            body = '{"ami-id":"ami-12345678","instance-id":"i-abcdef0123456789"}'
        elif "127.0.0.1" in all_input:
            body = '<html><title>Apache Status</title>Server Version: Apache/2.4'
        
        # ─── Sensitive files ──────────────────────────────────
        elif "/.env" in url and ".env" in parsed.path:
            body = "DB_HOST=localhost\nDB_PASS=secret123\nAPI_KEY=sk-12345"
        elif "/.git/HEAD" in url:
            body = "ref: refs/heads/main"
        elif "/phpinfo.php" in url:
            body = "phpinfo()\nPHP Version 8.1.0\n<h1>Configuration</h1>"
        elif "/actuator/env" in url:
            body = '{"propertySources":[{"name":"server.ports"}]}'
        elif "/server-status" in url:
            body = "<html><title>Apache Server Status</title></html>"
        elif "/robots.txt" in url:
            body = "User-agent: *\nDisallow: /admin-panel/\nDisallow: /api/internal/"
        elif "/admin-panel" in url or "/api/internal" in url:
            body = "<html><body>Admin Panel - Internal</body></html>"
        
        # ─── CRLF Injection ───────────────────────────────────
        elif "%0d%0a" in url.lower() or "%0a" in url.lower():
            if "Injected-Header" in url or "Set-Cookie" in url:
                resp_headers["injected-header"] = "BugBountyAgent"
        
        # ─── Default response ─────────────────────────────────
        else:
            body = '<html><head><title>Test App</title></head><body><h1>Welcome</h1></body></html>'
        
        return FakeResponse(status, body, resp_headers, {}), raw_req
    
    async def mock_get(url, params=None, **kwargs):
        return await mock_request("GET", url, params=params, **kwargs)
    
    async def mock_post(url, data=None, json=None, **kwargs):
        return await mock_request("POST", url, data=data, json=json, **kwargs)
    
    async def mock_get_no_redirect(url, **kwargs):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        all_vals = " ".join(v for vals in qs.values() for v in vals)
        if "evil.com" in all_vals:
            return FakeResponse(302, "", {"location": "https://evil.com/steal"}, {}), raw_req
        return FakeResponse(200, "<html></html>", {}, {}), raw_req
    
    async def mock_request_no_redirect(method, url, **kwargs):
        return await mock_get_no_redirect(url, **kwargs)
    
    client.get = AsyncMock(side_effect=mock_get)
    client.post = AsyncMock(side_effect=mock_post)
    client.request = AsyncMock(side_effect=mock_request)
    client.request_no_redirect = AsyncMock(side_effect=mock_request_no_redirect)
    client.get_no_redirect = AsyncMock(side_effect=mock_get_no_redirect)
    client.put = AsyncMock(side_effect=mock_request)
    client.delete = AsyncMock(side_effect=mock_request)
    client.options = AsyncMock(side_effect=mock_request)
    
    return client


def build_test_state():
    target = Target(
        url="http://vuln.test",
        scope=Scope(allowed_domains=["vuln.test"]),
        discovered_urls=[
            "http://vuln.test/search.php?q=hello",
            "http://vuln.test/product.php?id=1",
            "http://vuln.test/callback?url=http://safe.com",
            "http://vuln.test/js/app.js",
        ],
        discovered_params={
            "http://vuln.test/search.php": ["q"],
            "http://vuln.test/product.php": ["id"],
            "http://vuln.test/showimage.php": ["file"],
            "http://vuln.test/callback": ["url"],
        },
        metadata={
            "js_files": ["http://vuln.test/js/app.js"],
        },
    )
    return ScanState(target=target, phase="scanning")


# Define expected detections per scanner
EXPECTED_DETECTIONS = {
    "SQLInjectionScanner": ("sql_injection", True),
    "XSSScanner": ("xss", True),
    "PathTraversalScanner": ("path_traversal", True),
    "SSTIScanner": ("ssti", True),
    "CommandInjectionScanner": ("command_injection", True),
    "SSRFScanner": ("ssrf", True),
    "MisconfigScanner": ("misconfig", True),
    "OpenRedirectScanner": ("open_redirect", True),
    # These don't have specific mock responses, so we just verify they don't crash
    "IDORScanner": ("idor", False),
    "CRLFInjectionScanner": ("crlf", False),
    "LFIRFIScanner": ("lfi", False),
    "AuthScanner": ("auth", False),
    "CSRFScanner": ("csrf", False),
    "JWTScanner": ("jwt", False),
    "RateLimitScanner": ("rate_limit", False),
    "RaceConditionScanner": ("race_condition", False),
    "BrokenAccessControlScanner": ("bac", False),
    "CORSScanner": ("cors", False),
    "HeaderSecurityScanner": ("headers", False),
    "SensitiveDataExposureScanner": ("sensitive_data", False),
    "HostHeaderScanner": ("host_header", False),
    "XXEScanner": ("xxe", False),
    "GraphQLScanner": ("graphql", False),
    "SubdomainTakeoverScanner": ("subdomain", False),
    "SSLTLSScanner": ("ssl", False),
    "OpenAPIScanner": ("openapi_discovery", False),
    "BOLAScanner": ("bola", False),
    "MassAssignmentScanner": ("mass_assignment", False),
    "OAuthOIDCScanner": ("oauth_oidc", False),
    "SessionCookieScanner": ("session_cookie", False),
    "CacheBehaviorScanner": ("authenticated_cache", False),
    "WebSocketScanner": ("websocket", False),
}

SCANNER_IMPORTS = list(SCANNER_REGISTRY.values())


async def main():
    print("=" * 72)
    print("  SCANNER DETECTION VERIFICATION")
    print("  (mock vulnerable server responses)")
    print("=" * 72)
    
    state = build_test_state()
    registered_classes = {class_name for _, class_name in SCANNER_IMPORTS}
    if set(EXPECTED_DETECTIONS) != registered_classes:
        missing = sorted(registered_classes - set(EXPECTED_DETECTIONS))
        stale = sorted(set(EXPECTED_DETECTIONS) - registered_classes)
        print(f"Harness expectation mismatch: missing={missing}, stale={stale}")
        return 1
    errors = []
    passed = []
    detections_passed = 0
    detections_expected = sum(1 for _, (_, expected) in EXPECTED_DETECTIONS.items() if expected)
    
    for module_path, class_name in SCANNER_IMPORTS:
        print(f"  {class_name:40s}", end=" ", flush=True)
        
        try:
            mod = __import__(module_path, fromlist=[class_name])
            cls = getattr(mod, class_name)
        except Exception as e:
            print(f"IMPORT FAIL: {e}")
            errors.append((class_name, f"import: {e}", traceback.format_exc()))
            continue
        
        client = make_vuln_client()
        
        try:
            scanner = cls(client)
            t0 = time.monotonic()
            findings = await asyncio.wait_for(scanner.run(state), timeout=30)
            elapsed = time.monotonic() - t0
            
            _, should_find = EXPECTED_DETECTIONS.get(class_name, ("", False))
            
            if should_find and len(findings) == 0:
                print(f"MISS  0 findings ({elapsed:.1f}s) -- expected detection!")
                errors.append((class_name, "expected findings but got 0", ""))
            elif should_find and len(findings) > 0:
                severities = {}
                for f in findings:
                    s = f.severity.upper()
                    severities[s] = severities.get(s, 0) + 1
                sev_str = ", ".join(f"{c}x{s}" for s, c in severities.items())
                print(f"FOUND {len(findings):3d} findings ({sev_str}) ({elapsed:.1f}s)")
                detections_passed += 1
                passed.append(class_name)
            else:
                print(f"OK    {len(findings):3d} findings ({elapsed:.1f}s)")
                passed.append(class_name)
                
        except asyncio.TimeoutError:
            print(f"TIMEOUT (30s)")
            errors.append((class_name, "timeout", ""))
        except Exception as e:
            tb = traceback.format_exc()
            print(f"ERROR: {type(e).__name__}: {e}")
            errors.append((class_name, f"{type(e).__name__}: {e}", tb))
    
    print("\n" + "=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"\n  Scanners OK:           {len(passed)}/{len(SCANNER_IMPORTS)}")
    print(f"  Scanners ERRORED:      {len(errors)}")
    print(f"  Detection confirmed:   {detections_passed}/{detections_expected}")
    
    if errors:
        print("\n  ERRORS (need patching):")
        for name, err, tb in errors:
            print(f"\n  >> {name}: {err}")
            if tb:
                for line in tb.strip().split("\n")[-6:]:
                    print(f"     {line}")
    
    print(f"\n{'=' * 72}")
    return len(errors)


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
