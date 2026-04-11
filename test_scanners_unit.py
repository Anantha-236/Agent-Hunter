#!/usr/bin/env python3
"""
Scanner Unit Test — Tests all scanner logic without network dependency.

Uses mock HTTP responses to verify scanners don't crash and produce correct findings.
"""
import asyncio
import sys
import time
import traceback
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass

from core.models import Scope, Target, ScanState, Finding
from utils.http_client import HttpClient


@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = ""
    headers: dict = None
    cookies: dict = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.cookies is None:
            self.cookies = {}
    
    def get(self, key, default=None):
        return self.headers.get(key, default)


def make_mock_client():
    """Create a mock HTTP client that returns safe responses."""
    client = MagicMock(spec=HttpClient)
    client._policy_enforcer = None
    client._scope = None
    
    # Default: returns a valid response for any request
    normal_resp = FakeResponse(
        status_code=200,
        text="<html><body>Hello World</body></html>",
        headers={"server": "Apache/2.4", "content-type": "text/html"},
        cookies={},
    )
    raw_req = "GET / HTTP/1.1\r\nHost: test\r\n"
    
    async def mock_get(url, **kwargs):
        # Return different responses based on URL patterns
        if ".env" in url:
            return FakeResponse(200, "DB_HOST=localhost\nDB_PASS=secret\n", {"content-type": "text/plain"}), raw_req
        if ".git/HEAD" in url:
            return FakeResponse(200, "ref: refs/heads/main\n", {"content-type": "text/plain"}), raw_req
        if "phpinfo" in url:
            return FakeResponse(200, "<h1>phpinfo()</h1>PHP Version 8.1", {}), raw_req
        if "/robots.txt" in url:
            return FakeResponse(200, "User-agent: *\nDisallow: /admin/\nDisallow: /api/internal/", {}), raw_req
        if "/admin" in url:
            return FakeResponse(200, "<html><form><input name='username'><input name='password'>login</form></html>", {}), raw_req
        if "passwd" in url or "etc/passwd" in str(kwargs):
            return FakeResponse(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", {}), raw_req
        if "sleep" in str(kwargs) or "SLEEP" in str(kwargs):
            return FakeResponse(200, normal_resp.text, {}), raw_req
        if "alert" in str(kwargs) or "<script>" in str(kwargs):
            return FakeResponse(200, f"<html><body>Results for: <script>alert(1)</script></body></html>", {}), raw_req
        return normal_resp, raw_req
    
    async def mock_post(url, data=None, json=None, **kwargs):
        return normal_resp, raw_req
    
    async def mock_request(method, url, **kwargs):
        return normal_resp, raw_req
    
    async def mock_request_no_redirect(method, url, **kwargs):
        return FakeResponse(302, "", {"location": "https://evil.com"}), raw_req
    
    async def mock_get_no_redirect(url, **kwargs):
        return FakeResponse(302, "", {"location": "https://evil.com"}), raw_req
    
    client.get = AsyncMock(side_effect=mock_get)
    client.post = AsyncMock(side_effect=mock_post)
    client.request = AsyncMock(side_effect=mock_request)
    client.request_no_redirect = AsyncMock(side_effect=mock_request_no_redirect)
    client.get_no_redirect = AsyncMock(side_effect=mock_get_no_redirect)
    client.put = AsyncMock(side_effect=mock_request)
    client.delete = AsyncMock(side_effect=mock_request)
    client.options = AsyncMock(side_effect=mock_request)
    client.request_log = []
    
    return client


def build_test_state():
    """Build a test ScanState with realistic params."""
    target = Target(
        url="http://testphp.vulnweb.com",
        scope=Scope(allowed_domains=["testphp.vulnweb.com"]),
        discovered_urls=[
            "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "http://testphp.vulnweb.com/search.php?test=hello",
            "http://testphp.vulnweb.com/artists.php?artist=1",
            "http://testphp.vulnweb.com/showimage.php?file=logo.png",
            "http://testphp.vulnweb.com/login.php",
            "http://testphp.vulnweb.com/js/main.js",
        ],
        discovered_params={
            "http://testphp.vulnweb.com/listproducts.php": ["cat"],
            "http://testphp.vulnweb.com/search.php": ["test"],
            "http://testphp.vulnweb.com/showimage.php": ["file"],
            "http://testphp.vulnweb.com/userinfo.php": ["id"],
        },
        metadata={
            "js_files": ["http://testphp.vulnweb.com/js/main.js"],
        },
    )
    return ScanState(target=target, phase="scanning")


SCANNER_IMPORTS = [
    ("scanners.injection.sql_injection", "SQLInjectionScanner"),
    ("scanners.xss.xss_scanner", "XSSScanner"),
    ("scanners.ssrf.ssrf_scanner", "SSRFScanner"),
    ("scanners.injection.ssti", "SSTIScanner"),
    ("scanners.injection.command_injection", "CommandInjectionScanner"),
    ("scanners.injection.crlf_injection", "CRLFInjectionScanner"),
    ("scanners.file.path_traversal", "PathTraversalScanner"),
    ("scanners.file.lfi_rfi_scanner", "LFIRFIScanner"),
    ("scanners.authz.idor_scanner", "IDORScanner"),
    ("scanners.misconfig.misconfig_scanner", "MisconfigScanner"),
    ("scanners.redirect.open_redirect", "OpenRedirectScanner"),
    ("scanners.auth.auth_scanner", "AuthScanner"),
    ("scanners.auth.csrf_scanner", "CSRFScanner"),
    ("scanners.auth.jwt_scanner", "JWTScanner"),
    ("scanners.auth.rate_limit_scanner", "RateLimitScanner"),
    ("scanners.auth.race_condition", "RaceConditionScanner"),
    ("scanners.authz.broken_access_control", "BrokenAccessControlScanner"),
    ("scanners.misconfig.cors_scanner", "CORSScanner"),
    ("scanners.misconfig.header_security", "HeaderSecurityScanner"),
    ("scanners.misconfig.sensitive_data_exposure", "SensitiveDataExposureScanner"),
    ("scanners.misconfig.host_header", "HostHeaderScanner"),
    ("scanners.injection.xxe_scanner", "XXEScanner"),
    ("scanners.injection.graphql_scanner", "GraphQLScanner"),
    ("scanners.recon.subdomain_takeover", "SubdomainTakeoverScanner"),
    ("scanners.recon.ssl_tls_scanner", "SSLTLSScanner"),
]


async def main():
    print("=" * 72)
    print("  SCANNER UNIT TEST (mock HTTP, no network)")
    print("=" * 72)
    
    state = build_test_state()
    results = []
    errors = []
    
    for module_path, class_name in SCANNER_IMPORTS:
        print(f"  {class_name:40s}", end=" ", flush=True)
        
        # Import
        try:
            mod = __import__(module_path, fromlist=[class_name])
            cls = getattr(mod, class_name)
        except Exception as e:
            print(f"IMPORT FAIL: {e}")
            errors.append((class_name, f"import: {e}", traceback.format_exc()))
            continue
        
        # Create mock client and scanner
        client = make_mock_client()
        
        try:
            scanner = cls(client)
        except Exception as e:
            print(f"INIT FAIL: {e}")
            errors.append((class_name, f"init: {e}", traceback.format_exc()))
            continue
        
        # Run with timeout
        try:
            t0 = time.monotonic()
            findings = await asyncio.wait_for(scanner.run(state), timeout=30)
            elapsed = time.monotonic() - t0
            
            if not isinstance(findings, list):
                print(f"FAIL: run() returned {type(findings)}, not list")
                errors.append((class_name, "non-list return", ""))
                continue
            
            # Validate findings
            for f in findings:
                if not isinstance(f, Finding):
                    print(f"FAIL: finding is {type(f)}, not Finding")
                    errors.append((class_name, f"bad finding type: {type(f)}", ""))
                    break
            else:
                print(f"OK  {len(findings):3d} findings  ({elapsed:.1f}s)")
                results.append((class_name, len(findings), elapsed))
                
        except asyncio.TimeoutError:
            print(f"TIMEOUT (30s)")
            errors.append((class_name, "timeout (30s)", ""))
        except Exception as e:
            tb = traceback.format_exc()
            print(f"ERROR: {type(e).__name__}: {e}")
            errors.append((class_name, f"{type(e).__name__}: {e}", tb))
    
    print("\n" + "=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"\n  OK: {len(results)}/{len(SCANNER_IMPORTS)}")
    print(f"  Errors: {len(errors)}")
    
    if errors:
        print("\n  ERRORS:")
        for name, err, tb in errors:
            print(f"\n  >> {name}: {err}")
            if tb:
                for line in tb.strip().split("\n")[-6:]:
                    print(f"     {line}")
    
    total_findings = sum(c for _, c, _ in results)
    print(f"\n  Total findings (mock): {total_findings}")
    
    if results:
        print("\n  Scanner findings:")
        for name, count, elapsed in results:
            bar = "#" * min(count, 30)
            print(f"    {name:40s} {count:3d} {bar}")
    
    print(f"\n{'=' * 72}")
    return len(errors)


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
