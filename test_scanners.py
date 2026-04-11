#!/usr/bin/env python3
"""
Scanner Integration Test — Tests all scanners against testphp.vulnweb.com

This script:
1. Crawls the target to discover URLs and parameters
2. Runs each scanner individually
3. Reports findings and any errors/exceptions
"""
import asyncio
import logging
import sys
import time
import traceback
from urllib.parse import urlparse, urljoin

from core.models import Scope, Target, ScanState, Finding
from utils.http_client import HttpClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("test_scanners")

TARGET_URL = "http://testphp.vulnweb.com"

# ── Scanner imports ───────────────────────────────────────────

SCANNER_CLASSES = []

def import_scanners():
    """Import all scanner classes."""
    scanners = []
    imports = [
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
    for module_path, class_name in imports:
        try:
            mod = __import__(module_path, fromlist=[class_name])
            cls = getattr(mod, class_name)
            scanners.append((class_name, cls))
            logger.info(f"  OK Imported {class_name}")
        except Exception as e:
            logger.error(f"  FAIL IMPORT: {module_path}.{class_name} -> {e}")
            scanners.append((class_name, None))
    return scanners


async def light_crawl(client: HttpClient, base_url: str) -> dict:
    """Do a quick crawl to discover URLs and parameters."""
    import re
    discovered_urls = set()
    discovered_params = {}
    
    # Fetch main page
    resp, _ = await client.get(base_url)
    if resp:
        body = resp.text
    else:
        logger.warning("Initial crawl failed, using known params only")
        body = ""
    
    
    parsed_base = urlparse(base_url)
    
    # Extract links
    links = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)
    links += re.findall(r'action=["\']([^"\']+)["\']', body, re.IGNORECASE)
    links += re.findall(r'src=["\']([^"\']+\.js)["\']', body, re.IGNORECASE)
    
    for link in links:
        if link.startswith("#") or link.startswith("mailto:"):
            continue
        full = urljoin(base_url, link)
        full_host = urlparse(full).hostname or ""
        if parsed_base.hostname and parsed_base.hostname in full_host:
            discovered_urls.add(full)
    
    # Crawl a few pages to discover params
    pages_to_crawl = list(discovered_urls)[:15]
    for page_url in pages_to_crawl:
        try:
            resp2, _ = await client.get(page_url)
            if not resp2:
                continue
            # Extract links from sub-pages
            sub_links = re.findall(r'href=["\']([^"\']+)["\']', resp2.text, re.IGNORECASE)
            for sl in sub_links:
                full = urljoin(page_url, sl)
                if parsed_base.hostname in urlparse(full).hostname:
                    discovered_urls.add(full)
            # Extract params from URL
            p = urlparse(page_url)
            if p.query:
                from urllib.parse import parse_qs
                params = list(parse_qs(p.query).keys())
                if params:
                    base = page_url.split("?")[0]
                    discovered_params.setdefault(base, [])
                    for param in params:
                        if param not in discovered_params[base]:
                            discovered_params[base].append(param)
            # Extract form params
            forms = re.findall(
                r'<input[^>]*name=["\']([^"\']+)["\']', resp2.text, re.IGNORECASE
            )
            if forms:
                discovered_params.setdefault(page_url.split("?")[0], [])
                for f_param in forms:
                    if f_param not in discovered_params[page_url.split("?")[0]]:
                        discovered_params[page_url.split("?")[0]].append(f_param)
        except Exception:
            continue
    
    # Also add some known vuln endpoints for testphp.vulnweb.com
    known_params = {
        f"{base_url}/listproducts.php": ["cat", "artist"],
        f"{base_url}/search.php": ["test"],
        f"{base_url}/artists.php": ["artist"],
        f"{base_url}/showimage.php": ["file"],
        f"{base_url}/comment.php": ["aid"],
        f"{base_url}/userinfo.php": ["id"],
        f"{base_url}/hpp/params.php": ["p", "pp"],
    }
    for url, params in known_params.items():
        discovered_params.setdefault(url, [])
        for p in params:
            if p not in discovered_params[url]:
                discovered_params[url].append(p)
    
    return {
        "urls": list(discovered_urls),
        "params": discovered_params,
    }


async def run_scanner(scanner_name, scanner_cls, client, state, timeout=60):
    """Run a single scanner with timeout and error handling."""
    if scanner_cls is None:
        return {"name": scanner_name, "status": "IMPORT_FAILED", "findings": [], "error": "Import failed"}
    
    try:
        scanner = scanner_cls(client)
        findings = await asyncio.wait_for(scanner.run(state), timeout=timeout)
        return {
            "name": scanner_name,
            "status": "OK",
            "findings": findings,
            "count": len(findings),
            "error": None,
        }
    except asyncio.TimeoutError:
        return {
            "name": scanner_name,
            "status": "TIMEOUT",
            "findings": [],
            "count": 0,
            "error": f"Timed out after {timeout}s",
        }
    except Exception as e:
        tb = traceback.format_exc()
        return {
            "name": scanner_name,
            "status": "ERROR",
            "findings": [],
            "count": 0,
            "error": f"{type(e).__name__}: {e}",
            "traceback": tb,
        }


async def main():
    print("=" * 72)
    print("  AGENT-HUNTER SCANNER INTEGRATION TEST")
    print(f"  Target: {TARGET_URL}")
    print("=" * 72)
    
    # Import all scanners
    print("\n[1/4] Importing scanners...")
    scanners = import_scanners()
    imported = sum(1 for _, cls in scanners if cls is not None)
    print(f"  => {imported}/{len(scanners)} scanners imported successfully\n")
    
    # Setup HTTP client and scope
    scope = Scope(allowed_domains=["testphp.vulnweb.com", "*.vulnweb.com"])
    
    async with HttpClient(scope=scope, verify_ssl=False) as client:
        # Light crawl
        print("[2/4] Crawling target for URLs and parameters...")
        crawl_data = await light_crawl(client, TARGET_URL)
        print(f"  => Discovered {len(crawl_data['urls'])} URLs")
        print(f"  => Discovered params on {len(crawl_data['params'])} endpoints:")
        for url, params in list(crawl_data['params'].items())[:10]:
            short = url.replace(TARGET_URL, "")
            print(f"    {short}: {params}")
        
        # Build scan state
        target = Target(
            url=TARGET_URL,
            scope=scope,
            discovered_urls=crawl_data["urls"],
            discovered_params=crawl_data["params"],
            metadata={"js_files": [u for u in crawl_data["urls"] if u.endswith(".js")]},
        )
        state = ScanState(target=target, phase="scanning")
        
        # Run each scanner
        print(f"\n[3/4] Running {len(scanners)} scanners (60s timeout each)...")
        print("-" * 72)
        
        results = []
        for scanner_name, scanner_cls in scanners:
            print(f"  Running {scanner_name}...", end=" ", flush=True)
            t0 = time.monotonic()
            result = await run_scanner(scanner_name, scanner_cls, client, state, timeout=60)
            elapsed = time.monotonic() - t0
            
            status = result["status"]
            if status == "OK":
                print(f"OK {result['count']} findings ({elapsed:.1f}s)")
            elif status == "TIMEOUT":
                print(f"TIMEOUT ({elapsed:.1f}s)")
            elif status == "IMPORT_FAILED":
                print(f"FAIL IMPORT")
            else:
                print(f"FAIL ERROR: {result['error']}")
            
            results.append(result)
        
        # Summary
        print("\n" + "=" * 72)
        print("  RESULTS SUMMARY")
        print("=" * 72)
        
        ok = [r for r in results if r["status"] == "OK"]
        errors = [r for r in results if r["status"] == "ERROR"]
        timeouts = [r for r in results if r["status"] == "TIMEOUT"]
        imports_failed = [r for r in results if r["status"] == "IMPORT_FAILED"]
        
        total_findings = sum(r.get("count", 0) for r in results)
        
        print(f"\n  Scanners OK:       {len(ok)}/{len(results)}")
        print(f"  Scanners ERRORED:  {len(errors)}")
        print(f"  Scanners TIMEOUT:  {len(timeouts)}")
        print(f"  Import FAILED:     {len(imports_failed)}")
        print(f"  Total Findings:    {total_findings}")
        
        if errors:
            print(f"\n  {'─' * 60}")
            print("  ERRORS (need patching):")
            print(f"  {'─' * 60}")
            for r in errors:
                print(f"\n  FAIL {r['name']}:")
                print(f"    {r['error']}")
                if "traceback" in r:
                    for line in r["traceback"].strip().split("\n")[-5:]:
                        print(f"    {line}")
        
        if ok:
            print(f"\n  {'─' * 60}")
            print("  FINDINGS BY SCANNER:")
            print(f"  {'─' * 60}")
            for r in ok:
                if r["count"] > 0:
                    print(f"\n  {r['name']} ({r['count']} findings):")
                    for f in r["findings"][:5]:
                        sev = f.severity.upper() if hasattr(f, 'severity') else "?"
                        title = f.title if hasattr(f, 'title') else str(f)
                        print(f"    [{sev}] {title}")
                    if r["count"] > 5:
                        print(f"    ... and {r['count'] - 5} more")
        
        print(f"\n{'=' * 72}")
        
        return errors


if __name__ == "__main__":
    errors = asyncio.run(main())
    sys.exit(1 if errors else 0)
