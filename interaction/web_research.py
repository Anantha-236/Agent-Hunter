"""Live web research helpers for Hunter chat and external bots."""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

# Pattern to detect IP addresses (v4) in user messages
_IP_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)


class WebResearchTool:
    """Fetches compact live knowledge from public web endpoints."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def research(self, query: str) -> str:
        query = (query or "").strip()
        if not query:
            return "Usage: /search <query>"

        snippets: List[str] = []
        sources: List[str] = []

        duck = await self._duckduckgo_answer(query)
        if duck:
            snippets.append(duck["summary"])
            sources.extend(duck["sources"])

        wiki = await self._wikipedia_summary(query)
        if wiki:
            snippets.append(wiki["summary"])
            sources.extend(wiki["sources"])

        if not snippets:
            return (
                f"No live web result found for '{query}'. "
                "Try a narrower query or teach Hunter directly with /learn."
            )

        source_lines = "\n".join(f"- {source}" for source in sources[:5])
        body = "\n\n".join(snippets[:2])
        return f"Web research for {query}\n\n{body}\n\nSources:\n{source_lines}"

    async def _duckduckgo_answer(self, query: str) -> Optional[Dict[str, Any]]:
        url = (
            "https://api.duckduckgo.com/"
            f"?q={quote(query)}&format=json&no_html=1&skip_disambig=1"
        )
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "AgentHunter/2.1"})
            if resp.status_code != 200:
                return None

            data = resp.json()
            abstract = (data.get("AbstractText") or "").strip()
            heading = (data.get("Heading") or query).strip()
            source_url = (data.get("AbstractURL") or "").strip()

            if abstract:
                summary = f"{heading}: {abstract}"
                sources = [source_url] if source_url else []
                return {"summary": summary, "sources": sources}

            related = data.get("RelatedTopics") or []
            for topic in related:
                if isinstance(topic, dict) and topic.get("Text"):
                    summary = topic["Text"]
                    first_url = topic.get("FirstURL", "")
                    sources = [first_url] if first_url else []
                    return {"summary": summary, "sources": sources}
        except Exception:
            return None
        return None

    async def _wikipedia_summary(self, query: str) -> Optional[Dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                search = await client.get(
                    "https://en.wikipedia.org/w/api.php",
                    params={
                        "action": "query",
                        "list": "search",
                        "srsearch": query,
                        "utf8": 1,
                        "format": "json",
                    },
                    headers={"User-Agent": "AgentHunter/2.1"},
                )
            if search.status_code != 200:
                return None

            search_data = search.json()
            results = search_data.get("query", {}).get("search", [])
            if not results:
                return None

            title = results[0]["title"]
            summary_url = (
                "https://en.wikipedia.org/api/rest_v1/page/summary/"
                f"{quote(title)}"
            )
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                summary_resp = await client.get(
                    summary_url,
                    headers={"User-Agent": "AgentHunter/2.1"},
                )
            if summary_resp.status_code != 200:
                return None

            page = summary_resp.json()
            extract = (page.get("extract") or "").strip()
            if not extract:
                return None
            page_url = (
                page.get("content_urls", {})
                .get("desktop", {})
                .get("page", "")
            )
            return {
                "summary": f"{title}: {extract}",
                "sources": [page_url] if page_url else [],
            }
        except Exception:
            return None

    # ── IP address lookup ─────────────────────────────────────

    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Return all IPv4-like strings found in *text*."""
        return _IP_RE.findall(text)

    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        """Return True if *ip_str* is a syntactically valid IPv4 address."""
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except ValueError:
            return False

    async def ip_lookup(self, ip_str: str) -> str:
        """
        Look up real-world information for an IP address using the
        free ip-api.com JSON endpoint.  Returns a formatted summary
        or a clear error when the IP is invalid / unreachable.
        """
        # ── validate first ──────────────────────────────────
        if not self.validate_ip(ip_str):
            return (
                f"**{ip_str} is not a valid IPv4 address.**\n\n"
                "Each octet must be between 0 and 255.  "
                "For example, `10.123.55.288` is invalid because 288 > 255.\n"
                "Please double-check the IP and try again."
            )

        # ── classify private / reserved ────────────────────
        addr = ipaddress.IPv4Address(ip_str)
        if addr.is_private:
            return (
                f"**{ip_str}** is a **private (RFC 1918) address**.\n\n"
                "Private IP ranges:\n"
                "  - 10.0.0.0 – 10.255.255.255\n"
                "  - 172.16.0.0 – 172.31.255.255\n"
                "  - 192.168.0.0 – 192.168.255.255\n\n"
                "Private addresses are not routable on the public Internet. "
                "No geolocation or ownership data is available externally.\n"
                "To get details, you would need access to the internal "
                "network where this address is assigned."
            )
        if addr.is_reserved or addr.is_loopback or addr.is_link_local:
            label = (
                "loopback" if addr.is_loopback
                else "link-local" if addr.is_link_local
                else "reserved"
            )
            return (
                f"**{ip_str}** is a **{label} address** and has no public "
                "geolocation or ownership information."
            )

        # ── live lookup via ip-api.com (free, no key needed) ──
        api_url = f"http://ip-api.com/json/{ip_str}?fields=66846719"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    api_url,
                    headers={"User-Agent": "AgentHunter/2.1"},
                )
            if resp.status_code != 200:
                return f"IP lookup API returned HTTP {resp.status_code} for {ip_str}."

            data = resp.json()
            if data.get("status") != "success":
                return (
                    f"IP lookup failed for {ip_str}: "
                    f"{data.get('message', 'unknown error')}"
                )

            lines = [f"## IP Intelligence — {ip_str}", ""]
            field_map = [
                ("Country", "country"),
                ("Region", "regionName"),
                ("City", "city"),
                ("ZIP", "zip"),
                ("Latitude", "lat"),
                ("Longitude", "lon"),
                ("Timezone", "timezone"),
                ("ISP", "isp"),
                ("Organization", "org"),
                ("AS", "as"),
                ("Reverse DNS", "reverse"),
                ("Mobile", "mobile"),
                ("Proxy/VPN", "proxy"),
                ("Hosting", "hosting"),
            ]
            for label, key in field_map:
                val = data.get(key)
                if val is not None and val != "":
                    lines.append(f"  **{label}:** {val}")

            lines.append("")
            lines.append("*Source: ip-api.com (real-time lookup)*")
            return "\n".join(lines)

        except httpx.TimeoutException:
            return f"IP lookup timed out for {ip_str}. Try again later."
        except Exception as exc:
            return f"IP lookup error for {ip_str}: {exc}"
