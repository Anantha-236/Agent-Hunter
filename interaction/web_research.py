"""Live web research helpers for Hunter chat and external bots."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx


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
