"""
Web crawler / attack surface mapper.
Discovers URLs, parameters, forms, JS files, and API endpoints.
"""
from __future__ import annotations
import asyncio
import re
import logging
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from config.settings import MAX_CRAWL_DEPTH, MAX_URLS_PER_TARGET
from core.models import Target
from utils.http_client import HttpClient, ScopeViolationError

logger = logging.getLogger(__name__)

# Patterns to extract endpoints from JS files
JS_ENDPOINT_PATTERNS = [
    r'["\'](/[a-zA-Z0-9/_\-\.?=&%]+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'endpoint:\s*["\']([^"\']+)["\']',
    r'api[_\-]?url:\s*["\']([^"\']+)["\']',
]

SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)["\s]*[=:]["\s]*([a-zA-Z0-9\-_]{20,})', "API Key"),
    (r'(?i)(secret|password|passwd|token)["\s]*[=:]["\s]*([a-zA-Z0-9\-_@$!%*?&]{8,})', "Secret/Password"),
    (r'(?i)aws_?access_?key_?id["\s]*[=:]["\s]*([A-Z0-9]{20})', "AWS Access Key"),
    (r'(?i)aws_?secret["\s]*[=:]["\s]*([a-zA-Z0-9/+]{40})', "AWS Secret"),
    (r'(?i)(AKIA[A-Z0-9]{16})', "AWS Key Pattern"),
    (r'(?i)bearer\s+([a-zA-Z0-9\-_\.]{20,})', "Bearer Token"),
    (r'(?i)(ghp_[a-zA-Z0-9]{36})', "GitHub PAT"),
]


class Crawler:
    """Async breadth-first web crawler."""

    def __init__(self, client: HttpClient):
        self.client = client

    async def crawl(self, target: Target, depth: int = MAX_CRAWL_DEPTH) -> Target:
        """
        Crawl the target URL up to `depth` levels.
        Populates target.discovered_urls and target.discovered_params.
        Returns the enriched target.
        """
        visited: Set[str] = set()
        queue: List[tuple] = [(target.url, 0)]
        discovered_params: Dict[str, List[str]] = {}
        js_files: List[str] = []
        secrets_found: List[str] = []

        while queue and len(visited) < MAX_URLS_PER_TARGET:
            url, current_depth = queue.pop(0)
            if url in visited or current_depth > depth:
                continue
            if target.scope and not target.scope.is_in_scope(url):
                continue

            visited.add(url)
            logger.debug(f"Crawling: {url} (depth {current_depth})")

            try:
                resp, _ = await self.client.get(url)
                if resp is None:
                    continue

                # Store headers from first request
                if not target.headers:
                    target.headers = dict(resp.headers)

                content_type = resp.headers.get("content-type", "")

                if "javascript" in content_type or url.endswith(".js"):
                    js_files.append(url)
                    new_urls = self._extract_from_js(resp.text, url)
                    secrets = self._find_secrets(resp.text, url)
                    secrets_found.extend(secrets)
                    for new_url in new_urls:
                        if new_url not in visited:
                            queue.append((new_url, current_depth + 1))

                elif "html" in content_type:
                    new_urls, params = self._extract_from_html(resp.text, url)
                    for p_url, p_params in params.items():
                        discovered_params.setdefault(p_url, []).extend(p_params)
                    for new_url in new_urls:
                        if new_url not in visited:
                            queue.append((new_url, current_depth + 1))

                # Extract params from query string
                parsed = urlparse(url)
                if parsed.query:
                    qparams = list(parse_qs(parsed.query).keys())
                    if qparams:
                        discovered_params.setdefault(url, []).extend(qparams)

            except ScopeViolationError:
                continue
            except Exception as exc:
                logger.debug(f"Crawl error at {url}: {exc}")

        target.discovered_urls = list(visited)
        target.discovered_params = {
            k: list(set(v)) for k, v in discovered_params.items()
        }
        target.metadata["js_files"] = js_files
        target.metadata["secrets_in_js"] = secrets_found

        logger.info(
            f"Crawl complete: {len(visited)} URLs, "
            f"{len(discovered_params)} parameterised endpoints, "
            f"{len(js_files)} JS files"
        )
        return target

    # ──────────────────────────────────────────
    def _extract_from_html(self, html: str, base_url: str):
        """Extract links and form parameters from HTML."""
        urls: List[str] = []
        params: Dict[str, List[str]] = {}
        try:
            soup = BeautifulSoup(html, "html.parser")
            # Links
            for tag in soup.find_all(["a", "link"], href=True):
                href = tag.get("href", "")
                if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    full = urljoin(base_url, href)
                    urls.append(full)

            # Forms
            for form in soup.find_all("form"):
                action = form.get("action", base_url)
                form_url = urljoin(base_url, action)
                inputs = form.find_all(["input", "textarea", "select"])
                param_names = [
                    i.get("name") for i in inputs if i.get("name")
                ]
                if param_names:
                    params[form_url] = param_names
                    urls.append(form_url)

            # Script src
            for script in soup.find_all("script", src=True):
                src = script.get("src", "")
                if src:
                    urls.append(urljoin(base_url, src))

        except Exception as exc:
            logger.debug(f"HTML parse error: {exc}")
        return urls, params

    def _extract_from_js(self, js_content: str, base_url: str) -> List[str]:
        """Extract API endpoints from JS source."""
        urls: List[str] = []
        parsed_base = urlparse(base_url)
        netloc = parsed_base.netloc or parsed_base.hostname or ""
        base = f"{parsed_base.scheme}://{netloc}"
        for pattern in JS_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, js_content)
            for m in matches:
                path = m if isinstance(m, str) else m[0]
                if path.startswith("/"):
                    urls.append(base + path)
                elif path.startswith("http"):
                    urls.append(path)
        return list(set(urls))

    def _find_secrets(self, content: str, source_url: str) -> List[str]:
        """Detect hardcoded secrets in JS/HTML content."""
        found: List[str] = []
        for pattern, label in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                found.append(f"{label} found in {source_url}")
        return found
