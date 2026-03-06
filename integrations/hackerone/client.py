"""
HackerOne API Client
Handles authentication, pagination, rate-limiting, and all key endpoints
for the Hacker (not organization) API.

Authentication: HTTP Basic Auth
  - Username: API Token Identifier  (from HackerOne settings)
  - Password: API Token Value        (the secret)

Base URL: https://api.hackerone.com/v1
"""
from __future__ import annotations
import logging
import os
import time
from typing import Any, Dict, Iterator, List, Optional

import httpx

logger = logging.getLogger(__name__)

H1_BASE_URL = "https://api.hackerone.com/v1"
H1_RATE_LIMIT_DELAY = 1.0          # seconds between requests (conservative)
H1_MAX_RETRIES      = 3
H1_PAGE_SIZE         = 25           # results per page


class HackerOneError(Exception):
    """Raised on non-2xx API responses."""
    def __init__(self, status: int, body: str):
        self.status = status
        self.body   = body
        super().__init__(f"HackerOne API error {status}: {body[:200]}")


class HackerOneClient:
    """
    Minimal sync HackerOne API client.

    Usage:
        client = HackerOneClient(
            api_identifier="your-token-identifier",
            api_token="your-secret-token"
        )

        # Test connection
        me = client.get_me()

        # Fetch programs you have access to
        programs = list(client.iter_programs())

        # Submit a report
        report_id = client.submit_report(
            team_handle="example",
            title="SQL Injection in /search",
            vulnerability_information="...",
            impact="...",
            severity_rating="high",
        )
    """

    def __init__(
        self,
        api_identifier: Optional[str] = None,
        api_token: Optional[str] = None,
    ):
        # Support env vars as fallback
        self.identifier = api_identifier or os.getenv("H1_API_IDENTIFIER", "")
        self.token      = api_token      or os.getenv("H1_API_TOKEN", "")

        if not self.identifier or not self.token:
            raise ValueError(
                "HackerOne API credentials missing. "
                "Pass api_identifier + api_token, or set "
                "H1_API_IDENTIFIER and H1_API_TOKEN env vars."
            )

        self._session = httpx.Client(
            base_url=H1_BASE_URL,
            auth=(self.identifier, self.token),
            headers={
                "Accept":       "application/json",
                "Content-Type": "application/json",
                "User-Agent":   "BugBountyAgent/1.0",
            },
            timeout=30,
            follow_redirects=True,
        )
        self._last_request_time: float = 0.0

    # ── Low-level helpers ──────────────────────────────────────────────────────

    def _rate_limit(self) -> None:
        """Respect H1 rate limits with a simple delay."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < H1_RATE_LIMIT_DELAY:
            time.sleep(H1_RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.monotonic()

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json: Optional[Dict] = None,
        retries: int = H1_MAX_RETRIES,
    ) -> Any:
        """Execute a request with retry + rate-limit logic. Returns parsed JSON."""
        for attempt in range(retries + 1):
            self._rate_limit()
            try:
                resp = self._session.request(
                    method=method,
                    url=path,
                    params=params,
                    json=json,
                )
                if resp.status_code == 429:          # rate limited
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    logger.warning(f"H1 rate limited — sleeping {retry_after}s")
                    time.sleep(retry_after)
                    continue
                if resp.status_code >= 400:
                    raise HackerOneError(resp.status_code, resp.text)
                return resp.json()
            except HackerOneError:
                raise
            except Exception as exc:
                logger.warning(f"H1 request failed (attempt {attempt+1}): {exc}")
                if attempt < retries:
                    time.sleep(2 ** attempt)
        raise HackerOneError(0, "Max retries exceeded")

    def _get(self, path: str, params: Optional[Dict] = None) -> Any:
        return self._request("GET", path, params=params)

    def _post(self, path: str, json: Dict) -> Any:
        return self._request("POST", path, json=json)

    def _paginate(self, path: str, params: Optional[Dict] = None) -> Iterator[Dict]:
        """Yield every item across all pages of a paginated endpoint."""
        params = params or {}
        params.setdefault("page[size]", H1_PAGE_SIZE)
        while path:
            data = self._get(path, params)
            for item in data.get("data", []):
                yield item
            # Follow next-page link if present
            links = data.get("links", {})
            next_url = links.get("next")
            if next_url:
                # next_url is a full URL — strip base for relative path
                path   = next_url.replace(H1_BASE_URL, "")
                params = {}          # already embedded in the URL
            else:
                path = None

    # ── Hacker Identity ───────────────────────────────────────────────────────

    def get_me(self) -> Dict:
        """Return the authenticated hacker profile. Use to test credentials."""
        return self._get("/hackers/me")

    def verify_credentials(self) -> bool:
        """Returns True if credentials are valid, False otherwise."""
        try:
            self.get_me()
            return True
        except HackerOneError as e:
            if e.status == 401:
                return False
            raise

    # ── Programs ──────────────────────────────────────────────────────────────

    def iter_programs(self, filters: Optional[Dict] = None) -> Iterator[Dict]:
        """
        Iterate over all bug bounty programs.
        filters: optional dict, e.g. {"offers_bounties": True}
        """
        params = {}
        if filters:
            for k, v in filters.items():
                params[f"filter[{k}]"] = str(v).lower()
        yield from self._paginate("/hackers/programs", params)

    def get_program(self, handle: str) -> Dict:
        """Get full details for a specific program by handle."""
        return self._get(f"/hackers/programs/{handle}")

    def get_program_scope(self, handle: str) -> List[Dict]:
        """Return all structured scopes (in-scope and out-of-scope assets)."""
        data = self._get(f"/hackers/programs/{handle}/structured_scopes")
        return data.get("data", [])

    # ── Reports ───────────────────────────────────────────────────────────────

    def iter_my_reports(
        self,
        state: Optional[str] = None,
        program: Optional[str] = None,
    ) -> Iterator[Dict]:
        """
        Iterate over all reports submitted by you.
        state: new | pending-program-review | triaged | needs-more-info |
               resolved | not-applicable | informative | duplicate | spam | retesting
        """
        params = {}
        if state:   params["filter[state][]"]   = state
        if program: params["filter[program][]"] = program
        yield from self._paginate("/hackers/me/reports", params)

    def get_report(self, report_id: int) -> Dict:
        """Fetch full report details by ID."""
        return self._get(f"/hackers/reports/{report_id}")

    def submit_report(
        self,
        team_handle: str,
        title: str,
        vulnerability_information: str,
        impact: str,
        severity_rating: str = "medium",   # none|low|medium|high|critical
        structured_scope_id: Optional[int] = None,
        weakness_id: Optional[int] = None,
        attachments: Optional[List[str]] = None,
    ) -> Dict:
        """
        Submit a vulnerability report to a HackerOne program.
        Returns the created report object.

        severity_rating: "none" | "low" | "medium" | "high" | "critical"
        structured_scope_id: get from get_program_scope()
        weakness_id: CWE-based weakness — see /weaknesses endpoint
        """
        attributes: Dict[str, Any] = {
            "team_handle":               team_handle,
            "title":                     title,
            "vulnerability_information": vulnerability_information,
            "impact":                    impact,
            "severity_rating":           severity_rating,
        }
        if structured_scope_id:
            attributes["structured_scope_id"] = structured_scope_id
        if weakness_id:
            attributes["weakness_id"] = weakness_id

        payload = {"data": {"type": "report", "attributes": attributes}}
        return self._post("/hackers/reports", json=payload)

    def add_comment(self, report_id: int, message: str, internal: bool = False) -> Dict:
        """Add a comment to an existing report."""
        payload = {
            "data": {
                "type": "activity-comment",
                "attributes": {"message": message, "internal": internal},
            }
        }
        return self._post(f"/hackers/reports/{report_id}/activities", json=payload)

    # ── Weakness / CWE lookup ─────────────────────────────────────────────────

    def iter_weaknesses(self) -> Iterator[Dict]:
        """Iterate over all supported weaknesses (CWE mappings)."""
        yield from self._paginate("/weaknesses")

    def find_weakness_id(self, cwe_id: str) -> Optional[int]:
        """
        Find the HackerOne weakness ID for a given CWE string (e.g. "CWE-89").
        Returns None if not found.
        """
        cwe_num = cwe_id.replace("CWE-", "").strip()
        for w in self.iter_weaknesses():
            attrs = w.get("attributes", {})
            if str(attrs.get("external_id", "")).endswith(cwe_num):
                return int(w["id"])
        return None

    # ── Hacktivity ────────────────────────────────────────────────────────────

    def iter_hacktivity(self, query: Optional[str] = None) -> Iterator[Dict]:
        """
        Browse public disclosed reports (hacktivity).
        query: Apache Lucene syntax, e.g. "severity_rating:critical AND disclosed_at:>=01-01-2024"
        """
        params = {}
        if query:
            params["queryString"] = query
        yield from self._paginate("/hackers/hacktivity", params)

    def close(self) -> None:
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
