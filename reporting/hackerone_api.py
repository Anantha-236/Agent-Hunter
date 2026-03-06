"""
HackerOne API Client — interact with the HackerOne platform programmatically.

Config-driven via config/ai_hunter_config.json → hackerone_api section.
Auth via H1_USERNAME + H1_API_TOKEN environment variables (Basic Auth).

Usage:
    client = HackerOneClient()
    if await client.is_authenticated():
        programs = await client.list_programs()
        await client.submit_report(report_data)
"""
from __future__ import annotations
import base64
import json
import logging
from typing import Any, Dict, List, Optional

import httpx

from config.settings import (
    H1_API_BASE, H1_USERNAME, H1_API_IDENTIFIER, H1_API_TOKEN, H1_ENDPOINTS,
    H1_REQUEST_HEADERS, H1_REPORT_TEMPLATE, H1_SEVERITY_CVSS,
    H1_ERROR_HANDLING, H1_AUTO_SUBMIT,
)
from core.models import Finding

logger = logging.getLogger(__name__)


class HackerOneClient:
    """
    Async client for the HackerOne API v1.

    Supports:
      - Authentication verification
      - Listing enrolled programs
      - Fetching program scope & policy
      - Submitting vulnerability reports
      - Retrieving report status
    """

    def __init__(self, username: str = None, api_token: str = None,
                 base_url: str = None):
        self.base_url = (base_url or H1_API_BASE).rstrip("/")
        # Use API Identifier for auth (falls back to H1_USERNAME for compat)
        self._username = username or H1_API_IDENTIFIER or H1_USERNAME
        self._api_token = api_token or H1_API_TOKEN
        self._headers = dict(H1_REQUEST_HEADERS)
        self._endpoints = dict(H1_ENDPOINTS)
        self._authenticated: Optional[bool] = None

    @property
    def _auth(self) -> Optional[httpx.BasicAuth]:
        if self._username and self._api_token:
            return httpx.BasicAuth(self._username, self._api_token)
        return None

    @property
    def is_configured(self) -> bool:
        return bool(self._username and self._api_token)

    # ── Authentication ────────────────────────────────────────

    async def is_authenticated(self) -> bool:
        """Verify H1 API credentials are valid."""
        if self._authenticated is not None:
            return self._authenticated
        if not self.is_configured:
            logger.debug("HackerOne API not configured (missing H1_USERNAME/H1_API_TOKEN)")
            self._authenticated = False
            return False
        try:
            resp = await self._get(self._endpoints.get("me", "/me"))
            self._authenticated = resp is not None
            if self._authenticated:
                logger.info("HackerOne API authentication successful")
            else:
                logger.warning("HackerOne API authentication failed")
        except Exception as exc:
            logger.warning(f"HackerOne auth check failed: {exc}")
            self._authenticated = False
        return self._authenticated

    # ── Programs ──────────────────────────────────────────────

    async def list_programs(self) -> List[Dict]:
        """List all programs the user is enrolled in."""
        data = await self._get(self._endpoints.get("programs_list", "/me/programs"))
        if data:
            return data.get("data", [])
        return []

    async def get_program(self, handle: str) -> Optional[Dict]:
        """Get program details."""
        endpoint = self._endpoints.get("program_detail", "/programs/{handle}")
        data = await self._get(endpoint.format(handle=handle))
        return data

    async def get_program_policy(self, handle: str) -> Optional[Dict]:
        """Get a program's policy."""
        endpoint = self._endpoints.get("program_policy", "/programs/{handle}/policy")
        data = await self._get(endpoint.format(handle=handle))
        return data

    async def get_scope(self, handle: str) -> List[Dict]:
        """Get a program's in-scope assets."""
        endpoint = self._endpoints.get(
            "in_scope_assets", "/programs/{handle}/structured_scopes"
        )
        data = await self._get(endpoint.format(handle=handle))
        if data:
            return data.get("data", [])
        return []

    # ── Reports ───────────────────────────────────────────────

    async def submit_report(self, report_data: Dict) -> Optional[Dict]:
        """Submit a vulnerability report to HackerOne."""
        endpoint = self._endpoints.get("submit_report", "/reports")
        data = await self._post(endpoint, report_data)
        return data

    async def get_report(self, report_id: str) -> Optional[Dict]:
        """Get a report by ID."""
        endpoint = self._endpoints.get("get_report", "/reports/{report_id}")
        data = await self._get(endpoint.format(report_id=report_id))
        return data

    async def list_my_reports(self) -> List[Dict]:
        """List the user's submitted reports."""
        data = await self._get(self._endpoints.get("list_my_reports", "/me/reports"))
        if data:
            return data.get("data", [])
        return []

    async def add_comment(self, report_id: str, message: str,
                          internal: bool = False) -> Optional[Dict]:
        """Add a comment to a report."""
        endpoint = self._endpoints.get(
            "add_comment", "/reports/{report_id}/activities"
        )
        body = {
            "data": {
                "type": "activity-comment",
                "attributes": {
                    "message": message,
                    "internal": internal,
                },
            }
        }
        data = await self._post(endpoint.format(report_id=report_id), body)
        return data

    # ── Report Builder ────────────────────────────────────────

    def build_report(self, finding: Finding, program_handle: str) -> Dict:
        """Build an H1 API report payload from a Finding."""
        template = json.loads(json.dumps(H1_REPORT_TEMPLATE)) if H1_REPORT_TEMPLATE else {
            "data": {
                "type": "report",
                "attributes": {}
            }
        }

        attrs = template.get("data", {}).get("attributes", {})
        attrs["team_handle"] = program_handle
        attrs["title"] = finding.title
        attrs["vulnerability_information"] = self._build_description(finding)
        attrs["severity_rating"] = finding.severity
        attrs["impact"] = self._build_impact(finding)
        attrs["proof_of_concept"] = self._build_poc(finding)

        if finding.cwe_id:
            cwe_num = finding.cwe_id.replace("CWE-", "")
            attrs["weakness_id"] = int(cwe_num) if cwe_num.isdigit() else None

        template["data"]["attributes"] = attrs
        return template

    def _build_description(self, finding: Finding) -> str:
        lines = [
            f"## Vulnerability Details",
            f"",
            f"**Type:** {finding.vuln_type.replace('_', ' ').title()}",
            f"**URL:** {finding.url}",
            f"**Parameter:** {finding.parameter}",
            f"**Method:** {finding.method}",
            f"",
            finding.description or f"The parameter `{finding.parameter}` is vulnerable to {finding.vuln_type.replace('_', ' ')}.",
            f"",
            f"**Payload:**",
            f"```",
            finding.payload,
            f"```",
            f"",
            f"**Evidence:**",
            f"```",
            (finding.evidence or "")[:500],
            f"```",
        ]
        return "\n".join(lines)

    def _build_impact(self, finding: Finding) -> str:
        return (
            f"This {finding.severity.upper()} severity vulnerability "
            f"at {finding.url} can be exploited by an attacker to "
            f"compromise the security of the application."
        )

    def _build_poc(self, finding: Finding) -> str:
        if finding.poc_steps:
            return "\n".join(
                f"{i}. {step}" for i, step in enumerate(finding.poc_steps, 1)
            )
        return (
            f"1. Navigate to {finding.url}\n"
            f"2. Inject payload: {finding.payload}\n"
            f"3. Observe the vulnerability in the response"
        )

    # ── Hacktivity ────────────────────────────────────────────

    async def get_hacktivity(self) -> List[Dict]:
        """Get public hacktivity feed."""
        data = await self._get(self._endpoints.get("hacktivity_public", "/hacktivity"))
        if data:
            return data.get("data", [])
        return []

    # ── HTTP Helpers ──────────────────────────────────────────

    async def _get(self, endpoint: str) -> Optional[Dict]:
        """Perform an authenticated GET request."""
        url = f"{self.base_url}{endpoint}"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers, auth=self._auth)
                return self._handle_response(resp)
        except Exception as exc:
            logger.warning(f"H1 API GET {endpoint} failed: {exc}")
            return None

    async def _post(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """Perform an authenticated POST request."""
        url = f"{self.base_url}{endpoint}"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    url, headers=self._headers, auth=self._auth, json=data
                )
                return self._handle_response(resp)
        except Exception as exc:
            logger.warning(f"H1 API POST {endpoint} failed: {exc}")
            return None

    def _handle_response(self, resp: httpx.Response) -> Optional[Dict]:
        """Handle HTTP response with config-driven error messages."""
        if 200 <= resp.status_code < 300:
            try:
                return resp.json()
            except Exception:
                return {"raw": resp.text}

        status_str = str(resp.status_code)
        error_msg = H1_ERROR_HANDLING.get(status_str, f"HTTP {resp.status_code}")
        logger.warning(f"H1 API error {resp.status_code}: {error_msg}")
        return None
