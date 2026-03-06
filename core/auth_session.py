"""Authenticated Scanning — session manager for scanning behind login walls."""
from __future__ import annotations
import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class AuthSession:
    """Manages authenticated sessions for deep scanning."""

    def __init__(self):
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.tokens: Dict[str, str] = {}  # JWT, CSRF, etc.
        self.authenticated = False
        self.auth_method: str = ""
        self.user_roles: List[str] = []

    async def login_form(self, client, login_url: str,
                         username: str, password: str,
                         username_field: str = "username",
                         password_field: str = "password") -> bool:
        """Authenticate via HTML login form."""
        try:
            # Get login page to extract CSRF token
            resp, _ = await client.get(login_url)
            if not resp:
                return False

            form_data = {username_field: username, password_field: password}

            # Extract CSRF token if present
            csrf = self._extract_csrf(resp.text)
            if csrf:
                form_data[csrf[0]] = csrf[1]
                self.tokens["csrf"] = csrf[1]

            # Submit login
            login_resp, _ = await client.post(login_url, data=form_data)
            if not login_resp:
                return False

            # Check if login succeeded
            if login_resp.status_code in (200, 302, 303):
                # Extract session cookies
                for cookie_header in [login_resp.headers.get("set-cookie", "")]:
                    if cookie_header:
                        parts = cookie_header.split(";")[0].split("=", 1)
                        if len(parts) == 2:
                            self.cookies[parts[0].strip()] = parts[1].strip()

                # Check for auth indicators in response
                body_lower = login_resp.text.lower()
                login_failed = any(kw in body_lower for kw in [
                    "invalid", "incorrect", "wrong password", "login failed",
                    "authentication failed", "bad credentials",
                ])

                if not login_failed:
                    self.authenticated = True
                    self.auth_method = "form"
                    logger.info(f"Login successful via form at {login_url}")
                    return True

            logger.warning(f"Login failed at {login_url}")
            return False

        except Exception as exc:
            logger.error(f"Login error: {exc}")
            return False

    async def login_api(self, client, api_url: str,
                        credentials: Dict[str, str],
                        token_path: str = "token") -> bool:
        """Authenticate via API (JSON body)."""
        try:
            resp, _ = await client.post(
                api_url, json=credentials,
                headers={"Content-Type": "application/json"},
            )
            if not resp or resp.status_code not in (200, 201):
                return False

            data = resp.json()
            token = self._extract_nested(data, token_path)
            if token:
                self.tokens["bearer"] = token
                self.headers["Authorization"] = f"Bearer {token}"
                self.authenticated = True
                self.auth_method = "api_bearer"
                logger.info(f"API login successful, got bearer token")
                return True

            return False
        except Exception as exc:
            logger.error(f"API login error: {exc}")
            return False

    def set_bearer_token(self, token: str):
        """Manually set a bearer token."""
        self.tokens["bearer"] = token
        self.headers["Authorization"] = f"Bearer {token}"
        self.authenticated = True
        self.auth_method = "manual_bearer"

    def set_cookies(self, cookies: Dict[str, str]):
        """Manually set session cookies."""
        self.cookies.update(cookies)
        self.authenticated = True
        self.auth_method = "manual_cookies"

    def set_api_key(self, key_name: str, key_value: str, location: str = "header"):
        """Set an API key for authentication."""
        self.tokens["api_key"] = key_value
        if location == "header":
            self.headers[key_name] = key_value
        self.authenticated = True
        self.auth_method = "api_key"

    def get_auth_headers(self) -> Dict[str, str]:
        """Get all auth-related headers."""
        return {**self.headers}

    def get_auth_cookies(self) -> Dict[str, str]:
        """Get all auth-related cookies."""
        return {**self.cookies}

    async def test_auth(self, client, protected_url: str) -> bool:
        """Test if current session is still authenticated."""
        try:
            resp, _ = await client.get(
                protected_url,
                headers=self.get_auth_headers(),
            )
            if resp and resp.status_code == 200:
                body_lower = resp.text.lower()
                if not any(kw in body_lower for kw in ["login", "sign in", "unauthorized"]):
                    return True
            return False
        except Exception:
            return False

    def _extract_csrf(self, html: str) -> Optional[tuple]:
        """Extract CSRF token from HTML form."""
        patterns = [
            r'name=["\']?(csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken|_csrf|_wpnonce|nonce)["\']?\s+value=["\']?([^"\'>\s]+)',
            r'value=["\']?([^"\'>\s]+)["\']?\s+name=["\']?(csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token)["\']?',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                groups = match.groups()
                return (groups[0], groups[1]) if not groups[0].startswith("csrf") else (groups[0], groups[1])
        return None

    def _extract_nested(self, data: dict, path: str) -> Optional[str]:
        """Extract nested value from dict using dot path."""
        keys = path.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return str(current) if current else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "method": self.auth_method,
            "cookies": self.cookies,
            "custom_headers": self.headers,
            "roles": self.user_roles,
        }
