"""Scan Scope Profiles — save/load target configurations for reuse."""
from __future__ import annotations
import json
import os
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PROFILES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "profiles")


class ScopeProfile:
    """Save and load scan configurations for different BBP targets."""

    def __init__(self, name: str):
        self.name = name
        self.target_url: str = ""
        self.scope_domains: List[str] = []
        self.excluded_domains: List[str] = []
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.modules: List[str] = []
        self.proxy: str = ""
        self.auth: Dict[str, Any] = {}
        self.notes: str = ""
        self.platform: str = ""  # hackerone, bugcrowd, etc.
        self.policy_path: str = ""  # path to BBPPolicy / PreEngagement JSON
        self.policy_data: Optional[Dict[str, Any]] = None  # embedded policy

    def save(self) -> str:
        """Save profile to disk."""
        os.makedirs(PROFILES_DIR, exist_ok=True)
        path = os.path.join(PROFILES_DIR, f"{self.name}.json")
        data = {
            "name": self.name,
            "target_url": self.target_url,
            "scope_domains": self.scope_domains,
            "excluded_domains": self.excluded_domains,
            "cookies": self.cookies,
            "headers": self.headers,
            "modules": self.modules,
            "proxy": self.proxy,
            "auth": self.auth,
            "notes": self.notes,
            "platform": self.platform,
            "policy_path": self.policy_path,
            "policy_data": self.policy_data,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Profile saved: {path}")
        return path

    @classmethod
    def load(cls, name: str) -> Optional["ScopeProfile"]:
        """Load a profile from disk."""
        path = os.path.join(PROFILES_DIR, f"{name}.json")
        if not os.path.exists(path):
            logger.error(f"Profile not found: {path}")
            return None
        with open(path) as f:
            data = json.load(f)
        profile = cls(data["name"])
        profile.target_url = data.get("target_url", "")
        profile.scope_domains = data.get("scope_domains", [])
        profile.excluded_domains = data.get("excluded_domains", [])
        profile.cookies = data.get("cookies", {})
        profile.headers = data.get("headers", {})
        profile.modules = data.get("modules", [])
        profile.proxy = data.get("proxy", "")
        profile.auth = data.get("auth", {})
        profile.notes = data.get("notes", "")
        profile.platform = data.get("platform", "")
        profile.policy_path = data.get("policy_path", "")
        profile.policy_data = data.get("policy_data")
        return profile

    @staticmethod
    def list_profiles() -> List[str]:
        """List all saved profiles."""
        if not os.path.exists(PROFILES_DIR):
            return []
        return [f.replace(".json", "") for f in os.listdir(PROFILES_DIR) if f.endswith(".json")]

    @classmethod
    def delete(cls, name: str) -> bool:
        path = os.path.join(PROFILES_DIR, f"{name}.json")
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def to_cli_args(self) -> List[str]:
        """Convert profile to CLI arguments."""
        args = ["--target", self.target_url]
        if self.scope_domains:
            args += ["--scope"] + self.scope_domains
        if self.excluded_domains:
            args += ["--exclude"] + self.excluded_domains
        if self.modules:
            args += ["--modules"] + self.modules
        if self.proxy:
            args += ["--proxy", self.proxy]
        for k, v in self.cookies.items():
            args += ["--cookie", f"{k}={v}"]
        for k, v in self.headers.items():
            args += ["--header", f"{k}:{v}"]
        if self.policy_path:
            args += ["--policy", self.policy_path]
        return args

    def get_policy_data(self) -> Optional[Dict[str, Any]]:
        """
        Get policy data — from embedded data or from policy_path file.
        Returns the raw dict suitable for BBPPolicy.from_dict() or
        PreEngagementChecklist.from_dict().
        """
        if self.policy_data:
            return self.policy_data
        if self.policy_path and os.path.exists(self.policy_path):
            with open(self.policy_path) as f:
                return json.load(f)
        return None
