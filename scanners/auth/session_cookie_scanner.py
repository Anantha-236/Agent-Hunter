"""Metadata-only cookie and session attribute analysis."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Iterable
from urllib.parse import urlparse

from core.base_scanner import BaseScanner
from core.models import EvidenceStatus, Finding, ScanState
from core.test_identities import secret_state_fingerprint


@dataclass(frozen=True)
class CookieObservation:
    name: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    same_site: str
    expiry_class: str
    value_fingerprint: str
    issues: tuple[str, ...]
    evidence_status: EvidenceStatus = EvidenceStatus.OBSERVED

    def to_dict(self):
        return {
            "name": self.name, "domain": self.domain, "path": self.path,
            "secure": self.secure, "http_only": self.http_only,
            "same_site": self.same_site, "expiry_class": self.expiry_class,
            "value_fingerprint": self.value_fingerprint,
            "issues": list(self.issues), "evidence_status": self.evidence_status.value,
        }


def parse_set_cookie_metadata(headers: Iterable[str], source_url: str) -> tuple[CookieObservation, ...]:
    host = (urlparse(source_url).hostname or "").lower()
    observations = []
    for header in headers:
        parts = [part.strip() for part in str(header).split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, value = parts[0].split("=", 1)
        attrs = {}
        flags = set()
        for part in parts[1:]:
            if "=" in part:
                key, attr_value = part.split("=", 1)
                attrs[key.lower()] = attr_value.strip()
            else:
                flags.add(part.lower())
        domain = attrs.get("domain", host).lstrip(".").lower()
        path = attrs.get("path", "/") or "/"
        secure = "secure" in flags
        http_only = "httponly" in flags
        same_site = attrs.get("samesite", "unspecified").lower()
        issues = []
        if not secure:
            issues.append("missing_secure")
        if not http_only:
            issues.append("missing_httponly")
        if same_site == "unspecified":
            issues.append("missing_samesite")
        lower_name = name.lower()
        if lower_name.startswith("__host-"):
            if not secure:
                issues.append("host_prefix_requires_secure")
            if "domain" in attrs:
                issues.append("host_prefix_forbids_domain")
            if path != "/":
                issues.append("host_prefix_requires_root_path")
        if lower_name.startswith("__secure-") and not secure:
            issues.append("secure_prefix_requires_secure")
        observations.append(CookieObservation(
            name=name[:256], domain=domain[:253], path=path[:512], secure=secure,
            http_only=http_only, same_site=same_site[:32],
            expiry_class=_expiry_class(attrs),
            value_fingerprint=secret_state_fingerprint({"cookie_value": value}),
            issues=tuple(dict.fromkeys(issues)),
        ))
    return tuple(observations)


class SessionCookieScanner(BaseScanner):
    name = "session_cookie_scanner"
    description = "Captures cookie scope/flag metadata without retaining values"
    tags = ["auth", "cookie", "session", "passive"]

    async def run(self, state: ScanState) -> list[Finding]:
        observations = []
        seen = set()
        for url in [state.target.url, *state.target.discovered_urls]:
            if url in seen or len(seen) >= 5:
                continue
            seen.add(url)
            if state.target.scope and not state.target.scope.is_in_scope(url):
                continue
            response, _ = await self.client.get(url)
            if response is None:
                continue
            raw_headers = []
            try:
                raw_headers = [value for key, value in response.headers.multi_items() if key.lower() == "set-cookie"]
            except Exception:
                value = response.headers.get("set-cookie", "")
                if value:
                    raw_headers = [value]
            observations.extend(parse_set_cookie_metadata(raw_headers, url))
        state.target.metadata["cookie_observations"] = [item.to_dict() for item in observations]
        findings = []
        for item in observations:
            if not item.issues:
                continue
            findings.append(self.make_finding(
                title=f"Cookie metadata observation: {item.name}",
                vuln_type="cookie_attribute_observation",
                severity="low",
                url=state.target.url,
                parameter=item.name,
                evidence=", ".join(item.issues),
                description="Cookie attributes differ from a recommended baseline; impact is not independently proven.",
                evidence_status=EvidenceStatus.OBSERVED,
                confirmed=False,
            ))
        return findings


def _expiry_class(attrs: dict[str, str]) -> str:
    if "max-age" in attrs:
        try:
            return "session" if int(attrs["max-age"]) <= 0 else "persistent"
        except ValueError:
            return "invalid"
    if "expires" in attrs:
        try:
            expires = parsedate_to_datetime(attrs["expires"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            return "expired" if expires <= datetime.now(UTC) else "persistent"
        except Exception:
            return "invalid"
    return "session"
