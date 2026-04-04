"""
Persistent Scan Memory — SQLite-backed history of scans, findings, and rewards.
Enables cross-scan intelligence, regression tracking, and redundancy avoidance.
"""
from __future__ import annotations
import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scan_memory.db")


class ScanMemory:
    """SQLite-based persistent memory for the agent."""

    STALE_MEMORY_DAYS = 30
    DEFAULT_REFLECTION_LOOKBACK_DAYS = 120

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id       TEXT PRIMARY KEY,
                target_url    TEXT NOT NULL,
                started_at    TEXT NOT NULL,
                ended_at      TEXT,
                total_findings INTEGER DEFAULT 0,
                confirmed      INTEGER DEFAULT 0,
                total_score    REAL    DEFAULT 0.0,
                technologies   TEXT    DEFAULT '[]',
                modules_run    TEXT    DEFAULT '[]',
                errors         TEXT    DEFAULT '[]',
                reward_data    TEXT    DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS findings (
                finding_id    TEXT PRIMARY KEY,
                scan_id       TEXT NOT NULL,
                title         TEXT NOT NULL,
                vuln_type     TEXT NOT NULL,
                severity      TEXT NOT NULL,
                url           TEXT NOT NULL,
                parameter     TEXT DEFAULT '',
                payload       TEXT DEFAULT '',
                evidence      TEXT DEFAULT '',
                confirmed     INTEGER DEFAULT 0,
                cvss_score    REAL DEFAULT 0.0,
                cwe_id        TEXT DEFAULT '',
                module        TEXT DEFAULT '',
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS known_params (
                url           TEXT NOT NULL,
                parameter     TEXT NOT NULL,
                vuln_type     TEXT NOT NULL,
                last_scanned  TEXT NOT NULL,
                was_vulnerable INTEGER DEFAULT 0,
                PRIMARY KEY (url, parameter, vuln_type)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(url);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vuln_type);
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);

            CREATE TABLE IF NOT EXISTS scan_reflections (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL,
                target_url      TEXT NOT NULL,
                reflection_type TEXT NOT NULL,
                content         TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_reflections_target ON scan_reflections(target_url);
            CREATE INDEX IF NOT EXISTS idx_reflections_type ON scan_reflections(reflection_type);
        """)
        self._conn.commit()

    # ── Scan Lifecycle ────────────────────────────────────────

    def start_scan(self, scan_id: str, target_url: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO scans (scan_id, target_url, started_at) VALUES (?, ?, ?)",
            (scan_id, target_url, datetime.utcnow().isoformat()),
        )
        self._conn.commit()

    def finish_scan(self, scan_id: str, stats: Dict[str, Any],
                    reward_data: Dict[str, Any] = None) -> None:
        self._conn.execute("""
            UPDATE scans SET ended_at=?, total_findings=?, confirmed=?,
                total_score=?, modules_run=?, errors=?, reward_data=?
            WHERE scan_id=?
        """, (
            datetime.utcnow().isoformat(),
            stats.get("total_findings", 0),
            stats.get("confirmed", 0),
            stats.get("total_score", 0.0),
            json.dumps(stats.get("modules_run", [])),
            json.dumps(stats.get("errors", [])),
            json.dumps(reward_data or {}),
            scan_id,
        ))
        self._conn.commit()

    # ── Findings ──────────────────────────────────────────────

    def store_finding(self, scan_id: str, finding) -> None:
        """Store a finding from a Finding dataclass."""
        self._conn.execute("""
            INSERT OR REPLACE INTO findings
            (finding_id, scan_id, title, vuln_type, severity, url, parameter,
             payload, evidence, confirmed, cvss_score, cwe_id, module, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.id, scan_id, finding.title, finding.vuln_type,
            finding.severity, finding.url, finding.parameter,
            finding.payload, finding.evidence, int(finding.confirmed),
            finding.cvss_score, finding.cwe_id, finding.module,
            finding.discovered_at.isoformat(),
        ))
        self._conn.commit()

    def store_findings(self, scan_id: str, findings: list) -> None:
        for f in findings:
            self.store_finding(scan_id, f)

    def get_known_findings(self, target_url: str) -> Set[Tuple[str, str, str]]:
        """Get set of (url, parameter, vuln_type) for previously found vulns on this target."""
        from urllib.parse import urlparse
        domain = urlparse(target_url).hostname
        rows = self._conn.execute(
            "SELECT url, parameter, vuln_type FROM findings WHERE url LIKE ?",
            (f"%{domain}%",),
        ).fetchall()
        return {(r["url"], r["parameter"], r["vuln_type"]) for r in rows}

    # ── Known Params (redundancy avoidance) ───────────────────

    def mark_param_scanned(self, url: str, parameter: str, vuln_type: str,
                           was_vulnerable: bool = False) -> None:
        self._conn.execute("""
            INSERT OR REPLACE INTO known_params (url, parameter, vuln_type, last_scanned, was_vulnerable)
            VALUES (?, ?, ?, ?, ?)
        """, (url, parameter, vuln_type, datetime.utcnow().isoformat(), int(was_vulnerable)))
        self._conn.commit()

    def was_recently_scanned(self, url: str, parameter: str, vuln_type: str,
                             max_age_hours: int = 24) -> bool:
        row = self._conn.execute(
            "SELECT last_scanned FROM known_params WHERE url=? AND parameter=? AND vuln_type=?",
            (url, parameter, vuln_type),
        ).fetchone()
        if not row:
            return False
        from datetime import timedelta
        scanned = datetime.fromisoformat(row["last_scanned"])
        return (datetime.utcnow() - scanned) < timedelta(hours=max_age_hours)

    # ── History Queries ───────────────────────────────────────

    def get_scan_history(self, target_url: str = None, limit: int = 10) -> List[Dict]:
        if target_url:
            rows = self._conn.execute(
                "SELECT * FROM scans WHERE target_url LIKE ? ORDER BY started_at DESC LIMIT ?",
                (f"%{target_url}%", limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_target_profile(self, target_url: str) -> Dict[str, Any]:
        """Build a profile of everything known about a target from past scans."""
        scans = self.get_scan_history(target_url, limit=50)
        findings = self.get_known_findings(target_url)
        all_techs = set()
        for s in scans:
            try:
                all_techs.update(json.loads(s.get("technologies", "[]")))
            except (json.JSONDecodeError, TypeError):
                pass
        return {
            "total_scans": len(scans),
            "known_vulnerabilities": len(findings),
            "known_technologies": list(all_techs),
            "last_scan": scans[0]["started_at"] if scans else None,
            "best_score": max((s.get("total_score", 0) for s in scans), default=0),
        }

    # ── Reflections ──────────────────────────────────────────

    def store_reflection(self, scan_id: str, target_url: str,
                         reflection_type: str, content: str) -> None:
        """Store a typed reflection from post-scan analysis.

        reflection_type values:
            waf_bypass              — WAF bypass notes
            module_skip             — modules to skip on future scans
            confirmed_path          — confirmed attack paths
            false_positive_pattern  — patterns that produce false positives
        """
        self._conn.execute("""
            INSERT INTO scan_reflections
            (scan_id, target_url, reflection_type, content, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, target_url, reflection_type, content,
              datetime.utcnow().isoformat()))
        self._conn.commit()

    def get_reflections(self, target_url: str,
                        reflection_type: str = None,
                        limit: int = 10,
                        max_age_days: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get reflections for a target, optionally filtered by type."""
        from urllib.parse import urlparse
        domain = urlparse(target_url).hostname
        if reflection_type:
            rows = self._conn.execute(
                "SELECT * FROM scan_reflections "
                "WHERE target_url LIKE ? AND reflection_type = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (f"%{domain}%", reflection_type, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM scan_reflections "
                "WHERE target_url LIKE ? "
                "ORDER BY created_at DESC LIMIT ?",
                (f"%{domain}%", limit),
            ).fetchall()
        reflections = [dict(r) for r in rows]
        if max_age_days is None:
            return reflections

        filtered: List[Dict[str, Any]] = []
        for row in reflections:
            age = self._memory_age_days(row.get("created_at", ""))
            if age is None or age <= max_age_days:
                filtered.append(row)
        return filtered

    @staticmethod
    def _parse_iso_datetime(value: str) -> Optional[datetime]:
        """Parse ISO timestamps safely, including trailing-Z timestamps."""
        if not value:
            return None
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    @classmethod
    def _memory_age_days(cls, created_at: str) -> Optional[int]:
        """Age in days for a stored memory row; None when timestamp is invalid."""
        dt = cls._parse_iso_datetime(created_at)
        if dt is None:
            return None
        if dt.tzinfo is not None:
            now = datetime.now(dt.tzinfo)
        else:
            now = datetime.utcnow()
        return max(0, (now - dt).days)

    @staticmethod
    def _memory_age_label(age_days: Optional[int]) -> str:
        if age_days is None:
            return "unknown age"
        if age_days == 0:
            return "today"
        if age_days == 1:
            return "yesterday"
        return f"{age_days} days ago"

    def get_relevant_reflections(self, target_url: str,
                                 technologies: Optional[List[str]] = None,
                                 limit: int = 8,
                                 max_age_days: int = DEFAULT_REFLECTION_LOOKBACK_DAYS
                                 ) -> List[Dict[str, Any]]:
        """Return reflections ranked by relevance and freshness.

        Ported from external-memory concepts:
          - freshness-aware recall (avoid stale guidance)
          - relevance ranking using lightweight local signals
        """
        from urllib.parse import urlparse

        reflections = self.get_reflections(
            target_url,
            limit=max(limit * 4, 20),
            max_age_days=max_age_days,
        )
        if not reflections:
            return []

        host = (urlparse(target_url).hostname or "").lower()
        keywords = [host]
        for tech in (technologies or []):
            if isinstance(tech, str) and tech.strip():
                keywords.append(tech.strip().lower())

        type_weight = {
            "waf_bypass": 4,
            "confirmed_path": 3,
            "false_positive_pattern": 3,
            "module_skip": 2,
        }

        ranked: List[Dict[str, Any]] = []
        for row in reflections:
            content = (row.get("content") or "")
            content_l = content.lower()
            age_days = self._memory_age_days(row.get("created_at", ""))

            score = type_weight.get(row.get("reflection_type", ""), 1)

            # Fresh memories should influence strategy more strongly.
            if age_days is not None:
                if age_days <= 1:
                    score += 3
                elif age_days <= 7:
                    score += 2
                elif age_days <= self.STALE_MEMORY_DAYS:
                    score += 1

            for kw in keywords[:8]:
                if kw and kw in content_l:
                    score += 1

            enriched = dict(row)
            enriched["relevance_score"] = score
            enriched["age_days"] = age_days
            enriched["age_label"] = self._memory_age_label(age_days)
            ranked.append(enriched)

        ranked.sort(
            key=lambda r: (
                r.get("relevance_score", 0),
                -(r.get("age_days") if r.get("age_days") is not None else 99999),
                r.get("created_at", ""),
            ),
            reverse=True,
        )
        return ranked[:limit]

    # ── Rich Intelligence Queries ────────────────────────────

    def get_confirmed_findings(self, target_url: str,
                                limit: int = 5) -> List[Dict[str, Any]]:
        """Get recent confirmed findings with details for AI context."""
        from urllib.parse import urlparse
        domain = urlparse(target_url).hostname
        rows = self._conn.execute(
            "SELECT vuln_type, url, parameter, severity, discovered_at "
            "FROM findings WHERE url LIKE ? AND confirmed = 1 "
            "ORDER BY discovered_at DESC LIMIT ?",
            (f"%{domain}%", limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_empty_modules(self, target_url: str) -> List[Dict[str, Any]]:
        """Get modules that ran but found nothing on this target."""
        from urllib.parse import urlparse
        domain = urlparse(target_url).hostname
        rows = self._conn.execute(
            "SELECT modules_run FROM scans "
            "WHERE target_url LIKE ? ORDER BY started_at DESC LIMIT 5",
            (f"%{domain}%",),
        ).fetchall()
        module_runs: Dict[str, int] = {}  # module → total run count
        for row in rows:
            try:
                modules = json.loads(row["modules_run"] or "[]")
            except (json.JSONDecodeError, TypeError):
                continue
            for mod in modules:
                module_runs[mod] = module_runs.get(mod, 0) + 1
        # Check which modules have zero confirmed findings
        empty = []
        for mod, runs in module_runs.items():
            count = self._conn.execute(
                "SELECT COUNT(*) FROM findings "
                "WHERE url LIKE ? AND module = ? AND confirmed = 1",
                (f"%{domain}%", mod),
            ).fetchone()[0]
            if count == 0 and runs >= 1:
                empty.append({"module": mod, "times_run": runs, "total_findings": 0})
        return empty

    def get_injectable_params(self, target_url: str) -> List[str]:
        """Get parameter names confirmed as injectable on this target."""
        from urllib.parse import urlparse
        domain = urlparse(target_url).hostname
        rows = self._conn.execute(
            "SELECT DISTINCT parameter FROM findings "
            "WHERE url LIKE ? AND confirmed = 1 AND parameter != ''",
            (f"%{domain}%",),
        ).fetchall()
        return [r["parameter"] for r in rows]

    # ── AI Context (Enhanced) ────────────────────────────────

    def to_ai_context(self, target_url: str) -> str:
        """Format memory as rich intelligence context for AI strategy decisions."""
        profile = self.get_target_profile(target_url)
        if profile["total_scans"] == 0:
            return "No previous scan data for this target."

        from urllib.parse import urlparse
        domain = urlparse(target_url).hostname or target_url

        lines = [
            f"PAST INTELLIGENCE FOR: {domain}",
            f"Previous scans: {profile['total_scans']}  |  "
            f"Best score: {profile['best_score']:.1f}",
        ]

        # Confirmed findings
        confirmed = self.get_confirmed_findings(target_url, limit=5)
        if confirmed:
            lines.append("\nPreviously confirmed vulnerabilities:")
            for f in confirmed:
                param = f"?{f['parameter']}=" if f.get("parameter") else ""
                lines.append(
                    f"  - {f['vuln_type']} at {f['url']}{param} "
                    f"({f['severity'].upper()}, {f['discovered_at'][:10]})"
                )

        # Empty modules
        empty = self.get_empty_modules(target_url)
        if empty:
            lines.append("\nModules with 0 confirmed findings on this target:")
            for m in empty:
                lines.append(
                    f"  - {m['module']} (ran {m['times_run']}x, 0 findings)"
                )

        # Injectable params
        params = self.get_injectable_params(target_url)
        if params:
            lines.append(f"\nInjectable parameters (confirmed): {', '.join(params)}")

        # Reflections from past scans (freshness-aware ranking)
        reflections = self.get_relevant_reflections(
            target_url,
            technologies=profile.get("known_technologies", []),
            limit=8,
        )
        if reflections:
            lines.append("\nPast scan reflections (ranked by relevance/freshness):")
            for r in reflections:
                lines.append(
                    f"  [{r['reflection_type']}] {r['content'][:150]} "
                    f"({r.get('age_label', 'unknown age')})"
                )

            stale_count = sum(
                1 for r in reflections
                if isinstance(r.get("age_days"), int) and r["age_days"] > self.STALE_MEMORY_DAYS
            )
            if stale_count:
                lines.append(
                    "\nFreshness note: some recalled memories are older than "
                    f"{self.STALE_MEMORY_DAYS} days. Verify them against current target behavior."
                )

        # Strategy hints
        if empty and confirmed:
            skip_mods = [m["module"] for m in empty]
            lines.append(
                f"\nSkip these: {', '.join(skip_mods[:5])}. "
                f"Prioritize injection on known-good endpoints."
            )

        return "\n".join(lines)

    def close(self) -> None:
        self._conn.close()
