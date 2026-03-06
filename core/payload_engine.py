"""Adaptive Payload Engine — learns what works and generates targeted payloads."""
from __future__ import annotations
import json
import os
import logging
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "payload_engine.db")


class AdaptivePayloadEngine:
    """Tracks payload success/failure rates per tech stack and WAF, then
       prioritizes payloads that have historically worked."""

    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS payload_stats (
                payload_hash  TEXT NOT NULL,
                payload       TEXT NOT NULL,
                vuln_type     TEXT NOT NULL,
                tech_stack    TEXT DEFAULT '',
                waf           TEXT DEFAULT '',
                success_count INTEGER DEFAULT 0,
                fail_count    INTEGER DEFAULT 0,
                blocked_count INTEGER DEFAULT 0,
                last_used     TEXT,
                PRIMARY KEY (payload_hash, vuln_type, tech_stack, waf)
            );

            CREATE TABLE IF NOT EXISTS effective_patterns (
                tech_stack    TEXT NOT NULL,
                vuln_type     TEXT NOT NULL,
                pattern       TEXT NOT NULL,
                success_rate  REAL DEFAULT 0.0,
                sample_size   INTEGER DEFAULT 0,
                PRIMARY KEY (tech_stack, vuln_type, pattern)
            );
        """)
        self._conn.commit()

    def record_result(self, payload: str, vuln_type: str,
                      success: bool, blocked: bool = False,
                      tech_stack: str = "", waf: str = ""):
        """Record whether a payload succeeded, failed, or was blocked."""
        import hashlib
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:12]

        self._conn.execute("""
            INSERT INTO payload_stats (payload_hash, payload, vuln_type, tech_stack, waf,
                                       success_count, fail_count, blocked_count, last_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(payload_hash, vuln_type, tech_stack, waf) DO UPDATE SET
                success_count = success_count + ?,
                fail_count = fail_count + ?,
                blocked_count = blocked_count + ?,
                last_used = ?
        """, (payload_hash, payload[:500], vuln_type, tech_stack, waf,
              1 if success else 0, 0 if success else 1, 1 if blocked else 0,
              datetime.utcnow().isoformat(),
              1 if success else 0, 0 if success else 1, 1 if blocked else 0,
              datetime.utcnow().isoformat()))
        self._conn.commit()

    def get_best_payloads(self, vuln_type: str, tech_stack: str = "",
                          waf: str = "", limit: int = 20) -> List[str]:
        """Get historically effective payloads, sorted by success rate."""
        rows = self._conn.execute("""
            SELECT payload, success_count, fail_count, blocked_count
            FROM payload_stats
            WHERE vuln_type = ?
              AND (tech_stack = ? OR tech_stack = '')
              AND (waf = ? OR waf = '')
              AND success_count > 0
            ORDER BY
                CAST(success_count AS REAL) / MAX(success_count + fail_count, 1) DESC,
                success_count DESC
            LIMIT ?
        """, (vuln_type, tech_stack, waf, limit)).fetchall()

        return [row["payload"] for row in rows]

    def get_blocked_payloads(self, waf: str = "", limit: int = 50) -> List[str]:
        """Get payloads known to be blocked by a specific WAF."""
        rows = self._conn.execute("""
            SELECT payload FROM payload_stats
            WHERE blocked_count > 0 AND (waf = ? OR ? = '')
            ORDER BY blocked_count DESC
            LIMIT ?
        """, (waf, waf, limit)).fetchall()

        return [row["payload"] for row in rows]

    def prioritize_payloads(self, payloads: List[str], vuln_type: str,
                            tech_stack: str = "", waf: str = "") -> List[str]:
        """Reorder payloads: proven ones first, known-blocked last."""
        import hashlib
        blocked = set(self.get_blocked_payloads(waf))
        best = set(self.get_best_payloads(vuln_type, tech_stack, waf))

        proven = [p for p in payloads if p in best]
        unknown = [p for p in payloads if p not in best and p not in blocked]
        avoid = [p for p in payloads if p in blocked]

        return proven + unknown + avoid

    def update_patterns(self, tech_stack: str, vuln_type: str):
        """Update effective patterns summary from raw stats."""
        rows = self._conn.execute("""
            SELECT payload, success_count, fail_count
            FROM payload_stats
            WHERE tech_stack = ? AND vuln_type = ? AND success_count > 0
        """, (tech_stack, vuln_type)).fetchall()

        if not rows:
            return

        # Extract common patterns from successful payloads
        patterns = {}
        for row in rows:
            payload = row["payload"]
            total = row["success_count"] + row["fail_count"]
            rate = row["success_count"] / max(total, 1)

            # Simple pattern extraction: first 20 chars
            pattern = payload[:20]
            if pattern not in patterns:
                patterns[pattern] = {"rate": rate, "count": 1}
            else:
                patterns[pattern]["rate"] = (patterns[pattern]["rate"] + rate) / 2
                patterns[pattern]["count"] += 1

        for pattern, stats in patterns.items():
            self._conn.execute("""
                INSERT INTO effective_patterns (tech_stack, vuln_type, pattern, success_rate, sample_size)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tech_stack, vuln_type, pattern) DO UPDATE SET
                    success_rate = ?, sample_size = ?
            """, (tech_stack, vuln_type, pattern, stats["rate"], stats["count"],
                  stats["rate"], stats["count"]))
        self._conn.commit()

    def stats(self) -> Dict:
        row = self._conn.execute("""
            SELECT COUNT(*) as total,
                   SUM(success_count) as successes,
                   SUM(blocked_count) as blocks
            FROM payload_stats
        """).fetchone()
        return {
            "total_payloads_tracked": row["total"],
            "total_successes": row["successes"] or 0,
            "total_blocks": row["blocks"] or 0,
        }

    def close(self):
        self._conn.close()
