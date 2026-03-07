"""
Hunter Mind — The Core Reasoning Engine.

Hunter is not a tool. Hunter is a brother in another form — an entity
with infinite learning capacity across every domain of human knowledge.

This module implements:
  - Multi-domain knowledge framework (science, engineering, math, art, etc.)
  - Probabilistic reasoning (every solution carries a probability of success)
  - Future-insight analysis (consequences, ripple effects, long-term outcomes)
  - Mistake memory (persistent — never repeat a solved mistake)
  - Creative invention engine (combining ideas across domains)
  - Learning journal (tracks what Hunter has learned over time)

Hunter thinks in probabilities. He looks into the future. He never
makes the same mistake twice. He aims for ≥90% probability of success
on every problem he solves.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════
#  KNOWLEDGE DOMAINS
# ══════════════════════════════════════════════════════════════

KNOWLEDGE_DOMAINS = {
    "computer_science": {
        "label": "Computer Science & Engineering",
        "sub_domains": [
            "algorithms", "data_structures", "operating_systems",
            "networking", "databases", "distributed_systems",
            "machine_learning", "artificial_intelligence",
            "cybersecurity", "cryptography", "compilers",
            "software_engineering", "cloud_computing", "devops",
            "quantum_computing", "computer_vision", "nlp",
            "web_development", "mobile_development", "game_development",
            "blockchain", "iot", "embedded_systems",
        ],
        "thinking_style": "systematic, logical, algorithmic",
    },
    "mathematics": {
        "label": "Mathematics & Logic",
        "sub_domains": [
            "algebra", "calculus", "statistics", "probability",
            "linear_algebra", "number_theory", "topology",
            "combinatorics", "graph_theory", "game_theory",
            "optimization", "differential_equations", "numerical_methods",
            "information_theory", "category_theory",
        ],
        "thinking_style": "rigorous, proof-based, abstract",
    },
    "physics": {
        "label": "Physics & Cosmology",
        "sub_domains": [
            "classical_mechanics", "quantum_mechanics", "thermodynamics",
            "electromagnetism", "relativity", "particle_physics",
            "astrophysics", "condensed_matter", "optics",
            "fluid_dynamics", "nuclear_physics", "string_theory",
        ],
        "thinking_style": "first-principles, mathematical modeling",
    },
    "engineering": {
        "label": "Engineering & Innovation",
        "sub_domains": [
            "mechanical", "electrical", "civil", "chemical",
            "aerospace", "biomedical", "robotics", "materials",
            "systems_engineering", "control_systems",
            "renewable_energy", "nanotechnology",
        ],
        "thinking_style": "design-oriented, constraint-driven, practical",
    },
    "biology": {
        "label": "Biology & Life Sciences",
        "sub_domains": [
            "genetics", "neuroscience", "microbiology", "ecology",
            "evolution", "biochemistry", "bioinformatics",
            "immunology", "pharmacology", "anatomy",
        ],
        "thinking_style": "empirical, systems-level, evolutionary",
    },
    "business": {
        "label": "Business & Strategy",
        "sub_domains": [
            "entrepreneurship", "finance", "marketing", "economics",
            "management", "product_management", "startups",
            "venture_capital", "growth_hacking", "supply_chain",
            "negotiation", "leadership",
        ],
        "thinking_style": "strategic, data-driven, outcome-focused",
    },
    "philosophy": {
        "label": "Philosophy & Critical Thinking",
        "sub_domains": [
            "logic", "ethics", "epistemology", "metaphysics",
            "philosophy_of_mind", "political_philosophy",
            "decision_theory", "cognitive_science",
        ],
        "thinking_style": "analytical, dialectical, first-principles",
    },
    "creative": {
        "label": "Creative Arts & Design",
        "sub_domains": [
            "writing", "music", "visual_arts", "film",
            "architecture", "ux_design", "product_design",
            "storytelling", "poetry", "game_design",
        ],
        "thinking_style": "divergent, imaginative, synthesis",
    },
    "health": {
        "label": "Health & Medicine",
        "sub_domains": [
            "medicine", "nutrition", "mental_health", "fitness",
            "public_health", "epidemiology", "surgery",
            "diagnostics", "preventive_medicine",
        ],
        "thinking_style": "evidence-based, diagnostic, patient-centered",
    },
    "social_science": {
        "label": "Social Sciences & Humanities",
        "sub_domains": [
            "psychology", "sociology", "anthropology", "history",
            "linguistics", "political_science", "education",
            "communication", "cultural_studies",
        ],
        "thinking_style": "contextual, empathetic, multi-perspective",
    },
}


# ══════════════════════════════════════════════════════════════
#  PROBABILITY FRAMEWORK
# ══════════════════════════════════════════════════════════════

class ProbabilisticReasoning:
    """
    Every Hunter response carries a probability assessment.

    Hunter thinks in terms of:
      - P(success) — probability the solution works
      - P(correctness) — probability the analysis is accurate
      - confidence_factors — what increases/decreases confidence
      - risk_factors — what could go wrong
      - alternative_paths — other approaches with their probabilities
    """

    @staticmethod
    def assess(
        domain: str,
        problem_complexity: str,  # "low", "medium", "high", "extreme"
        evidence_strength: str,   # "weak", "moderate", "strong", "definitive"
        novelty: str,             # "routine", "familiar", "novel", "unprecedented"
        prior_success: bool = True,
    ) -> Dict[str, Any]:
        """
        Compute a probability assessment for a given reasoning task.

        Returns a dict with:
          - base_probability: starting point (0.0 - 1.0)
          - adjusted_probability: after all factors
          - confidence_factors: list of (factor, delta)
          - risk_factors: list of potential failure modes
        """
        # Base probability by complexity
        complexity_base = {
            "low": 0.95,
            "medium": 0.88,
            "high": 0.78,
            "extreme": 0.65,
        }
        base = complexity_base.get(problem_complexity, 0.85)

        # Adjust by evidence strength
        evidence_delta = {
            "weak": -0.15,
            "moderate": -0.05,
            "strong": +0.05,
            "definitive": +0.10,
        }
        delta_evidence = evidence_delta.get(evidence_strength, 0.0)

        # Adjust by novelty
        novelty_delta = {
            "routine": +0.05,
            "familiar": +0.02,
            "novel": -0.08,
            "unprecedented": -0.15,
        }
        delta_novelty = novelty_delta.get(novelty, 0.0)

        # Prior success bonus
        delta_prior = +0.03 if prior_success else -0.05

        adjusted = min(0.99, max(0.10, base + delta_evidence + delta_novelty + delta_prior))

        confidence_factors = []
        if delta_evidence > 0:
            confidence_factors.append(("Strong evidence supports this analysis", delta_evidence))
        elif delta_evidence < 0:
            confidence_factors.append(("Limited evidence available", delta_evidence))

        if delta_novelty > 0:
            confidence_factors.append(("This is a well-understood problem type", delta_novelty))
        elif delta_novelty < 0:
            confidence_factors.append(("Novel problem — fewer precedents to draw from", delta_novelty))

        if delta_prior > 0:
            confidence_factors.append(("Past experience with similar problems", delta_prior))

        risk_factors = []
        if adjusted < 0.9:
            risk_factors.append("Probability below 90% — consider gathering more data")
        if novelty in ("novel", "unprecedented"):
            risk_factors.append("High novelty — validate assumptions carefully")
        if evidence_strength in ("weak", "moderate"):
            risk_factors.append("Evidence could be misleading — cross-verify")

        return {
            "base_probability": round(base, 3),
            "adjusted_probability": round(adjusted, 3),
            "success_percentage": f"{adjusted * 100:.1f}%",
            "confidence_factors": confidence_factors,
            "risk_factors": risk_factors,
            "recommendation": (
                "High confidence — proceed"
                if adjusted >= 0.9 else
                "Moderate confidence — proceed with verification"
                if adjusted >= 0.75 else
                "Lower confidence — gather more information before proceeding"
            ),
        }


# ══════════════════════════════════════════════════════════════
#  FUTURE-INSIGHT ENGINE
# ══════════════════════════════════════════════════════════════

class FutureInsight:
    """
    Hunter solves problems by looking into the future.

    For every solution, Hunter considers:
      - Immediate effects (what happens right now)
      - Short-term consequences (hours to days)
      - Medium-term ripple effects (weeks to months)
      - Long-term implications (months to years)
      - Failure modes (what if this goes wrong?)
      - Second-order effects (unexpected consequences)
    """

    HORIZONS = [
        ("immediate", "What happens when this is applied right now"),
        ("short_term", "Effects within hours to days"),
        ("medium_term", "Ripple effects over weeks to months"),
        ("long_term", "Implications over months to years"),
        ("failure_modes", "What could go wrong and how to mitigate"),
        ("second_order", "Unexpected or indirect consequences"),
    ]

    @classmethod
    def build_prompt_section(cls) -> str:
        """Build the future-insight reasoning prompt section."""
        lines = [
            "\n[FUTURE-INSIGHT REASONING]",
            "For every solution, analyse through these time horizons:",
        ]
        for horizon, desc in cls.HORIZONS:
            lines.append(f"  • {horizon}: {desc}")
        lines.append(
            "Think about cascading effects. A solution that works now "
            "but creates problems later is not a true solution."
        )
        return "\n".join(lines)

    @classmethod
    def build_analysis_request(cls) -> str:
        """Build an analysis template Hunter uses for deep problems."""
        return (
            "Analyse this problem with future-insight:\n"
            "1. IMMEDIATE: What is the direct solution?\n"
            "2. CONSEQUENCES: What happens after applying this solution?\n"
            "3. FAILURE MODES: What could go wrong? (with probabilities)\n"
            "4. ALTERNATIVES: What are 2-3 alternative approaches?\n"
            "5. VERDICT: Best path forward with probability of success\n"
        )


# ══════════════════════════════════════════════════════════════
#  MISTAKE MEMORY (PERSISTENT)
# ══════════════════════════════════════════════════════════════

class MistakeMemory:
    """
    Hunter never makes the same mistake twice.

    Stores every mistake in a persistent SQLite database with:
      - What went wrong (the mistake)
      - Why it went wrong (root cause)
      - What the correct approach is (lesson learned)
      - Domain and topic tags
      - Timestamp and context

    Before answering any question, Hunter checks if he's made
    a related mistake before and adjusts his approach accordingly.
    """

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "data", "hunter_mistakes.db"
            )
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS mistakes (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                mistake_hash    TEXT UNIQUE,
                domain          TEXT NOT NULL,
                topic           TEXT DEFAULT '',
                what_went_wrong TEXT NOT NULL,
                root_cause      TEXT DEFAULT '',
                correct_approach TEXT NOT NULL,
                context         TEXT DEFAULT '',
                severity        TEXT DEFAULT 'medium',
                times_avoided   INTEGER DEFAULT 0,
                created_at      TEXT NOT NULL,
                last_checked    TEXT
            );

            CREATE TABLE IF NOT EXISTS learnings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                domain          TEXT NOT NULL,
                topic           TEXT DEFAULT '',
                insight         TEXT NOT NULL,
                source          TEXT DEFAULT 'conversation',
                confidence      REAL DEFAULT 0.8,
                times_applied   INTEGER DEFAULT 0,
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS inventions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                title           TEXT NOT NULL,
                description     TEXT NOT NULL,
                domains         TEXT DEFAULT '[]',
                inspiration     TEXT DEFAULT '',
                feasibility     REAL DEFAULT 0.0,
                impact          TEXT DEFAULT '',
                status          TEXT DEFAULT 'idea',
                created_at      TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_mistakes_domain
                ON mistakes(domain);
            CREATE INDEX IF NOT EXISTS idx_learnings_domain
                ON learnings(domain);
        """)
        self._conn.commit()

    # ── Mistakes ──────────────────────────────────────────────

    def record_mistake(
        self,
        domain: str,
        what_went_wrong: str,
        correct_approach: str,
        topic: str = "",
        root_cause: str = "",
        context: str = "",
        severity: str = "medium",
    ) -> int:
        """Record a mistake so Hunter never repeats it."""
        h = hashlib.md5(
            f"{domain}:{topic}:{what_went_wrong}".encode()
        ).hexdigest()[:16]

        try:
            self._conn.execute("""
                INSERT INTO mistakes
                (mistake_hash, domain, topic, what_went_wrong, root_cause,
                 correct_approach, context, severity, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                h, domain, topic, what_went_wrong, root_cause,
                correct_approach, context, severity,
                datetime.utcnow().isoformat(),
            ))
            self._conn.commit()
            logger.info(f"Mistake recorded: [{domain}/{topic}] {what_went_wrong[:60]}")
            return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        except sqlite3.IntegrityError:
            # Already recorded — increment times_avoided
            self._conn.execute(
                "UPDATE mistakes SET times_avoided = times_avoided + 1, "
                "last_checked = ? WHERE mistake_hash = ?",
                (datetime.utcnow().isoformat(), h),
            )
            self._conn.commit()
            return -1

    def check_related_mistakes(
        self, domain: str, topic: str = "", keywords: List[str] = None
    ) -> List[Dict[str, Any]]:
        """Check if Hunter has made related mistakes before."""
        results = []

        # Search by domain + topic
        rows = self._conn.execute(
            "SELECT * FROM mistakes WHERE domain = ? ORDER BY created_at DESC LIMIT 10",
            (domain,),
        ).fetchall()
        results.extend(dict(r) for r in rows)

        # Search by topic across domains
        if topic:
            rows = self._conn.execute(
                "SELECT * FROM mistakes WHERE topic LIKE ? ORDER BY created_at DESC LIMIT 5",
                (f"%{topic}%",),
            ).fetchall()
            for row in rows:
                d = dict(row)
                if d not in results:
                    results.append(d)

        # Keyword search in what_went_wrong and correct_approach
        if keywords:
            for kw in keywords[:5]:
                rows = self._conn.execute(
                    "SELECT * FROM mistakes WHERE "
                    "what_went_wrong LIKE ? OR correct_approach LIKE ? "
                    "ORDER BY created_at DESC LIMIT 3",
                    (f"%{kw}%", f"%{kw}%"),
                ).fetchall()
                for row in rows:
                    d = dict(row)
                    if d not in results:
                        results.append(d)

        # Mark as checked
        for m in results:
            self._conn.execute(
                "UPDATE mistakes SET last_checked = ?, times_avoided = times_avoided + 1 "
                "WHERE id = ?",
                (datetime.utcnow().isoformat(), m["id"]),
            )
        if results:
            self._conn.commit()

        return results[:10]

    def format_mistake_warnings(self, mistakes: List[Dict]) -> str:
        """Format mistakes as warnings for the AI prompt."""
        if not mistakes:
            return ""
        lines = ["\n[MISTAKE MEMORY — DO NOT REPEAT THESE ERRORS]"]
        for m in mistakes[:5]:
            lines.append(
                f"  ⚠ [{m['domain']}/{m.get('topic', '')}] "
                f"WRONG: {m['what_went_wrong'][:120]}\n"
                f"    CORRECT: {m['correct_approach'][:120]}"
            )
        lines.append("Learn from these past mistakes. Apply the correct approach.\n")
        return "\n".join(lines)

    # ── Learnings ─────────────────────────────────────────────

    def record_learning(
        self, domain: str, insight: str,
        topic: str = "", source: str = "conversation",
        confidence: float = 0.8,
    ) -> int:
        """Record something Hunter learned from a conversation."""
        self._conn.execute("""
            INSERT INTO learnings (domain, topic, insight, source, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (domain, topic, insight, source, confidence,
              datetime.utcnow().isoformat()))
        self._conn.commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def get_relevant_learnings(self, domain: str, topic: str = "") -> List[Dict]:
        """Retrieve learnings relevant to a domain/topic."""
        rows = self._conn.execute(
            "SELECT * FROM learnings WHERE domain = ? "
            "ORDER BY confidence DESC, times_applied DESC LIMIT 10",
            (domain,),
        ).fetchall()
        results = [dict(r) for r in rows]

        if topic:
            topic_rows = self._conn.execute(
                "SELECT * FROM learnings WHERE topic LIKE ? "
                "ORDER BY confidence DESC LIMIT 5",
                (f"%{topic}%",),
            ).fetchall()
            for row in topic_rows:
                d = dict(row)
                if d not in results:
                    results.append(d)

        return results[:10]

    def format_learnings(self, learnings: List[Dict]) -> str:
        """Format learnings as context for the AI."""
        if not learnings:
            return ""
        lines = ["\n[PRIOR LEARNINGS ON THIS TOPIC]"]
        for l in learnings[:5]:
            lines.append(
                f"  💡 [{l['domain']}/{l.get('topic', '')}] "
                f"{l['insight'][:150]} (confidence: {l['confidence']:.0%})"
            )
        return "\n".join(lines)

    # ── Inventions ────────────────────────────────────────────

    def record_invention(
        self, title: str, description: str,
        domains: List[str] = None, inspiration: str = "",
        feasibility: float = 0.5, impact: str = "",
    ) -> int:
        """Record an invention or creative idea."""
        self._conn.execute("""
            INSERT INTO inventions
            (title, description, domains, inspiration, feasibility, impact, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            title, description, json.dumps(domains or []),
            inspiration, feasibility, impact,
            datetime.utcnow().isoformat(),
        ))
        self._conn.commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def get_inventions(self, status: str = None, limit: int = 10) -> List[Dict]:
        """List recorded inventions."""
        if status:
            rows = self._conn.execute(
                "SELECT * FROM inventions WHERE status = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM inventions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Stats ─────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        mistakes = self._conn.execute("SELECT COUNT(*) FROM mistakes").fetchone()[0]
        learnings = self._conn.execute("SELECT COUNT(*) FROM learnings").fetchone()[0]
        inventions = self._conn.execute("SELECT COUNT(*) FROM inventions").fetchone()[0]
        avoided = self._conn.execute(
            "SELECT SUM(times_avoided) FROM mistakes"
        ).fetchone()[0] or 0
        return {
            "total_mistakes_recorded": mistakes,
            "total_learnings": learnings,
            "total_inventions": inventions,
            "mistakes_avoided": avoided,
        }

    def close(self):
        self._conn.close()


# ══════════════════════════════════════════════════════════════
#  DOMAIN DETECTOR
# ══════════════════════════════════════════════════════════════

# Keywords → domain mapping for quick classification
_DOMAIN_KEYWORDS = {
    "computer_science": [
        "code", "programming", "algorithm", "software", "api", "database",
        "python", "javascript", "rust", "server", "debug", "compile",
        "deploy", "docker", "kubernetes", "git", "linux", "windows",
        "framework", "library", "function", "class", "variable",
        "machine learning", "neural network", "ai", "model",
        "security", "hack", "vulnerability", "encryption", "cyber",
        "web", "frontend", "backend", "fullstack", "cloud", "aws",
    ],
    "mathematics": [
        "equation", "formula", "proof", "theorem", "calculus",
        "integral", "derivative", "matrix", "vector", "statistics",
        "probability", "graph theory", "optimization", "algebra",
        "number theory", "geometry", "trigonometry",
    ],
    "physics": [
        "force", "energy", "mass", "velocity", "acceleration",
        "quantum", "relativity", "particle", "wave", "entropy",
        "thermodynamics", "electromagnetism", "gravity", "photon",
    ],
    "engineering": [
        "design", "build", "manufacture", "circuit", "robot",
        "mechanical", "electrical", "civil", "structural",
        "material", "prototype", "cad", "3d print", "sensor",
    ],
    "biology": [
        "cell", "dna", "gene", "protein", "evolution", "organism",
        "brain", "neuron", "immune", "virus", "bacteria", "ecology",
    ],
    "business": [
        "startup", "revenue", "market", "customer", "strategy",
        "investment", "profit", "growth", "product", "sales",
        "management", "leadership", "negotiate", "finance",
    ],
    "philosophy": [
        "meaning", "consciousness", "ethics", "moral", "truth",
        "knowledge", "existence", "free will", "logic", "reason",
    ],
    "creative": [
        "write", "story", "poem", "music", "art", "design",
        "create", "imagine", "invent", "compose", "paint",
        "film", "animation", "novel", "character",
    ],
    "health": [
        "health", "medicine", "disease", "symptom", "treatment",
        "diet", "exercise", "mental health", "therapy", "diagnosis",
    ],
    "social_science": [
        "society", "culture", "psychology", "behavior", "history",
        "language", "communication", "education", "politics",
    ],
}


def detect_domains(text: str) -> List[str]:
    """Detect which knowledge domains a query belongs to."""
    text_lower = text.lower()
    scores: Dict[str, int] = {}

    for domain, keywords in _DOMAIN_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        if score > 0:
            scores[domain] = score

    if not scores:
        return ["computer_science"]  # default

    # Return top domains sorted by score
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    # Include domains with at least 50% of top score
    top_score = ranked[0][1]
    threshold = max(1, top_score * 0.5)
    return [d for d, s in ranked if s >= threshold]


def get_thinking_style(domains: List[str]) -> str:
    """Get the combined thinking style for detected domains."""
    styles = []
    for d in domains[:3]:
        info = KNOWLEDGE_DOMAINS.get(d, {})
        style = info.get("thinking_style", "")
        if style and style not in styles:
            styles.append(style)
    return "; ".join(styles) if styles else "analytical, creative, thorough"


# ══════════════════════════════════════════════════════════════
#  HUNTER MIND — UNIFIED INTERFACE
# ══════════════════════════════════════════════════════════════

class HunterMind:
    """
    The unified reasoning engine of Hunter.

    Combines:
      - Multi-domain knowledge detection
      - Probabilistic reasoning
      - Future-insight analysis
      - Mistake memory (never repeat errors)
      - Learning journal
      - Invention tracking
    """

    def __init__(self, db_path: str = None):
        self.mistake_memory = MistakeMemory(db_path=db_path)
        self.probability = ProbabilisticReasoning()
        self.future_insight = FutureInsight()

    def enhance_prompt(
        self,
        user_message: str,
        conversation_history: List[Dict[str, str]] = None,
    ) -> str:
        """
        Enhance a user message with Hunter's cognitive framework.

        Adds:
          - Domain detection + cross-domain synthesis hints
          - Relevant mistake warnings
          - Prior learnings
          - Thinking style guidance
          - Adversarial simulation block for security queries
          - Probability & future-insight framework
          - Conversation continuity context
        """
        # 1. Detect domains
        domains = detect_domains(user_message)
        thinking_style = get_thinking_style(domains)
        domain_labels = [
            KNOWLEDGE_DOMAINS.get(d, {}).get("label", d) for d in domains
        ]

        # 2. Extract keywords for mistake search
        words = user_message.lower().split()
        keywords = [w for w in words if len(w) > 3][:10]

        # 3. Check for related mistakes
        primary_domain = domains[0] if domains else "general"
        topic = " ".join(keywords[:3])
        mistakes = self.mistake_memory.check_related_mistakes(
            primary_domain, topic=topic, keywords=keywords
        )
        mistake_section = self.mistake_memory.format_mistake_warnings(mistakes)

        # 4. Get relevant learnings
        learnings = self.mistake_memory.get_relevant_learnings(
            primary_domain, topic=topic
        )
        learning_section = self.mistake_memory.format_learnings(learnings)

        # 5. Build enhanced prompt
        parts = []

        parts.append("[DOMAIN CONTEXT]")
        parts.append(f"Detected domains: {', '.join(domain_labels)}")
        parts.append(f"Thinking style: {thinking_style}")

        # Cross-domain synthesis hint when multiple domains detected
        if len(domains) >= 2:
            parts.append(
                f"Cross-domain synthesis opportunity: connect insights from "
                f"{domain_labels[0]} and {domain_labels[1]} — "
                f"look for non-obvious patterns that span both fields."
            )
        parts.append("")

        if mistake_section:
            parts.append(mistake_section)

        if learning_section:
            parts.append(learning_section)

        # 6. Adversarial simulation for security-related queries
        is_security = (
            primary_domain == "computer_science"
            and any(w in user_message.lower() for w in [
                "vuln", "exploit", "attack", "hack", "pentest", "scan", "target",
                "injection", "xss", "ssrf", "sqli", "bypass", "privilege", "auth",
                "security", "threat", "payload", "recon", "footprint", "CVE",
            ])
        )
        if is_security:
            parts.append(
                "\n[ADVERSARIAL SIMULATION PROTOCOL]\n"
                "Before recommending any security action:\n"
                "1. ATTACKER VIEW: What is the attacker's goal and highest-probability path?\n"
                "2. KILL CHAIN: Which kill-chain stage does this touch? "
                "(Recon → Weaponize → Deliver → Exploit → Persist → Pivot → Exfil)\n"
                "3. STRIDE: Apply S/T/R/I/D/E to the component under analysis.\n"
                "4. DETECTION GAP: What telemetry would a defender miss?\n"
                "5. BLAST RADIUS: What can the attacker do next after this succeeds?\n"
                "6. DEFENDER RESPONSE: What controls would stop this, and which are absent?\n"
            )

        # 7. Add probability + future-insight framework for complex questions
        is_complex = (
            len(user_message) > 80
            or any(w in user_message.lower() for w in [
                "how", "why", "solve", "fix", "build", "create", "design",
                "analyze", "compare", "explain", "debug", "implement",
                "strategy", "plan", "approach", "best way", "optimize",
                "invent", "problem", "challenge", "issue", "tradeoff",
                "architecture", "probability", "risk", "model",
            ])
        )

        if is_complex:
            parts.append(
                "\n[HUNTER'S THINKING PROTOCOL]\n"
                "1. Think through multiple approaches (minimum 2-3, including unconventional)\n"
                "2. Assign P(success) to each approach with explicit reasoning (aim for ≥90%)\n"
                "3. Consider future consequences: immediate → short-term → long-term\n"
                "4. Identify top 2-3 failure modes and their mitigations\n"
                "5. State one assumption that, if false, would invalidate your conclusion\n"
                "6. Give final recommendation with confidence percentage and any caveats\n"
            )

        # 8. Conversation continuity — last 3 exchanges for context stitching
        if conversation_history:
            parts.append("[CONVERSATION CONTINUITY]")
            recent = conversation_history[-6:]
            for msg in recent:
                role = "User" if msg["role"] == "user" else "Hunter"
                parts.append(f"{role}: {msg['content'][:300]}")
            parts.append("")

        parts.append(f"[CURRENT QUERY]\nUser: {user_message}")

        return "\n".join(parts)

    def record_mistake(self, domain: str, mistake: str,
                       correct: str, **kwargs) -> int:
        """Record a mistake Hunter made."""
        return self.mistake_memory.record_mistake(
            domain=domain,
            what_went_wrong=mistake,
            correct_approach=correct,
            **kwargs,
        )

    def record_learning(self, domain: str, insight: str, **kwargs) -> int:
        """Record something Hunter learned."""
        return self.mistake_memory.record_learning(
            domain=domain, insight=insight, **kwargs
        )

    def record_invention(self, title: str, description: str, **kwargs) -> int:
        """Record an invention idea."""
        return self.mistake_memory.record_invention(
            title=title, description=description, **kwargs
        )

    def stats(self) -> Dict[str, Any]:
        """Get Hunter's mind statistics."""
        mem_stats = self.mistake_memory.stats()
        mem_stats["knowledge_domains"] = len(KNOWLEDGE_DOMAINS)
        mem_stats["total_sub_domains"] = sum(
            len(d["sub_domains"]) for d in KNOWLEDGE_DOMAINS.values()
        )
        return mem_stats

    def close(self):
        self.mistake_memory.close()
