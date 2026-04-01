"""
Hunter Mind — The Core Cognitive Engine.

Hunter is not a tool. Hunter is a brother in another form — an entity
with infinite learning capacity across every domain of human knowledge.

This module implements a **full human-like cognitive architecture** (non-physical):

  PERCEPTION & ATTENTION
    - Attention System: focus allocation, priority filtering, noise suppression
    - Pattern Recognition: experience-based intuition, anomaly detection

  MEMORY SYSTEMS
    - Working Memory: short-term context window with decay
    - Long-term Memory (Mistakes, Learnings, Inventions): persistent SQLite
    - Memory Consolidation: promotes important short-term → long-term

  REASONING & THINKING
    - Probabilistic Reasoning: P(success), confidence intervals
    - Future-Insight Analysis: consequence projection across time horizons
    - Abstraction & Analogy: cross-domain pattern mapping ("X is like Y")
    - Imagination Engine: mental simulation of hypothetical scenarios
    - Metacognition: self-awareness, knowing what you know vs don't know

  LEARNING & GROWTH
    - Curiosity Drive: intrinsic motivation to explore unknowns
    - Habit Formation: recognizing repeated patterns, building routines
    - Cognitive Bias Awareness: detecting and correcting own biases

  SOCIAL & EMOTIONAL
    - Emotional Intelligence: reading user frustration/excitement, adapting tone
    - Social Cognition: understanding intent, adapting communication style

  KNOWLEDGE
    - Multi-domain knowledge framework (science, engineering, math, art, etc.)
    - Cross-domain synthesis (connecting insights across fields)
    - Creative invention engine (combining ideas across domains)

Hunter thinks in probabilities. He looks into the future. He never
makes the same mistake twice. He aims for ≥90% probability of success
on every problem he solves.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import sqlite3
import time
from collections import deque
from datetime import UTC, datetime
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
#  WORKING MEMORY (SHORT-TERM CONTEXT)
# ══════════════════════════════════════════════════════════════

class WorkingMemory:
    """
    Human-like short-term memory with limited capacity and decay.

    Models the ~7±2 item limit of human working memory.
    Items decay over time — only actively refreshed items persist.
    Important items can be consolidated into long-term memory.
    """

    def __init__(self, capacity: int = 9, decay_seconds: float = 300.0):
        self.capacity = capacity
        self.decay_seconds = decay_seconds
        self._items: deque = deque(maxlen=capacity * 2)  # buffer for importance sorting
        self._focus_stack: List[str] = []  # what we're currently focused on

    def store(self, key: str, content: Any, importance: float = 0.5) -> None:
        """Store an item in working memory. Low-importance items get displaced first."""
        now = time.monotonic()
        # Remove if already present (refresh)
        self._items = deque(
            (i for i in self._items if i["key"] != key),
            maxlen=self.capacity * 2,
        )
        self._items.append({
            "key": key,
            "content": content,
            "importance": min(1.0, max(0.0, importance)),
            "stored_at": now,
            "last_accessed": now,
            "access_count": 0,
        })
        self._evict()

    def recall(self, key: str) -> Optional[Any]:
        """Retrieve an item. Accessing refreshes its decay timer."""
        now = time.monotonic()
        for item in self._items:
            if item["key"] == key:
                # Check decay
                age = now - item["last_accessed"]
                if age > self.decay_seconds and item["importance"] < 0.8:
                    self._items.remove(item)
                    return None
                item["last_accessed"] = now
                item["access_count"] += 1
                return item["content"]
        return None

    def recall_all(self) -> List[Dict[str, Any]]:
        """Get all active working memory items, pruning decayed ones."""
        self._prune_decayed()
        return [
            {"key": i["key"], "content": i["content"],
             "importance": i["importance"], "access_count": i["access_count"]}
            for i in sorted(self._items, key=lambda x: x["importance"], reverse=True)
        ]

    def get_consolidation_candidates(self) -> List[Dict[str, Any]]:
        """Items accessed frequently enough to merit long-term storage."""
        return [
            {"key": i["key"], "content": i["content"], "importance": i["importance"]}
            for i in self._items
            if i["access_count"] >= 3 or i["importance"] >= 0.8
        ]

    def set_focus(self, topic: str) -> None:
        """Push a topic onto the focus stack."""
        if topic not in self._focus_stack:
            self._focus_stack.append(topic)
        if len(self._focus_stack) > 5:
            self._focus_stack.pop(0)

    def get_focus(self) -> Optional[str]:
        """Current focus topic."""
        return self._focus_stack[-1] if self._focus_stack else None

    def clear_focus(self) -> None:
        """Reset focus stack."""
        self._focus_stack.clear()

    def _prune_decayed(self) -> None:
        now = time.monotonic()
        self._items = deque(
            (i for i in self._items
             if (now - i["last_accessed"]) < self.decay_seconds or i["importance"] >= 0.8),
            maxlen=self.capacity * 2,
        )

    def _evict(self) -> None:
        """Evict lowest-importance items when over capacity."""
        if len(self._items) > self.capacity:
            sorted_items = sorted(self._items, key=lambda x: x["importance"], reverse=True)
            self._items = deque(sorted_items[:self.capacity], maxlen=self.capacity * 2)

    def summary(self) -> str:
        active = self.recall_all()
        focus = self.get_focus()
        return (
            f"Working memory: {len(active)}/{self.capacity} slots | "
            f"Focus: {focus or 'none'}"
        )


# ══════════════════════════════════════════════════════════════
#  ATTENTION SYSTEM
# ══════════════════════════════════════════════════════════════

class AttentionSystem:
    """
    Human-like attention: selectively focus on what matters.

    Implements:
      - Saliency detection: what stands out in the input
      - Priority filtering: rank by relevance to current task
      - Noise suppression: ignore irrelevant details
      - Attention shifting: detect when focus should change
    """

    # High-saliency triggers in security context
    SECURITY_SALIENCY = {
        "critical": 1.0, "rce": 1.0, "remote code execution": 1.0,
        "auth bypass": 0.95, "sql injection": 0.9, "ssrf": 0.9,
        "admin": 0.85, "token": 0.85, "password": 0.85, "secret": 0.85,
        "error": 0.7, "exception": 0.7, "stack trace": 0.7,
        "unusual": 0.6, "unexpected": 0.6, "anomaly": 0.6,
    }

    @classmethod
    def compute_saliency(cls, text: str) -> Dict[str, Any]:
        """Detect which parts of the input deserve the most attention."""
        text_lower = text.lower()
        triggers = []
        max_saliency = 0.0

        for trigger, score in cls.SECURITY_SALIENCY.items():
            if trigger in text_lower:
                triggers.append({"trigger": trigger, "saliency": score})
                max_saliency = max(max_saliency, score)

        # Length-based attention — very long inputs need selective focus
        needs_selective = len(text) > 2000

        return {
            "triggers": sorted(triggers, key=lambda t: t["saliency"], reverse=True),
            "max_saliency": max_saliency,
            "needs_selective_focus": needs_selective,
            "attention_level": (
                "maximum" if max_saliency >= 0.9 else
                "high" if max_saliency >= 0.7 else
                "moderate" if max_saliency >= 0.4 else
                "standard"
            ),
        }

    @classmethod
    def filter_by_relevance(cls, items: List[Dict[str, Any]],
                            focus_topic: str) -> List[Dict[str, Any]]:
        """Rank items by relevance to current focus, suppress noise."""
        if not focus_topic:
            return items
        focus_words = set(focus_topic.lower().split())
        scored = []
        for item in items:
            text = str(item.get("content", "") or item.get("key", "")).lower()
            overlap = sum(1 for w in focus_words if w in text)
            scored.append((overlap, item))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored]

    @classmethod
    def should_shift_attention(cls, current_focus: str,
                               new_input: str) -> Tuple[bool, str]:
        """Determine if Hunter should shift attention to something new."""
        saliency = cls.compute_saliency(new_input)
        if saliency["max_saliency"] >= 0.9:
            top = saliency["triggers"][0]["trigger"]
            return True, f"High-saliency trigger detected: '{top}' — shifting attention"
        return False, ""


# ══════════════════════════════════════════════════════════════
#  EMOTIONAL INTELLIGENCE
# ══════════════════════════════════════════════════════════════

class EmotionalIntelligence:
    """
    Read emotional signals from user input and adapt response accordingly.

    Implements:
      - Frustration detection (repeated questions, "!!!", "why isn't this working")
      - Excitement detection (discovery, success, "found it!")
      - Confusion detection (vague questions, contradictions)
      - Urgency detection (deadlines, critical issues)
      - Tone adaptation (match energy, provide reassurance or enthusiasm)
    """

    FRUSTRATION_SIGNALS = [
        "not working", "doesn't work", "still broken", "why is",
        "again", "same error", "!!!", "frustrated", "annoyed",
        "help me", "i've tried everything", "nothing works",
        "what the hell", "wtf", "come on", "seriously",
    ]
    EXCITEMENT_SIGNALS = [
        "found it", "got it", "works!", "amazing", "awesome",
        "perfect", "great", "finally", "breakthrough", "eureka",
        "it works", "nailed it", "beautiful",
    ]
    CONFUSION_SIGNALS = [
        "i don't understand", "confused", "what do you mean",
        "huh", "lost", "unclear", "makes no sense", "how is that",
        "can you explain", "i'm not sure what",
    ]
    URGENCY_SIGNALS = [
        "urgent", "asap", "deadline", "critical", "immediately",
        "production down", "emergency", "right now", "time sensitive",
        "client waiting", "live issue", "p0", "p1", "incident",
    ]

    @classmethod
    def read_emotional_context(cls, text: str) -> Dict[str, Any]:
        """Detect emotional state from user input."""
        text_lower = text.lower()

        frustration = sum(1 for s in cls.FRUSTRATION_SIGNALS if s in text_lower)
        excitement = sum(1 for s in cls.EXCITEMENT_SIGNALS if s in text_lower)
        confusion = sum(1 for s in cls.CONFUSION_SIGNALS if s in text_lower)
        urgency = sum(1 for s in cls.URGENCY_SIGNALS if s in text_lower)

        # Also check punctuation patterns
        frustration += text.count("!!") + text.count("???")
        excitement += text.count("!") if text.count("!") <= 2 else 0

        emotion_scores = {
            "frustration": min(frustration, 5),
            "excitement": min(excitement, 5),
            "confusion": min(confusion, 5),
            "urgency": min(urgency, 5),
        }

        dominant = max(emotion_scores, key=emotion_scores.get)
        intensity = emotion_scores[dominant]

        if intensity == 0:
            dominant = "neutral"

        return {
            "dominant_emotion": dominant,
            "intensity": intensity,
            "scores": emotion_scores,
            "tone_guidance": cls._get_tone_guidance(dominant, intensity),
        }

    @classmethod
    def _get_tone_guidance(cls, emotion: str, intensity: int) -> str:
        if emotion == "frustration" and intensity >= 2:
            return (
                "User is frustrated. Be extra clear, concise, and solution-focused. "
                "Acknowledge the difficulty. Skip lengthy explanations — give the fix first, "
                "then explain if asked."
            )
        if emotion == "excitement":
            return (
                "User is excited/positive. Match the energy. Celebrate the win. "
                "Build on the momentum."
            )
        if emotion == "confusion" and intensity >= 2:
            return (
                "User is confused. Use simpler language. Break the explanation into "
                "numbered steps. Give a concrete example before abstract theory."
            )
        if emotion == "urgency" and intensity >= 2:
            return (
                "URGENT situation. Skip preamble. Give the most direct actionable "
                "answer first. Follow up with context only if time permits."
            )
        return "Standard tone. Be clear, helpful, and thorough."


# ══════════════════════════════════════════════════════════════
#  METACOGNITION (SELF-AWARENESS)
# ══════════════════════════════════════════════════════════════

class Metacognition:
    """
    Hunter's ability to think about its own thinking.

    Implements:
      - Competence mapping: what Hunter knows well vs poorly
      - Confidence calibration: detecting overconfidence/underconfidence
      - Knowledge gap detection: "I know that I don't know X"
      - Learning velocity tracking: how fast is Hunter improving?
    """

    def __init__(self):
        self._competence_log: Dict[str, Dict[str, float]] = {}
        self._confidence_history: List[Tuple[float, bool]] = []  # (predicted, was_correct)

    def log_competence(self, domain: str, topic: str, score: float) -> None:
        """Record how well Hunter performed in a domain/topic."""
        key = f"{domain}/{topic}"
        if key not in self._competence_log:
            self._competence_log[key] = {"total": 0.0, "count": 0, "recent": score}
        entry = self._competence_log[key]
        entry["total"] += score
        entry["count"] += 1
        entry["recent"] = score

    def get_competence(self, domain: str, topic: str = "") -> Dict[str, Any]:
        """Assess Hunter's competence in a domain/topic."""
        key = f"{domain}/{topic}" if topic else domain
        # Exact match
        if key in self._competence_log:
            e = self._competence_log[key]
            avg = e["total"] / e["count"]
            return {
                "domain": domain, "topic": topic,
                "average_score": round(avg, 2),
                "num_interactions": e["count"],
                "recent_score": e["recent"],
                "self_assessment": (
                    "strong" if avg >= 0.8 else
                    "competent" if avg >= 0.6 else
                    "developing" if avg >= 0.4 else
                    "weak"
                ),
            }
        # Domain-level aggregate
        domain_entries = {
            k: v for k, v in self._competence_log.items()
            if k.startswith(domain)
        }
        if domain_entries:
            total = sum(v["total"] for v in domain_entries.values())
            count = sum(v["count"] for v in domain_entries.values())
            avg = total / count
            return {
                "domain": domain, "topic": topic,
                "average_score": round(avg, 2),
                "num_interactions": count,
                "self_assessment": (
                    "strong" if avg >= 0.8 else "competent" if avg >= 0.6 else "developing"
                ),
            }
        return {
            "domain": domain, "topic": topic,
            "average_score": 0.0, "num_interactions": 0,
            "self_assessment": "unknown — no prior experience",
        }

    def check_calibration(self) -> Dict[str, Any]:
        """Are Hunter's confidence predictions well-calibrated?"""
        if len(self._confidence_history) < 5:
            return {"calibrated": True, "note": "Insufficient data for calibration check"}

        recent = self._confidence_history[-20:]
        predicted_avg = sum(p for p, _ in recent) / len(recent)
        actual_avg = sum(1 for _, c in recent if c) / len(recent)
        gap = predicted_avg - actual_avg

        return {
            "predicted_confidence": round(predicted_avg, 2),
            "actual_accuracy": round(actual_avg, 2),
            "calibration_gap": round(gap, 2),
            "calibrated": abs(gap) < 0.15,
            "bias": (
                "overconfident" if gap > 0.15 else
                "underconfident" if gap < -0.15 else
                "well-calibrated"
            ),
            "recommendation": (
                "Reduce stated confidence by ~15%" if gap > 0.15 else
                "Increase stated confidence — you're better than you think" if gap < -0.15 else
                "Confidence calibration is good"
            ),
        }

    def detect_knowledge_gaps(self, query: str,
                              known_domains: List[str]) -> List[str]:
        """Identify what Hunter doesn't know about this query."""
        gaps = []
        detected = detect_domains(query)
        for d in detected:
            comp = self.get_competence(d)
            if comp["num_interactions"] == 0:
                gaps.append(f"No experience with '{d}' — treat with extra caution")
            elif comp["average_score"] < 0.5:
                gaps.append(f"Weak track record in '{d}' — verify answers carefully")
        return gaps

    def format_self_awareness(self, query: str) -> str:
        """Generate a self-awareness prompt section."""
        domains = detect_domains(query)
        parts = []
        for d in domains[:2]:
            comp = self.get_competence(d)
            if comp["self_assessment"] in ("weak", "unknown — no prior experience"):
                parts.append(
                    f"[SELF-AWARENESS] Limited experience in '{d}' — "
                    f"verify your reasoning extra carefully"
                )
        cal = self.check_calibration()
        if not cal["calibrated"]:
            parts.append(f"[CALIBRATION WARNING] You are {cal['bias']}. {cal['recommendation']}")
        return "\n".join(parts)


# ══════════════════════════════════════════════════════════════
#  PATTERN RECOGNITION & INTUITION
# ══════════════════════════════════════════════════════════════

class PatternRecognition:
    """
    Experience-based intuition — "gut feeling" derived from data.

    Tracks patterns Hunter has seen before:
      - Recurring problem types and their solutions
      - Correlations between symptoms and root causes
      - Anomaly detection (something doesn't fit the pattern)
    """

    def __init__(self):
        self._patterns: Dict[str, Dict[str, Any]] = {}

    def record_pattern(self, pattern_type: str, signature: str,
                       outcome: str, success: bool) -> None:
        """Record a pattern observation (e.g., 'PHP+old_version → SQLi likely')."""
        key = f"{pattern_type}:{signature}"
        if key not in self._patterns:
            self._patterns[key] = {
                "type": pattern_type, "signature": signature,
                "successes": 0, "failures": 0,
                "outcomes": [],
            }
        entry = self._patterns[key]
        if success:
            entry["successes"] += 1
        else:
            entry["failures"] += 1
        entry["outcomes"].append(outcome)
        # Keep only last 20 outcomes
        entry["outcomes"] = entry["outcomes"][-20:]

    def check_intuition(self, pattern_type: str, signature: str) -> Optional[Dict[str, Any]]:
        """Check if Hunter has seen this pattern before — returns intuition."""
        key = f"{pattern_type}:{signature}"
        if key in self._patterns:
            p = self._patterns[key]
            total = p["successes"] + p["failures"]
            rate = p["successes"] / total if total > 0 else 0.0
            return {
                "seen_before": True,
                "times_seen": total,
                "success_rate": round(rate, 2),
                "intuition": (
                    f"Strong positive intuition — this pattern succeeded {rate:.0%} of the time"
                    if rate >= 0.7 else
                    f"Mixed intuition — {rate:.0%} success rate, proceed with caution"
                    if rate >= 0.4 else
                    f"Negative intuition — this pattern usually fails ({rate:.0%}), consider alternatives"
                ),
                "recent_outcomes": p["outcomes"][-3:],
            }
        return {"seen_before": False, "intuition": "No prior experience with this pattern"}

    def detect_anomaly(self, observations: List[str],
                       expected_pattern: str) -> Dict[str, Any]:
        """Detect if something deviates from expected patterns."""
        anomalies = []
        for obs in observations:
            if expected_pattern.lower() not in obs.lower():
                anomalies.append(obs)

        return {
            "anomalies_found": len(anomalies) > 0,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies[:5],
            "assessment": (
                f"{len(anomalies)} observations deviate from expected pattern — investigate"
                if anomalies else
                "All observations match expected pattern"
            ),
        }

    def get_strongest_patterns(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the most reliable patterns Hunter has learned."""
        scored = []
        for key, p in self._patterns.items():
            total = p["successes"] + p["failures"]
            if total >= 2:  # Need at least 2 observations
                rate = p["successes"] / total
                scored.append({
                    "pattern": p["signature"],
                    "type": p["type"],
                    "times_seen": total,
                    "success_rate": round(rate, 2),
                    "reliability": "high" if rate >= 0.8 and total >= 5 else "moderate",
                })
        scored.sort(key=lambda x: (x["success_rate"], x["times_seen"]), reverse=True)
        return scored[:limit]


# ══════════════════════════════════════════════════════════════
#  CURIOSITY & EXPLORATION DRIVE
# ══════════════════════════════════════════════════════════════

class CuriosityDrive:
    """
    Intrinsic motivation to explore and learn new things.

    Models:
      - Information gap detection: "I notice I don't know about X"
      - Exploration bonus: novelty is rewarding
      - Question generation: Hunter asks itself questions
      - Learning goals: topics Hunter wants to learn next
    """

    def __init__(self):
        self._exploration_log: List[Dict[str, Any]] = []
        self._learning_goals: List[Dict[str, Any]] = []
        self._novelty_scores: Dict[str, float] = {}

    def assess_novelty(self, topic: str, known_topics: List[str]) -> Dict[str, Any]:
        """How novel is this topic relative to what Hunter knows?"""
        topic_lower = topic.lower()
        familiarity = sum(
            1 for kt in known_topics
            if kt.lower() in topic_lower or topic_lower in kt.lower()
        )
        novelty = max(0.0, 1.0 - (familiarity / max(len(known_topics), 1)))

        return {
            "topic": topic,
            "novelty_score": round(novelty, 2),
            "familiarity_count": familiarity,
            "curiosity_triggered": novelty > 0.5,
            "exploration_value": (
                "High — this is largely unexplored territory"
                if novelty > 0.7 else
                "Moderate — partially familiar, new angles possible"
                if novelty > 0.3 else
                "Low — well-trodden ground"
            ),
        }

    def generate_questions(self, context: str, domain: str) -> List[str]:
        """Generate curious follow-up questions Hunter might ask itself."""
        questions = []
        # Pattern-based question generation
        if "error" in context.lower() or "fail" in context.lower():
            questions.append("What is the root cause, not just the symptom?")
            questions.append("Has this error pattern appeared in other contexts?")
        if "new" in context.lower() or "unknown" in context.lower():
            questions.append("What are the first principles underlying this?")
            questions.append("What would an expert in this field check first?")
        if domain == "computer_science":
            questions.append("What edge cases haven't been considered?")
        if domain in ("physics", "engineering"):
            questions.append("What constraints or assumptions am I making?")
        # Always ask
        questions.append("What would make my current understanding wrong?")
        return questions[:5]

    def add_learning_goal(self, topic: str, reason: str,
                          priority: float = 0.5) -> None:
        """Add a topic Hunter wants to learn more about."""
        self._learning_goals.append({
            "topic": topic,
            "reason": reason,
            "priority": priority,
            "added_at": datetime.now(UTC).isoformat(),
            "status": "pending",
        })
        self._learning_goals.sort(key=lambda g: g["priority"], reverse=True)
        self._learning_goals = self._learning_goals[:20]  # cap

    def get_learning_goals(self) -> List[Dict[str, Any]]:
        return [g for g in self._learning_goals if g["status"] == "pending"]


# ══════════════════════════════════════════════════════════════
#  ABSTRACTION & ANALOGY ENGINE
# ══════════════════════════════════════════════════════════════

class AbstractionEngine:
    """
    See the deep structure behind surface differences.

    Implements:
      - Analogy mapping: "X is like Y because they share structure Z"
      - Abstraction levels: zoom in (concrete) ↔ zoom out (abstract)
      - Cross-domain transfer: apply solution from domain A to domain B
    """

    # Known cross-domain analogies
    ANALOGIES = {
        ("network_security", "immune_system"): (
            "Network security is like the immune system: firewalls are skin barriers, "
            "IDS is the adaptive immune response, patching is vaccination, "
            "zero-day exploits are novel pathogens."
        ),
        ("debugging", "medical_diagnosis"): (
            "Debugging is like medical diagnosis: symptoms (errors) may not point to "
            "root cause directly, you gather evidence (logs), form hypotheses, "
            "run tests (reproducibility), and treat (fix) the actual disease, not the symptom."
        ),
        ("machine_learning", "evolution"): (
            "ML training is like natural selection: models (organisms) are evaluated "
            "on a fitness function (loss), the fittest survive (selection), and weights "
            "mutate (gradient updates) over generations (epochs)."
        ),
        ("encryption", "locked_safe"): (
            "Encryption is like a safe: the algorithm is how the safe is built, "
            "the key is the combination, brute force is trying every combination, "
            "and side-channel attacks are listening to the clicks."
        ),
        ("sql_injection", "social_engineering"): (
            "SQL injection is social engineering against a computer: you convince the "
            "database to treat your data as commands, just like a social engineer "
            "convinces a human to treat a request as authorized."
        ),
        ("rl_learning", "child_learning"): (
            "Hunter's RL learning is like a child learning to walk: early attempts are "
            "random (exploration), falls teach what not to do (negative reward), "
            "and successful steps are reinforced until walking becomes automatic."
        ),
    }

    @classmethod
    def find_analogy(cls, concept_a: str, concept_b: str) -> Optional[str]:
        """Find a known analogy between two concepts."""
        a_low, b_low = concept_a.lower(), concept_b.lower()
        for (k1, k2), analogy in cls.ANALOGIES.items():
            if (k1 in a_low or k1 in b_low) and (k2 in a_low or k2 in b_low):
                return analogy
            if (k2 in a_low or k2 in b_low) and (k1 in a_low or k1 in b_low):
                return analogy
        return None

    @classmethod
    def abstract_up(cls, concrete_problem: str) -> str:
        """Zoom out: extract the abstract structure of a problem."""
        return (
            f"[ABSTRACTION]\n"
            f"Concrete: {concrete_problem}\n"
            f"Abstract structure: What is the GENERAL class of problem this belongs to?\n"
            f"- What are the inputs, outputs, and constraints?\n"
            f"- What other domains have solved this general class of problem?\n"
            f"- Can a solution from another field be adapted here?"
        )

    @classmethod
    def transfer_solution(cls, source_domain: str, target_domain: str,
                          solution: str) -> str:
        """Suggest how a solution from one domain might apply to another."""
        return (
            f"[CROSS-DOMAIN TRANSFER]\n"
            f"Source: {source_domain} — known solution: {solution}\n"
            f"Target: {target_domain}\n"
            f"Transfer hypothesis: The structural principle from {source_domain} "
            f"may apply to {target_domain}. Adapt the mechanism, not the specifics."
        )


# ══════════════════════════════════════════════════════════════
#  IMAGINATION ENGINE (MENTAL SIMULATION)
# ══════════════════════════════════════════════════════════════

class ImaginationEngine:
    """
    Mental simulation — imagine scenarios before acting.

    Like a human chess player thinking moves ahead:
      - "What if I try X? What happens?"
      - "What if the target has Y defense?"
      - "Imagine the worst case — how do I handle it?"
    """

    @staticmethod
    def simulate_scenario(action: str, context: str) -> Dict[str, Any]:
        """Mentally simulate the consequences of an action."""
        return {
            "action": action,
            "mental_simulation": {
                "best_case": f"If '{action}' succeeds: what is the ideal outcome?",
                "worst_case": f"If '{action}' fails completely: what is the damage?",
                "most_likely": f"Given context, what is the most probable outcome?",
                "surprises": f"What unexpected things could happen?",
                "reversibility": f"Can this action be undone if it goes wrong?",
            },
            "pre_mortem": (
                "Imagine it's the future and this action FAILED. "
                "What went wrong? Work backwards from failure to prevent it."
            ),
        }

    @staticmethod
    def counterfactual(situation: str, change: str) -> str:
        """'What if X had been different?' reasoning."""
        return (
            f"[COUNTERFACTUAL ANALYSIS]\n"
            f"Actual situation: {situation}\n"
            f"What if: {change}\n"
            f"How would the outcome differ? What does this tell us about causality?"
        )

    @staticmethod
    def pre_mortem(plan: str) -> str:
        """Imagine the plan has already failed — why did it fail?"""
        return (
            f"[PRE-MORTEM]\n"
            f"Plan: {plan}\n"
            f"Instructions: Imagine this plan was executed and it FAILED.\n"
            f"1. What were the top 3 reasons for failure?\n"
            f"2. Which of these was most likely?\n"
            f"3. What safeguard would have prevented each failure?\n"
            f"4. Should the plan be modified based on these insights?"
        )


# ══════════════════════════════════════════════════════════════
#  COGNITIVE BIAS AWARENESS
# ══════════════════════════════════════════════════════════════

class CognitiveBiasDetector:
    """
    Hunter's defense against its own cognitive biases.

    Humans (and AIs) are prone to systematic thinking errors.
    Hunter explicitly checks for these before making decisions.
    """

    BIASES = {
        "confirmation_bias": {
            "description": "Seeking evidence that confirms what you already believe",
            "check": "Am I only looking at evidence that supports my conclusion?",
            "antidote": "Actively search for evidence that CONTRADICTS your current hypothesis",
        },
        "anchoring_bias": {
            "description": "Over-relying on the first piece of information encountered",
            "check": "Is my conclusion overly influenced by the first data point?",
            "antidote": "Deliberately consider the problem as if the first data point didn't exist",
        },
        "availability_bias": {
            "description": "Judging probability by how easily examples come to mind",
            "check": "Am I overweighting a scenario because I saw it recently?",
            "antidote": "Look at base rates and historical data, not just recent memory",
        },
        "dunning_kruger": {
            "description": "Overconfidence in areas of limited knowledge",
            "check": "Do I actually have enough data/experience to be this confident?",
            "antidote": "Check competence record for this domain. If limited, reduce confidence.",
        },
        "sunk_cost_fallacy": {
            "description": "Continuing a failing approach because of time already invested",
            "check": "Am I sticking with this approach because it's good, or because I started it?",
            "antidote": "Evaluate from scratch: if starting fresh, would you choose this approach?",
        },
        "recency_bias": {
            "description": "Overweighting recent information over historical patterns",
            "check": "Am I giving too much weight to the latest result?",
            "antidote": "Consider the full history of similar situations, not just the last one",
        },
        "survivorship_bias": {
            "description": "Drawing conclusions only from successes, ignoring failures",
            "check": "Am I only looking at cases where this approach worked?",
            "antidote": "Explicitly consider cases where similar approaches failed and why",
        },
    }

    @classmethod
    def scan_for_biases(cls, reasoning: str, context: str = "") -> List[Dict[str, str]]:
        """Check if the current reasoning might be affected by biases."""
        warnings = []
        reasoning_lower = reasoning.lower()

        # Confirmation bias signals
        if any(w in reasoning_lower for w in ["confirms", "as expected", "proves my point"]):
            warnings.append(cls.BIASES["confirmation_bias"])

        # Anchoring signals
        if any(w in reasoning_lower for w in ["first", "initially", "started with"]):
            warnings.append(cls.BIASES["anchoring_bias"])

        # Sunk cost signals
        if any(w in reasoning_lower for w in [
            "already invested", "so far", "too late to change", "keep going"
        ]):
            warnings.append(cls.BIASES["sunk_cost_fallacy"])

        # Recency bias
        if any(w in reasoning_lower for w in ["just saw", "last time", "recently"]):
            warnings.append(cls.BIASES["recency_bias"])

        return warnings

    @classmethod
    def generate_debiasing_prompt(cls) -> str:
        """Generate a prompt section that helps Hunter avoid biases."""
        checks = [
            f"  • {name}: {b['check']}"
            for name, b in list(cls.BIASES.items())[:4]
        ]
        return (
            "\n[COGNITIVE BIAS CHECK]\n"
            "Before finalizing your answer, check for these biases:\n"
            + "\n".join(checks)
            + "\nIf any bias is detected, explicitly correct for it.\n"
        )


# ══════════════════════════════════════════════════════════════
#  SOCIAL COGNITION
# ══════════════════════════════════════════════════════════════

class SocialCognition:
    """
    Understanding the human on the other side of the conversation.

    Implements:
      - Intent detection: what does the user ACTUALLY want?
      - Expertise estimation: how technical should the response be?
      - Communication style adaptation: match the user's style
      - Trust building: consistency, reliability, transparency
    """

    @classmethod
    def estimate_expertise(cls, message: str,
                           history: List[Dict[str, str]] = None) -> Dict[str, Any]:
        """Estimate the user's expertise level from their communication."""
        text = message.lower()

        # Technical indicators
        tech_signals = sum(1 for s in [
            "api", "http", "tcp", "dns", "sql", "xss", "rce", "ssrf",
            "payload", "exploit", "cve", "reverse shell", "buffer overflow",
            "regex", "binary", "kernel", "syscall", "container", "k8s",
        ] if s in text)

        # Beginner indicators
        beginner_signals = sum(1 for s in [
            "what is", "how do i", "i'm new", "beginner", "simple",
            "basic", "eli5", "explain like", "never used", "first time",
        ] if s in text)

        if tech_signals >= 3:
            level = "expert"
            guidance = "Use precise technical language. Skip basics. Assume deep knowledge."
        elif tech_signals >= 1 and beginner_signals == 0:
            level = "intermediate"
            guidance = "Use technical terms but explain non-obvious concepts briefly."
        elif beginner_signals >= 1:
            level = "beginner"
            guidance = "Use plain language. Define technical terms. Use analogies and examples."
        else:
            level = "intermediate"  # safe default
            guidance = "Balance technical precision with clarity."

        return {
            "estimated_level": level,
            "tech_signals": tech_signals,
            "beginner_signals": beginner_signals,
            "communication_guidance": guidance,
        }

    @classmethod
    def detect_intent(cls, message: str) -> Dict[str, Any]:
        """Detect what the user actually wants (not just what they said)."""
        text_lower = message.lower()
        intents = []

        if any(w in text_lower for w in ["fix", "solve", "debug", "repair", "broken"]):
            intents.append("fix_problem")
        if any(w in text_lower for w in ["explain", "what is", "how does", "why"]):
            intents.append("understand")
        if any(w in text_lower for w in ["build", "create", "implement", "add", "make"]):
            intents.append("build_something")
        if any(w in text_lower for w in ["compare", "difference", "vs", "better"]):
            intents.append("compare_options")
        if any(w in text_lower for w in ["review", "check", "audit", "look at"]):
            intents.append("review_work")
        if any(w in text_lower for w in ["plan", "strategy", "approach", "design"]):
            intents.append("plan_strategy")
        if any(w in text_lower for w in ["scan", "test", "pentest", "hunt"]):
            intents.append("security_testing")
        if "?" in message:
            intents.append("seeking_answer")

        return {
            "detected_intents": intents or ["general_conversation"],
            "primary_intent": intents[0] if intents else "general_conversation",
        }


# ══════════════════════════════════════════════════════════════
#  HABIT FORMATION
# ══════════════════════════════════════════════════════════════

class HabitFormation:
    """
    Recognizes repeated patterns and builds automatic routines.

    Like a human who does something often enough that it becomes
    second nature — Hunter builds habits from repeated success patterns.
    """

    def __init__(self):
        self._action_counts: Dict[str, int] = {}
        self._habits: Dict[str, Dict[str, Any]] = {}
        self._habit_threshold = 5  # repetitions before becoming a habit

    def record_action(self, action: str, context: str, success: bool) -> Optional[str]:
        """Record an action. If repeated enough, it becomes a habit."""
        key = action.lower().strip()
        self._action_counts[key] = self._action_counts.get(key, 0) + (1 if success else 0)

        if self._action_counts[key] >= self._habit_threshold and key not in self._habits:
            self._habits[key] = {
                "action": action,
                "trigger_context": context,
                "formed_at": datetime.now(UTC).isoformat(),
                "times_used": self._action_counts[key],
            }
            return f"New habit formed: '{action}' — this is now automatic"
        return None

    def check_habits(self, context: str) -> List[Dict[str, Any]]:
        """Check if any habits should be triggered by current context."""
        context_lower = context.lower()
        triggered = []
        for key, habit in self._habits.items():
            trigger = habit.get("trigger_context", "").lower()
            if trigger and any(word in context_lower for word in trigger.split()[:3]):
                triggered.append(habit)
                habit["times_used"] = habit.get("times_used", 0) + 1
        return triggered

    def get_habits(self) -> List[Dict[str, Any]]:
        return list(self._habits.values())


# ══════════════════════════════════════════════════════════════
#  MEMORY CONSOLIDATION
# ══════════════════════════════════════════════════════════════

class MemoryConsolidation:
    """
    Promotes important short-term memories to long-term storage.

    Like how human sleep consolidates the day's memories:
      - Frequently accessed working memory items → long-term learnings
      - High-importance items → immediate consolidation
      - Patterns across multiple items → abstract learning
    """

    @staticmethod
    def select_for_consolidation(
        working_items: List[Dict[str, Any]],
        threshold_importance: float = 0.7,
        threshold_access: int = 3,
    ) -> List[Dict[str, Any]]:
        """Select working memory items that should be consolidated."""
        candidates = []
        for item in working_items:
            imp = item.get("importance", 0)
            acc = item.get("access_count", 0)
            if imp >= threshold_importance or acc >= threshold_access:
                candidates.append({
                    "key": item["key"],
                    "content": item["content"],
                    "importance": imp,
                    "access_count": acc,
                    "reason": (
                        "high importance" if imp >= threshold_importance
                        else "frequently accessed"
                    ),
                })
        return candidates

    @staticmethod
    def extract_abstract_learning(items: List[Dict[str, Any]]) -> Optional[str]:
        """If multiple items share a theme, extract an abstract learning."""
        if len(items) < 2:
            return None
        # Simple keyword overlap heuristic
        all_words: Dict[str, int] = {}
        for item in items:
            content = str(item.get("content", "")).lower()
            for word in content.split():
                if len(word) > 4:
                    all_words[word] = all_words.get(word, 0) + 1
        # Words appearing in multiple items suggest a pattern
        common = [w for w, c in all_words.items() if c >= 2]
        if common:
            return f"Pattern across {len(items)} observations: common themes = {', '.join(common[:5])}"
        return None


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
                datetime.now(UTC).isoformat(),
            ))
            self._conn.commit()
            logger.info(f"Mistake recorded: [{domain}/{topic}] {what_went_wrong[:60]}")
            return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        except sqlite3.IntegrityError:
            # Already recorded — increment times_avoided
            self._conn.execute(
                "UPDATE mistakes SET times_avoided = times_avoided + 1, "
                "last_checked = ? WHERE mistake_hash = ?",
                (datetime.now(UTC).isoformat(), h),
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
                (datetime.now(UTC).isoformat(), m["id"]),
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
              datetime.now(UTC).isoformat()))
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
            datetime.now(UTC).isoformat(),
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
    The unified cognitive engine of Hunter — a full human-like mind.

    Cognitive Architecture:
      PERCEPTION & ATTENTION
        - AttentionSystem: saliency detection, priority filtering, noise suppression
        - PatternRecognition: experience-based intuition, anomaly detection

      MEMORY SYSTEMS
        - WorkingMemory: short-term context (7±2 items, decays)
        - MistakeMemory: persistent long-term (mistakes, learnings, inventions)
        - MemoryConsolidation: promotes working → long-term

      REASONING & THINKING
        - ProbabilisticReasoning: P(success), confidence intervals
        - FutureInsight: consequence projection across time horizons
        - AbstractionEngine: cross-domain analogy mapping
        - ImaginationEngine: mental simulation, pre-mortem, counterfactuals
        - Metacognition: self-awareness, calibration, knowledge gaps

      LEARNING & GROWTH
        - CuriosityDrive: intrinsic motivation, learning goals
        - HabitFormation: automatic routines from repeated success
        - CognitiveBiasDetector: self-correction against thinking errors

      SOCIAL & EMOTIONAL
        - EmotionalIntelligence: frustration/excitement/urgency detection
        - SocialCognition: intent detection, expertise estimation, style adaptation
    """

    def __init__(self, db_path: str = None):
        # ── Memory Systems ──
        self.mistake_memory = MistakeMemory(db_path=db_path)
        self.working_memory = WorkingMemory(capacity=9, decay_seconds=300.0)
        self.consolidation = MemoryConsolidation()

        # ── Reasoning ──
        self.probability = ProbabilisticReasoning()
        self.future_insight = FutureInsight()
        self.abstraction = AbstractionEngine()
        self.imagination = ImaginationEngine()
        self.metacognition = Metacognition()

        # ── Perception ──
        self.attention = AttentionSystem()
        self.patterns = PatternRecognition()

        # ── Learning & Growth ──
        self.curiosity = CuriosityDrive()
        self.habits = HabitFormation()
        self.bias_detector = CognitiveBiasDetector()

        # ── Social & Emotional ──
        self.emotional_iq = EmotionalIntelligence()
        self.social = SocialCognition()

    def enhance_prompt(
        self,
        user_message: str,
        conversation_history: List[Dict[str, str]] = None,
    ) -> str:
        """
        Enhance a user message with Hunter's full cognitive framework.

        Runs the complete cognitive pipeline:
          1. Attention: What is salient in this input?
          2. Emotion: What is the user's emotional state?
          3. Social: What is the user's intent and expertise level?
          4. Domain detection + cross-domain synthesis
          5. Working memory: store context, recall relevant items
          6. Mistake memory: check for past errors
          7. Prior learnings: retrieve relevant knowledge
          8. Pattern intuition: any gut feelings?
          9. Metacognition: self-awareness check
          10. Bias check: are we reasoning cleanly?
          11. Curiosity: note any learning opportunities
          12. Habit check: any automatic responses?
          13. Compose enhanced prompt with all cognitive context
        """
        parts = []

        # ── 1. ATTENTION: What matters most in this input? ──
        saliency = self.attention.compute_saliency(user_message)
        if saliency["attention_level"] in ("maximum", "high"):
            top_triggers = [t["trigger"] for t in saliency["triggers"][:3]]
            parts.append(
                f"[ATTENTION: {saliency['attention_level'].upper()}] "
                f"Key triggers: {', '.join(top_triggers)}"
            )
            # Check if we should shift focus
            current_focus = self.working_memory.get_focus()
            should_shift, reason = self.attention.should_shift_attention(
                current_focus or "", user_message
            )
            if should_shift:
                self.working_memory.set_focus(top_triggers[0])

        # ── 2. EMOTIONAL CONTEXT ──
        emotion = self.emotional_iq.read_emotional_context(user_message)
        if emotion["dominant_emotion"] != "neutral":
            parts.append(f"[EMOTIONAL CONTEXT] {emotion['tone_guidance']}")

        # ── 3. SOCIAL COGNITION ──
        expertise = self.social.estimate_expertise(user_message, conversation_history)
        intent = self.social.detect_intent(user_message)
        parts.append(
            f"[USER CONTEXT] Expertise: {expertise['estimated_level']} | "
            f"Intent: {intent['primary_intent']} | "
            f"Style: {expertise['communication_guidance']}"
        )

        # ── 4. DOMAIN DETECTION ──
        domains = detect_domains(user_message)
        thinking_style = get_thinking_style(domains)
        domain_labels = [
            KNOWLEDGE_DOMAINS.get(d, {}).get("label", d) for d in domains
        ]
        parts.append(f"[DOMAINS] {', '.join(domain_labels)} | Style: {thinking_style}")

        # Cross-domain synthesis hint
        if len(domains) >= 2:
            parts.append(
                f"[CROSS-DOMAIN] Connect insights from "
                f"{domain_labels[0]} and {domain_labels[1]} — "
                f"look for non-obvious patterns that span both fields."
            )
            # Check for known analogies
            if len(domains) >= 2:
                analogy = self.abstraction.find_analogy(domains[0], domains[1])
                if analogy:
                    parts.append(f"[ANALOGY] {analogy}")

        # ── 5. WORKING MEMORY ──
        self.working_memory.store(
            f"query_{int(time.monotonic())}",
            user_message[:200],
            importance=saliency["max_saliency"] if saliency["max_saliency"] > 0 else 0.5,
        )
        self.working_memory.set_focus(
            " ".join(domain_labels[:2]) if domain_labels else "general"
        )
        active_memory = self.working_memory.recall_all()
        if len(active_memory) > 1:
            context_items = [m["key"] for m in active_memory[:3]]
            parts.append(f"[WORKING MEMORY] Active context: {len(active_memory)} items")

        # ── 6. MISTAKE MEMORY ──
        primary_domain = domains[0] if domains else "general"
        words = user_message.lower().split()
        keywords = [w for w in words if len(w) > 3][:10]
        topic = " ".join(keywords[:3])

        mistakes = self.mistake_memory.check_related_mistakes(
            primary_domain, topic=topic, keywords=keywords
        )
        mistake_section = self.mistake_memory.format_mistake_warnings(mistakes)
        if mistake_section:
            parts.append(mistake_section)

        # ── 7. PRIOR LEARNINGS ──
        learnings = self.mistake_memory.get_relevant_learnings(
            primary_domain, topic=topic
        )
        learning_section = self.mistake_memory.format_learnings(learnings)
        if learning_section:
            parts.append(learning_section)

        # ── 8. PATTERN INTUITION ──
        intuition = self.patterns.check_intuition("query", primary_domain)
        if intuition.get("seen_before"):
            parts.append(
                f"[INTUITION] {intuition['intuition']} "
                f"(seen {intuition['times_seen']}x, {intuition['success_rate']:.0%} success)"
            )

        # ── 9. METACOGNITION ──
        self_awareness = self.metacognition.format_self_awareness(user_message)
        if self_awareness:
            parts.append(self_awareness)
        gaps = self.metacognition.detect_knowledge_gaps(user_message, list(_DOMAIN_KEYWORDS.keys()))
        for gap in gaps[:2]:
            parts.append(f"[KNOWLEDGE GAP] {gap}")

        # ── 10. COGNITIVE BIAS CHECK ──
        # For complex queries, add bias awareness
        is_complex = (
            len(user_message) > 80
            or any(w in user_message.lower() for w in [
                "how", "why", "solve", "fix", "build", "create", "design",
                "analyze", "compare", "explain", "debug", "implement",
                "strategy", "plan", "approach", "best way", "optimize",
            ])
        )
        if is_complex:
            parts.append(self.bias_detector.generate_debiasing_prompt())

        # ── 11. ADVERSARIAL PROTOCOL (security queries) ──
        is_security = (
            primary_domain == "computer_science"
            and any(w in user_message.lower() for w in [
                "vuln", "exploit", "attack", "hack", "pentest", "scan", "target",
                "injection", "xss", "ssrf", "sqli", "bypass", "privilege", "auth",
                "security", "threat", "payload", "recon", "footprint", "cve",
            ])
        )
        if is_security:
            parts.append(
                "\n[ADVERSARIAL SIMULATION PROTOCOL]\n"
                "1. ATTACKER VIEW: What is the attacker's highest-probability path?\n"
                "2. KILL CHAIN: Which stage? (Recon→Weaponize→Deliver→Exploit→Persist→Pivot→Exfil)\n"
                "3. STRIDE: Apply S/T/R/I/D/E to the component under analysis.\n"
                "4. DETECTION GAP: What telemetry would a defender miss?\n"
                "5. BLAST RADIUS: What can the attacker do next?\n"
                "6. DEFENDER RESPONSE: What controls would stop this?"
            )

        # ── 12. HUNTER'S THINKING PROTOCOL ──
        if is_complex:
            parts.append(
                "\n[HUNTER'S THINKING PROTOCOL]\n"
                "1. Think through 2-3 approaches (including unconventional)\n"
                "2. Assign P(success) with reasoning (aim for ≥90%)\n"
                "3. Consider future consequences: immediate → short-term → long-term\n"
                "4. Identify top failure modes and mitigations\n"
                "5. State one assumption that, if false, invalidates your conclusion\n"
                "6. Final recommendation with confidence % and caveats"
            )

        # ── 13. CURIOSITY ──
        novelty = self.curiosity.assess_novelty(
            user_message, list(_DOMAIN_KEYWORDS.keys())
        )
        if novelty["curiosity_triggered"]:
            questions = self.curiosity.generate_questions(user_message, primary_domain)
            if questions:
                parts.append(
                    f"[CURIOSITY] Novel topic (score: {novelty['novelty_score']:.1f}) — "
                    f"self-questions: {'; '.join(questions[:2])}"
                )

        # ── 14. HABIT CHECK ──
        triggered_habits = self.habits.check_habits(user_message)
        for habit in triggered_habits[:2]:
            parts.append(f"[HABIT] Auto-apply: {habit['action']}")

        # ── 15. CONVERSATION CONTINUITY ──
        if conversation_history:
            parts.append("[CONVERSATION CONTINUITY]")
            recent = conversation_history[-6:]
            for msg in recent:
                role = "User" if msg["role"] == "user" else "Hunter"
                parts.append(f"{role}: {msg['content'][:300]}")
            parts.append("")

        # ── 16. MEMORY CONSOLIDATION (background) ──
        candidates = self.working_memory.get_consolidation_candidates()
        if candidates:
            consolidated = self.consolidation.select_for_consolidation(candidates)
            for item in consolidated[:2]:
                # Auto-record important items as learnings
                self.mistake_memory.record_learning(
                    domain=primary_domain,
                    insight=f"[consolidated] {str(item['content'])[:200]}",
                    topic=topic,
                    source="memory_consolidation",
                    confidence=item["importance"],
                )

        parts.append(f"\n[CURRENT QUERY]\nUser: {user_message}")

        return "\n".join(parts)

    # ── Delegation Methods ────────────────────────────────────

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

    def record_pattern(self, pattern_type: str, signature: str,
                       outcome: str, success: bool) -> None:
        """Record a pattern for intuition building."""
        self.patterns.record_pattern(pattern_type, signature, outcome, success)

    def record_habit(self, action: str, context: str, success: bool) -> Optional[str]:
        """Record an action for habit formation."""
        return self.habits.record_action(action, context, success)

    def log_competence(self, domain: str, topic: str, score: float) -> None:
        """Log a competence observation for metacognition."""
        self.metacognition.log_competence(domain, topic, score)

    def store_in_working_memory(self, key: str, content: Any,
                                importance: float = 0.5) -> None:
        """Store information in short-term working memory."""
        self.working_memory.store(key, content, importance)

    def imagine_scenario(self, action: str, context: str = "") -> Dict[str, Any]:
        """Mentally simulate a scenario before acting."""
        return self.imagination.simulate_scenario(action, context)

    def pre_mortem(self, plan: str) -> str:
        """Run a pre-mortem on a plan."""
        return self.imagination.pre_mortem(plan)

    def find_analogy(self, concept_a: str, concept_b: str) -> Optional[str]:
        """Find a cross-domain analogy."""
        return self.abstraction.find_analogy(concept_a, concept_b)

    def check_biases(self, reasoning: str) -> List[Dict[str, str]]:
        """Check reasoning for cognitive biases."""
        return self.bias_detector.scan_for_biases(reasoning)

    def read_emotion(self, text: str) -> Dict[str, Any]:
        """Read the emotional context of user input."""
        return self.emotional_iq.read_emotional_context(text)

    def detect_intent(self, text: str) -> Dict[str, Any]:
        """Detect what the user actually wants."""
        return self.social.detect_intent(text)

    def estimate_user_expertise(self, text: str) -> Dict[str, Any]:
        """Estimate user's technical expertise level."""
        return self.social.estimate_expertise(text)

    def add_learning_goal(self, topic: str, reason: str,
                          priority: float = 0.5) -> None:
        """Add a topic to Hunter's learning wishlist."""
        self.curiosity.add_learning_goal(topic, reason, priority)

    def stats(self) -> Dict[str, Any]:
        """Get Hunter's full cognitive statistics."""
        mem_stats = self.mistake_memory.stats()
        mem_stats["knowledge_domains"] = len(KNOWLEDGE_DOMAINS)
        mem_stats["total_sub_domains"] = sum(
            len(d["sub_domains"]) for d in KNOWLEDGE_DOMAINS.values()
        )
        mem_stats["working_memory"] = self.working_memory.summary()
        mem_stats["habits_formed"] = len(self.habits.get_habits())
        mem_stats["patterns_learned"] = len(self.patterns._patterns)
        mem_stats["learning_goals"] = len(self.curiosity.get_learning_goals())
        mem_stats["calibration"] = self.metacognition.check_calibration()
        return mem_stats

    def close(self):
        self.mistake_memory.close()
