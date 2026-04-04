"""Tests for Agent-Hunter AI Upgrade — Priorities 1-6.

All tests use mocked Ollama responses. No running Ollama instance required.

Key assertions:
  - chat_with_reasoning: pass-1 output appears VERBATIM in pass-2 prompt
  - reflect_on_scan: single call produces dual-destination JSON
  - get_relevant_ai_outputs: closes the self-learning read-back loop
  - to_ai_context: produces rich intelligence, not shallow stats
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timedelta
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Ensure project root on sys.path ─────────────────────────
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.memory import ScanMemory


# ═══════════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def tmp_db(tmp_path):
    """Return path to a temporary SQLite DB file."""
    return str(tmp_path / "test.db")


@pytest.fixture
def scan_memory(tmp_db):
    """ScanMemory backed by a temp DB."""
    mem = ScanMemory(db_path=tmp_db)
    return mem


@pytest.fixture
def rule_engine(tmp_db):
    """RuleEngine backed by a temp DB."""
    from core.Hunter_brain import RuleEngine
    return RuleEngine(db_path=tmp_db)


@pytest.fixture
def ollama_client():
    """OllamaClient with mocked httpx calls."""
    from core.Hunter_brain import OllamaClient
    client = OllamaClient()
    return client


@pytest.fixture
def ai_brain(tmp_db):
    """AIBrain with RuleEngine on temp DB."""
    from core.Hunter_brain import AIBrain
    brain = AIBrain()
    brain.rules = rule_engine_fixture(tmp_db)
    return brain


def rule_engine_fixture(db_path):
    from core.Hunter_brain import RuleEngine
    return RuleEngine(db_path=db_path)


# ═══════════════════════════════════════════════════════════════
#  PRIORITY 1: TWO-PASS CHAIN-OF-THOUGHT
# ═══════════════════════════════════════════════════════════════

class TestChatWithReasoning:
    """Verify the two-pass reasoning protocol."""

    @pytest.mark.asyncio
    async def test_pass1_output_in_pass2_prompt(self, ollama_client):
        """Pass-1 thinking output must appear VERBATIM in pass-2 prompt."""
        pass1_output = (
            "Step 1: The target runs PHP 5.6 with no WAF.\n"
            "Step 2: SQL injection on /listproducts.php?cat= has P(success)=0.85.\n"
            "Step 3: XSS is unlikely due to Content-Type: application/json.\n"
            "Risk: rate limiting may block blind SQLi."
        )
        pass2_output = json.dumps({
            "additional_modules": ["sqli_scanner"],
            "attack_vectors": ["SQL injection on cat parameter"],
            "detection_gaps": ["no CSP header"],
            "stride_flags": {},
        })

        call_count = 0
        captured_prompts = []

        async def mock_chat(prompt, system=None, max_tokens=None,
                            temperature=None, use_chat_endpoint=False):
            nonlocal call_count
            call_count += 1
            captured_prompts.append(prompt)
            if call_count == 1:
                return pass1_output  # thinking pass
            return pass2_output      # structure pass

        ollama_client.chat = mock_chat

        thinking, structured = await ollama_client.chat_with_reasoning(
            "Analyse target http://test.com"
        )

        assert call_count == 2, "Must make exactly 2 Ollama calls"
        assert thinking == pass1_output, "Thinking output must match pass-1 return"

        # Key assertion: pass-1 output appears VERBATIM in pass-2 prompt
        assert pass1_output in captured_prompts[1], (
            "Pass-1 thinking output must appear verbatim in the pass-2 prompt"
        )
        assert "ORIGINAL REQUEST" in captured_prompts[1]

    @pytest.mark.asyncio
    async def test_pass1_temperature_is_high(self, ollama_client):
        """Pass 1 should use temperature=0.7 for creative exploration."""
        temps = []

        async def mock_chat(prompt, system=None, max_tokens=None,
                            temperature=None, use_chat_endpoint=False):
            temps.append(temperature)
            return "thinking output"

        ollama_client.chat = mock_chat
        await ollama_client.chat_with_reasoning("test")

        assert temps[0] == 0.7, f"Pass-1 temperature should be 0.7, got {temps[0]}"
        assert temps[1] == 0.1, f"Pass-2 temperature should be 0.1, got {temps[1]}"

    @pytest.mark.asyncio
    async def test_graceful_failure_on_pass1_empty(self, ollama_client):
        """If pass 1 returns empty string, both outputs should be empty."""
        async def mock_chat(prompt, system=None, max_tokens=None,
                            temperature=None, use_chat_endpoint=False):
            return ""

        ollama_client.chat = mock_chat
        thinking, structured = await ollama_client.chat_with_reasoning("test")

        assert thinking == ""
        assert structured == ""

    @pytest.mark.asyncio
    async def test_temperature_threading_to_build_options(self, ollama_client):
        """Temperature parameter reaches _build_options correctly."""
        opts = ollama_client._build_options(256, 2048, temperature=0.3)
        assert opts["temperature"] == 0.3

        opts_default = ollama_client._build_options(256, 2048)
        # Should use the global OLLAMA_TEMPERATURE constant
        assert isinstance(opts_default["temperature"], (int, float))


# ═══════════════════════════════════════════════════════════════
#  PRIORITY 2: SELF-REFLECTION
# ═══════════════════════════════════════════════════════════════

class TestReflectOnScan:
    """Verify reflect_on_scan produces single-call dual-destination JSON."""

    @pytest.mark.asyncio
    async def test_reflection_json_structure(self, tmp_db):
        """reflect_on_scan must return all required keys."""
        from core.Hunter_brain import AIBrain

        reflection_json = json.dumps({
            "generalizable_lessons": [
                "PHP targets with old versions are highly susceptible to SQL injection"
            ],
            "generalizable_mistakes": [
                {"mistake": "Ran XXE scanner on non-XML target",
                 "correct": "Skip XXE when no XML content-type detected"}
            ],
            "target_waf_notes": "Cloudflare blocks standard union-based SQLi",
            "target_skip_modules": ["xxe_scanner"],
            "target_confirmed_paths": ["/listproducts.php?cat="],
        })

        brain = AIBrain()

        async def mock_reasoning(prompt, system=None, max_tokens=None):
            return ("Thinking about the scan...", reflection_json)

        brain.ollama.chat_with_reasoning = mock_reasoning
        brain._ollama_checked = True
        brain._ollama_available = True

        async def mock_check(force=False):
            return True
        brain._check_ollama = mock_check

        strategy = {"priority_modules": ["sqli_scanner", "xss_scanner"]}
        outcomes = {
            "total_findings": 3,
            "confirmed_findings": 2,
            "empty_modules": ["xxe_scanner"],
            "waf_detected": True,
            "waf_name": "Cloudflare",
            "target_url": "http://test.com",
            "technologies": ["PHP", "Apache"],
        }

        result = await brain.reflect_on_scan(strategy, outcomes, reward_summary="score=7.5")

        assert "generalizable_lessons" in result
        assert "generalizable_mistakes" in result
        assert "target_waf_notes" in result
        assert "target_skip_modules" in result
        assert "target_confirmed_paths" in result
        assert len(result["generalizable_lessons"]) == 1
        assert result["target_waf_notes"] == "Cloudflare blocks standard union-based SQLi"

    @pytest.mark.asyncio
    async def test_reflection_stores_thinking(self, tmp_db):
        """Reflection result should include _thinking from pass-1."""
        from core.Hunter_brain import AIBrain

        brain = AIBrain()
        thinking_text = "Analysing scan results step by step..."

        async def mock_reasoning(prompt, system=None, max_tokens=None):
            return (thinking_text, json.dumps({
                "generalizable_lessons": [],
                "generalizable_mistakes": [],
                "target_waf_notes": "",
                "target_skip_modules": [],
                "target_confirmed_paths": [],
            }))

        brain.ollama.chat_with_reasoning = mock_reasoning
        brain._ollama_checked = True
        brain._ollama_available = True

        async def mock_check(force=False):
            return True
        brain._check_ollama = mock_check

        result = await brain.reflect_on_scan({}, {}, reward_summary="")
        assert result["_thinking"] == thinking_text


# ═══════════════════════════════════════════════════════════════
#  PRIORITY 3: SELF-LEARNING READ-BACK
# ═══════════════════════════════════════════════════════════════

class TestSelfLearningReadBack:
    """Verify the learn → store → read-back loop."""

    def test_learn_from_ai_returns_row_id(self, rule_engine):
        """learn_from_ai must return the inserted row ID."""
        row_id = rule_engine.learn_from_ai(
            "strategy", "http://test.com",
            '{"modules": ["sqli"]}', quality_score=0.0
        )
        assert isinstance(row_id, int)
        assert row_id > 0

    def test_update_output_quality(self, rule_engine):
        """Quality score can be updated after scan results are known."""
        row_id = rule_engine.learn_from_ai(
            "strategy", "http://test.com", '{"test": true}', quality_score=0.0
        )
        rule_engine.update_output_quality(row_id, 0.85)

        # Verify update
        row = rule_engine._conn.execute(
            "SELECT quality_score FROM ai_outputs WHERE rowid = ?",
            (row_id,)
        ).fetchone()
        assert row is not None
        assert abs(row["quality_score"] - 0.85) < 0.01

    def test_get_relevant_ai_outputs_returns_high_quality(self, rule_engine):
        """Only outputs with quality_score > 0 should be returned."""
        # Low-quality output
        rule_engine.learn_from_ai("strategy", "t1", "bad output", quality_score=0.0)
        # High-quality output
        rule_engine.learn_from_ai("strategy", "t2", "good output", quality_score=0.8)
        # Different prompt type
        rule_engine.learn_from_ai("validation", "t3", "val output", quality_score=0.9)

        results = rule_engine.get_relevant_ai_outputs("strategy", limit=10)
        assert len(results) == 1, "Only 1 high-quality strategy output should be returned"
        assert results[0]["output"] == "good output"
        assert results[0]["quality_score"] == 0.8

    def test_get_learned_strategy_context_formats_correctly(self, rule_engine):
        """Learned strategies should produce human-readable context."""
        # Insert some strategy data
        rule_engine.learn_strategy("PHP", "sqli_scanner", success=True)
        rule_engine.learn_strategy("PHP", "sqli_scanner", success=True)
        rule_engine.learn_strategy("PHP", "xxe_scanner", success=False)

        ctx = rule_engine.get_learned_strategy_context(["PHP"])
        assert "LEARNED STRATEGY WEIGHTS" in ctx
        assert "sqli_scanner" in ctx
        assert "xxe_scanner" in ctx

    def test_get_learned_strategy_context_empty_for_unknown_tech(self, rule_engine):
        """Should return empty string for unknown tech stack."""
        ctx = rule_engine.get_learned_strategy_context(["Cobol"])
        assert ctx == ""


# ═══════════════════════════════════════════════════════════════
#  PRIORITY 6: RICHER MEMORY CONTEXT
# ═══════════════════════════════════════════════════════════════

class TestRichMemoryContext:
    """Verify enhanced to_ai_context produces actionable intelligence."""

    def _seed_scan_data(self, mem: ScanMemory, target: str = "http://test.vulnweb.com"):
        """Populate the DB with realistic scan data."""
        scan_id = "test-scan-001"
        mem.start_scan(scan_id, target)

        from core.models import Finding
        findings = [
            Finding(
                title="SQL Injection in cat param",
                vuln_type="sql_injection",
                url="http://test.vulnweb.com/listproducts.php",
                parameter="cat",
                payload="' OR 1=1--",
                evidence="error in your SQL syntax",
                severity="high",
                confirmed=True,
                module="sqli_scanner",
            ),
            Finding(
                title="XSS in search",
                vuln_type="xss_reflected",
                url="http://test.vulnweb.com/search.php",
                parameter="searchFor",
                payload="<script>alert(1)</script>",
                evidence="<script>alert(1)</script>",
                severity="medium",
                confirmed=True,
                module="xss_scanner",
            ),
        ]
        mem.store_findings(scan_id, findings)
        mem.finish_scan(scan_id, {
            "total_findings": 2,
            "modules_run": ["sqli_scanner", "xss_scanner", "xxe_scanner"],
        })

        # Add a reflection
        mem.store_reflection(scan_id, target, "waf_bypass",
                             "Standard union-based blocked; use blind timing instead")
        mem.store_reflection(scan_id, target, "module_skip", "xxe_scanner")

    def test_to_ai_context_contains_confirmed_findings(self, scan_memory):
        """Context should include details about confirmed vulns."""
        self._seed_scan_data(scan_memory)
        ctx = scan_memory.to_ai_context("http://test.vulnweb.com")

        assert "PAST INTELLIGENCE" in ctx
        assert "sql_injection" in ctx
        assert "cat" in ctx

    def test_to_ai_context_contains_reflections(self, scan_memory):
        """Context should include past reflections."""
        self._seed_scan_data(scan_memory)
        ctx = scan_memory.to_ai_context("http://test.vulnweb.com")

        assert "waf_bypass" in ctx
        assert "blind timing" in ctx

    def test_to_ai_context_no_data(self, scan_memory):
        """No previous scans should return a clean message."""
        ctx = scan_memory.to_ai_context("http://unknown.com")
        assert "No previous scan data" in ctx

    def test_store_reflection_typed_rows(self, scan_memory):
        """Reflections should be queryable by type."""
        scan_memory.start_scan("s1", "http://test.com")
        scan_memory.store_reflection("s1", "http://test.com",
                                     "waf_bypass", "Use double-URL encoding")
        scan_memory.store_reflection("s1", "http://test.com",
                                     "module_skip", "xxe_scanner")
        scan_memory.store_reflection("s1", "http://test.com",
                                     "confirmed_path", "/login endpoint with admin param")

        waf = scan_memory.get_reflections("http://test.com", reflection_type="waf_bypass")
        assert len(waf) == 1
        assert waf[0]["content"] == "Use double-URL encoding"

        skips = scan_memory.get_reflections("http://test.com", reflection_type="module_skip")
        assert len(skips) == 1

        all_refs = scan_memory.get_reflections("http://test.com")
        assert len(all_refs) == 3

    def test_get_injectable_params(self, scan_memory):
        """Should return distinct confirmed injectable parameters."""
        self._seed_scan_data(scan_memory)
        params = scan_memory.get_injectable_params("http://test.vulnweb.com")
        assert "cat" in params
        assert "searchFor" in params

    def test_get_empty_modules(self, scan_memory):
        """Modules with zero confirmed findings should be flagged."""
        self._seed_scan_data(scan_memory)
        empty = scan_memory.get_empty_modules("http://test.vulnweb.com")
        empty_names = [m["module"] for m in empty]
        assert "xxe_scanner" in empty_names

    def test_get_relevant_reflections_prefers_recent_and_high_signal(self, scan_memory):
        """Relevance ranking should favor fresher, higher-signal reflections."""
        scan_memory.start_scan("s-rank", "http://test.com")
        scan_memory.store_reflection(
            "s-rank", "http://test.com", "module_skip", "legacy skip note"
        )
        scan_memory.store_reflection(
            "s-rank", "http://test.com", "waf_bypass", "waf bypass on cloudflare edge"
        )

        old_ts = (datetime.utcnow() - timedelta(days=95)).isoformat()
        scan_memory._conn.execute(
            "UPDATE scan_reflections SET created_at = ? WHERE content = ?",
            (old_ts, "legacy skip note"),
        )
        scan_memory._conn.commit()

        ranked = scan_memory.get_relevant_reflections(
            "http://test.com", technologies=["cloudflare"], limit=2
        )

        assert len(ranked) == 2
        assert ranked[0]["content"] == "waf bypass on cloudflare edge"
        assert ranked[0]["relevance_score"] >= ranked[1]["relevance_score"]

    def test_to_ai_context_adds_freshness_note_for_stale_memories(self, scan_memory):
        """AI context should warn when recalled reflections are stale."""
        self._seed_scan_data(scan_memory)

        old_ts = (datetime.utcnow() - timedelta(days=45)).isoformat()
        scan_memory._conn.execute(
            "UPDATE scan_reflections SET created_at = ? WHERE reflection_type = ?",
            (old_ts, "module_skip"),
        )
        scan_memory._conn.commit()

        ctx = scan_memory.to_ai_context("http://test.vulnweb.com")
        assert "Freshness note" in ctx


# ═══════════════════════════════════════════════════════════════
#  INTEGRATION: FULL LOOP
# ═══════════════════════════════════════════════════════════════

class TestFullLoop:
    """End-to-end: strategy → scan → reflect → read-back."""

    @pytest.mark.asyncio
    async def test_strategy_includes_learned_context(self, tmp_db):
        """analyse_recon should include learned strategy context in the prompt."""
        from core.Hunter_brain import AIBrain
        from core.models import Target

        brain = AIBrain()
        brain.rules = rule_engine_fixture(tmp_db)
        # Lower threshold so the rule engine (confidence=80) doesn't skip LLM
        brain.LLM_SKIP_CONFIDENCE = 95

        # Seed: PHP + sqli_scanner historically succeeds
        brain.rules.learn_strategy("PHP", "sqli_scanner", success=True)
        brain.rules.learn_strategy("PHP", "sqli_scanner", success=True)

        captured_prompts = []

        async def mock_reasoning(prompt, system=None, max_tokens=None):
            captured_prompts.append(prompt)
            return ("thinking...", json.dumps({
                "additional_modules": [],
                "attack_vectors": [],
                "detection_gaps": [],
                "stride_flags": {},
            }))

        brain.ollama.chat_with_reasoning = mock_reasoning
        brain._ollama_checked = True
        brain._ollama_available = True

        async def mock_check(force=False):
            return True
        brain._check_ollama = mock_check

        target = Target(url="http://test.com")
        target.technologies = ["PHP", "Apache"]
        target.headers = {}
        target.discovered_urls = ["/index.php"]
        target.discovered_params = {"cat": ["1"]}

        result = await brain.analyse_recon(target)

        # The prompt should contain learned strategy weights
        assert len(captured_prompts) > 0
        assert "LEARNED STRATEGY WEIGHTS" in captured_prompts[0]
        assert "sqli_scanner" in captured_prompts[0]
        assert result.get("source") == "rules+llm_reasoning"
