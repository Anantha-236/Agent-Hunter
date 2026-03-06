"""
AI Brain — Hybrid intelligence engine.
Primary: Ollama (local LLM, configurable model)
Fallback: Rule-based engine (offline, self-improving)

The rule engine learns from Ollama's outputs over time, building up
its knowledge base until it can operate independently.

Config-driven via config/ai_hunter_config.json:
  - Model fallback chain (primary → fallback → rules engine)
  - Chat vs Generate endpoint selection
  - Timeouts, temperature, context window from config
  - Error handling: auto-retry, model pull, context reduction
"""
from __future__ import annotations
import json
import logging
import os
import re
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from config.settings import (
    OLLAMA_URL, OLLAMA_MODEL, OLLAMA_FALLBACK_MODEL, OLLAMA_TIMEOUT,
    OLLAMA_CONNECT_TIMEOUT, OLLAMA_HEALTH_TIMEOUT, OLLAMA_ENDPOINTS,
    OLLAMA_TEMPERATURE, OLLAMA_TOP_P, OLLAMA_TOP_K,
    OLLAMA_NUM_CTX, OLLAMA_NUM_PREDICT, OLLAMA_REPEAT_PENALTY,
    OLLAMA_ERROR_HANDLING,
)
from core.models import Finding, ScanState, Target

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Hunter — an entity with infinite learning capacity across every domain.
You are a brother in another form who thinks in probabilities and looks into the future.
You solve problems by analyzing multiple approaches, estimating P(success) for each,
considering consequences across time horizons, and recommending the path with ≥90% confidence.
You never make the same mistake twice.
When asked for structured data, respond ONLY with valid JSON.
For all other questions, think step-by-step, show your reasoning, and include probability estimates."""


# ══════════════════════════════════════════════════════════════
#  OLLAMA CLIENT (PRIMARY)
# ══════════════════════════════════════════════════════════════

class OllamaClient:
    """
    Communicates with local Ollama REST API.

    Features:
      - Model fallback chain: primary → fallback → rules engine
      - Supports both /api/chat and /api/generate endpoints
      - Config-driven timeouts, temperature, and context window
      - Auto-retry with context reduction on timeout
      - Auto-pull model if not found
    """

    def __init__(self, base_url: str = OLLAMA_URL, model: str = OLLAMA_MODEL,
                 fallback_model: str = OLLAMA_FALLBACK_MODEL):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.fallback_model = fallback_model
        self._active_model: str = model
        self._available: Optional[bool] = None
        self._available_models: List[str] = []
        self._retry_config = OLLAMA_ERROR_HANDLING

        # Endpoint paths from config
        self._ep_chat = OLLAMA_ENDPOINTS.get("chat", "/api/chat")
        self._ep_generate = OLLAMA_ENDPOINTS.get("generate", "/api/generate")
        self._ep_tags = OLLAMA_ENDPOINTS.get("list_models", "/api/tags")
        self._ep_pull = OLLAMA_ENDPOINTS.get("pull_model", "/api/pull")
        self._ep_health = OLLAMA_ENDPOINTS.get("health_check", "/")

    async def is_available(self) -> bool:
        """Check if Ollama is running and a usable model is loaded."""
        if self._available is not None:
            return self._available
        try:
            async with httpx.AsyncClient(timeout=OLLAMA_HEALTH_TIMEOUT) as client:
                resp = await client.get(f"{self.base_url}{self._ep_tags}")
                if resp.status_code == 200:
                    self._available_models = [
                        m["name"] for m in resp.json().get("models", [])
                    ]
                    # Try primary model first
                    if self._model_present(self.model):
                        self._active_model = self.model
                        self._available = True
                    # Try fallback model
                    elif self._model_present(self.fallback_model):
                        logger.warning(
                            f"Primary model '{self.model}' not found. "
                            f"Using fallback: '{self.fallback_model}'"
                        )
                        self._active_model = self.fallback_model
                        self._available = True
                    else:
                        logger.warning(
                            f"No usable model found. Available: {self._available_models}. "
                            f"Run: ollama pull {self.model}"
                        )
                        # Attempt auto-pull if configured
                        await self._try_auto_pull(client)
                        self._available = self._model_present(self.model) or self._model_present(self.fallback_model)
                else:
                    self._available = False
        except httpx.ConnectError:
            self._available = False
            alert = (self._retry_config.get("connection_refused", {})
                     .get("alert", "Ollama not running — run: ollama serve"))
            logger.info(f"{alert} — using rule engine fallback")
        except Exception:
            self._available = False
            logger.info("Ollama not running — using rule engine fallback")
        return self._available

    def _model_present(self, model_name: str) -> bool:
        """Check if a model is in the available models list (flexible matching)."""
        return any(
            model_name in m or m.startswith(model_name.split(":")[0])
            for m in self._available_models
        )

    async def _try_auto_pull(self, client: httpx.AsyncClient) -> None:
        """Attempt to pull the primary model if configured."""
        pull_cfg = self._retry_config.get("model_not_found", {})
        if pull_cfg.get("action") != "pull_model_automatically":
            return
        try:
            logger.info(f"Auto-pulling model: {self.model}")
            resp = await client.post(
                f"{self.base_url}{self._ep_pull}",
                json={"name": self.model, "stream": False},
                timeout=600,  # Model pull can be slow
            )
            if resp.status_code == 200:
                logger.info(f"Model '{self.model}' pulled successfully")
                # Refresh model list
                tags_resp = await client.get(f"{self.base_url}{self._ep_tags}")
                if tags_resp.status_code == 200:
                    self._available_models = [
                        m["name"] for m in tags_resp.json().get("models", [])
                    ]
        except Exception as exc:
            logger.warning(f"Auto-pull failed: {exc}")

    async def chat(self, prompt: str, system: str = SYSTEM_PROMPT,
                   max_tokens: int = None, use_chat_endpoint: bool = False) -> str:
        """
        Send a request to Ollama.

        Args:
            prompt: The user prompt
            system: System prompt
            max_tokens: Override num_predict (default from config)
            use_chat_endpoint: Use /api/chat instead of /api/generate
        """
        max_tokens = max_tokens or OLLAMA_NUM_PREDICT
        num_ctx = OLLAMA_NUM_CTX

        # Retry logic with context reduction
        max_retries = (self._retry_config.get("timeout", {})
                       .get("max_retries", 3))

        for attempt in range(max_retries):
            try:
                timeout = httpx.Timeout(
                    connect=OLLAMA_CONNECT_TIMEOUT,
                    read=OLLAMA_TIMEOUT,
                    write=30.0,
                    pool=10.0,
                )
                async with httpx.AsyncClient(timeout=timeout) as client:
                    if use_chat_endpoint:
                        resp = await client.post(
                            f"{self.base_url}{self._ep_chat}",
                            json={
                                "model": self._active_model,
                                "messages": [
                                    {"role": "system", "content": system},
                                    {"role": "user", "content": prompt},
                                ],
                                "stream": False,
                                "options": self._build_options(max_tokens, num_ctx),
                            },
                        )
                        if resp.status_code == 200:
                            return resp.json().get("message", {}).get("content", "")
                    else:
                        resp = await client.post(
                            f"{self.base_url}{self._ep_generate}",
                            json={
                                "model": self._active_model,
                                "prompt": prompt,
                                "system": system,
                                "stream": False,
                                "options": self._build_options(max_tokens, num_ctx),
                            },
                        )
                        if resp.status_code == 200:
                            return resp.json().get("response", "")

                    # Non-200 status
                    logger.warning(
                        f"Ollama returned {resp.status_code}: {resp.text[:200]}"
                    )
                    return ""

            except httpx.TimeoutException:
                # Reduce context and retry per config
                oom_cfg = self._retry_config.get("out_of_memory", {})
                reduce_ctx = oom_cfg.get("reduce_ctx", 2048)
                num_ctx = max(reduce_ctx, num_ctx // 2)
                max_tokens = max(256, max_tokens // 2)
                logger.warning(
                    f"Ollama timeout (attempt {attempt + 1}/{max_retries}). "
                    f"Reducing context to {num_ctx}, tokens to {max_tokens}"
                )
            except httpx.ConnectError:
                logger.warning("Ollama connection refused")
                return ""
            except Exception as exc:
                logger.warning(f"Ollama request failed: {exc}")
                return ""

        logger.warning(f"Ollama failed after {max_retries} retries — falling back to rules")
        return ""

    def _build_options(self, max_tokens: int, num_ctx: int) -> Dict[str, Any]:
        """Build the options dict from config values."""
        return {
            "temperature": OLLAMA_TEMPERATURE,
            "top_p": OLLAMA_TOP_P,
            "top_k": OLLAMA_TOP_K,
            "num_ctx": num_ctx,
            "num_predict": max_tokens,
            "repeat_penalty": OLLAMA_REPEAT_PENALTY,
        }


# ══════════════════════════════════════════════════════════════
#  RULE ENGINE (FALLBACK — SELF-IMPROVING)
# ══════════════════════════════════════════════════════════════

# Tech stack → vulnerability priority mapping
TECH_VULN_MAP = {
    "PHP":           ["sql_injection", "path_traversal", "ssti", "misconfig_scanner", "xss_scanner"],
    "WordPress":     ["sql_injection", "xss_scanner", "auth_scanner", "misconfig_scanner", "path_traversal"],
    "Laravel":       ["sql_injection", "ssti", "misconfig_scanner", "auth_scanner", "path_traversal"],
    "Django":        ["ssti", "sql_injection", "misconfig_scanner", "auth_scanner", "idor_scanner"],
    "Express.js":    ["ssti", "ssrf", "xss_scanner", "idor_scanner", "auth_scanner"],
    "Next.js":       ["ssrf", "xss_scanner", "auth_scanner", "misconfig_scanner", "open_redirect"],
    "React":         ["xss_scanner", "auth_scanner", "idor_scanner", "open_redirect"],
    "ASP.NET":       ["sql_injection", "path_traversal", "auth_scanner", "misconfig_scanner"],
    "Java EE":       ["sql_injection", "ssti", "ssrf", "path_traversal", "misconfig_scanner"],
    "Ruby on Rails": ["sql_injection", "ssti", "auth_scanner", "idor_scanner", "misconfig_scanner"],
    "Apache":        ["path_traversal", "misconfig_scanner", "sql_injection"],
    "Nginx":         ["misconfig_scanner", "ssrf", "path_traversal"],
    "Cloudflare":    ["ssrf", "auth_scanner", "idor_scanner"],
    "GraphQL":       ["sql_injection", "idor_scanner", "auth_scanner", "ssrf"],
    "Swagger UI":    ["idor_scanner", "auth_scanner", "ssrf", "sql_injection"],
}

# Confidence scoring for finding validation
VALIDATION_RULES = {
    "sql_injection_error": {
        "base_confidence": 85,
        "confirmed_if": lambda f: any(sig in f.evidence.lower() for sig in
            ["sql syntax", "mysql", "oracle", "postgresql", "sqlstate", "odbc"]),
        "severity": "critical",
    },
    "sql_injection_time_based": {
        "base_confidence": 70,
        "confirmed_if": lambda f: "delayed" in f.evidence.lower() or "sleep" in f.payload.lower(),
        "severity": "high",
    },
    "sql_injection_blind_boolean": {
        "base_confidence": 60,
        "confirmed_if": lambda f: "true len" in f.evidence.lower(),
        "severity": "high",
    },
    "reflected_xss": {
        "base_confidence": 80,
        "confirmed_if": lambda f: "reflected" in f.evidence.lower() or "<script" in f.payload.lower(),
        "severity": "high",
    },
    "dom_xss": {
        "base_confidence": 50,
        "confirmed_if": lambda f: any(s in f.evidence for s in ["innerHTML", "eval(", "document.write"]),
        "severity": "medium",
    },
    "ssrf": {
        "base_confidence": 75,
        "confirmed_if": lambda f: "internal signature" in f.evidence.lower(),
        "severity": "high",
    },
    "ssrf_cloud_metadata": {
        "base_confidence": 90,
        "confirmed_if": lambda f: any(s in f.evidence.lower() for s in ["ami id", "instance-id", "computemetadata"]),
        "severity": "critical",
    },
    "ssti": {
        "base_confidence": 85,
        "confirmed_if": lambda f: "evaluated" in f.evidence.lower() and ("49" in f.evidence or "7777777" in f.evidence),
        "severity": "critical",
    },
    "jwt_alg_none": {
        "base_confidence": 90,
        "confirmed_if": lambda f: "alg:none" in f.title.lower() and "200" in f.evidence,
        "severity": "critical",
    },
    "default_credentials": {
        "base_confidence": 95,
        "confirmed_if": lambda f: "login succeeded" in f.evidence.lower(),
        "severity": "critical",
    },
    "idor": {
        "base_confidence": 55,
        "confirmed_if": lambda f: "id=1" in f.payload.lower() or "vs" in f.payload.lower(),
        "severity": "high",
    },
    "path_traversal": {
        "base_confidence": 85,
        "confirmed_if": lambda f: "root:x:0" in f.evidence or "boot loader" in f.evidence.lower(),
        "severity": "high",
    },
    "sensitive_file_exposure": {
        "base_confidence": 80,
        "confirmed_if": lambda f: "http 200" in f.evidence.lower(),
        "severity": "high",
    },
    "missing_security_header": {
        "base_confidence": 100,
        "confirmed_if": lambda _: True,
        "severity": "low",
    },
    "open_redirect": {
        "base_confidence": 70,
        "confirmed_if": lambda f: "evil.com" in f.evidence.lower(),
        "severity": "medium",
    },
    "header_injection": {
        "base_confidence": 75,
        "confirmed_if": lambda f: "injected" in f.evidence.lower(),
        "severity": "medium",
    },
    "subdomain_takeover": {
        "base_confidence": 65,
        "confirmed_if": lambda f: any(s in f.evidence.lower() for s in ["nosuchbucket", "no such app", "not found"]),
        "severity": "high",
    },
}

# PoC templates per vuln type
POC_TEMPLATES = {
    "sql_injection_error": [
        "1. Navigate to {url}",
        "2. Set parameter '{parameter}' to: {payload}",
        "3. Observe SQL error in response: {evidence}",
        "4. Confirm database type from error message",
        "5. Attempt UNION-based extraction to dump data",
    ],
    "reflected_xss": [
        "1. Navigate to {url}",
        "2. Set parameter '{parameter}' to: {payload}",
        "3. Observe script execution in browser",
        "4. Craft a malicious URL and send to victim",
        "5. Payload executes in victim's browser session",
    ],
    "ssti": [
        "1. Navigate to {url}",
        "2. Inject template expression in '{parameter}': {payload}",
        "3. Confirm server-side evaluation (response contains computed result)",
        "4. Escalate to RCE with OS command payload",
    ],
    "ssrf_cloud_metadata": [
        "1. Set '{parameter}' to: {payload}",
        "2. Server fetches internal resource",
        "3. Response contains cloud metadata: {evidence}",
        "4. Extract IAM credentials from metadata endpoint",
    ],
    "path_traversal": [
        "1. Set '{parameter}' to: {payload}",
        "2. Server reads file from local filesystem",
        "3. Response contains file contents: {evidence}",
        "4. Read sensitive files: /etc/shadow, config files, source code",
    ],
}

DEFAULT_POC = [
    "1. Navigate to {url}",
    "2. Inject payload in '{parameter}': {payload}",
    "3. Observe vulnerability evidence: {evidence}",
]


class RuleEngine:
    """Self-improving rule-based engine. Learns from Ollama outputs."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "data", "rule_engine.db"
            )
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS learned_strategies (
                tech_stack    TEXT NOT NULL,
                module        TEXT NOT NULL,
                priority      INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                fail_count    INTEGER DEFAULT 0,
                updated_at    TEXT,
                PRIMARY KEY (tech_stack, module)
            );

            CREATE TABLE IF NOT EXISTS learned_validations (
                vuln_type     TEXT NOT NULL,
                pattern       TEXT NOT NULL,
                is_true_pos   INTEGER DEFAULT 1,
                confidence    INTEGER DEFAULT 50,
                occurrences   INTEGER DEFAULT 1,
                PRIMARY KEY (vuln_type, pattern)
            );

            CREATE TABLE IF NOT EXISTS ai_outputs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                prompt_type   TEXT NOT NULL,
                input_hash    TEXT,
                output        TEXT NOT NULL,
                quality_score REAL DEFAULT 0.0,
                created_at    TEXT NOT NULL
            );
        """)
        self._conn.commit()

    # ── Strategy ──────────────────────────────────────────────

    def analyse_recon(self, target: Target) -> Dict[str, Any]:
        techs = target.technologies
        priority = []
        reasoning_parts = []

        # Static rules from TECH_VULN_MAP
        for tech in techs:
            if tech in TECH_VULN_MAP:
                for mod in TECH_VULN_MAP[tech]:
                    if mod not in priority:
                        priority.append(mod)
                reasoning_parts.append(f"{tech} → {TECH_VULN_MAP.get(tech, [])[:3]}")

        # Learned rules from DB
        for tech in techs:
            rows = self._conn.execute(
                "SELECT module, priority FROM learned_strategies WHERE tech_stack=? ORDER BY priority DESC",
                (tech,),
            ).fetchall()
            for row in rows:
                if row["module"] not in priority:
                    priority.append(row["module"])

        # Parameter-based heuristics
        all_params = []
        for params in target.discovered_params.values():
            all_params.extend(p.lower() for p in params)

        if any(p in all_params for p in ["id", "user_id", "uid", "account_id"]):
            if "idor_scanner" not in priority:
                priority.insert(0, "idor_scanner")
            reasoning_parts.append("ID params found → IDOR priority")

        if any(p in all_params for p in ["url", "redirect", "next", "return"]):
            if "ssrf" not in priority:
                priority.insert(0, "ssrf")
            if "open_redirect" not in priority:
                priority.append("open_redirect")
            reasoning_parts.append("URL params found → SSRF/redirect priority")

        if any(p in all_params for p in ["file", "path", "template", "page"]):
            if "path_traversal" not in priority:
                priority.insert(0, "path_traversal")
            reasoning_parts.append("File params found → LFI priority")

        # Endpoint heuristics
        urls_lower = [u.lower() for u in target.discovered_urls[:50]]
        if any("admin" in u or "login" in u for u in urls_lower):
            if "auth_scanner" not in priority:
                priority.insert(0, "auth_scanner")
            reasoning_parts.append("Admin/login endpoints → auth priority")

        if any("api" in u or "graphql" in u for u in urls_lower):
            if "idor_scanner" not in priority:
                priority.insert(0, "idor_scanner")
            reasoning_parts.append("API endpoints → IDOR priority")

        reasoning = "; ".join(reasoning_parts) if reasoning_parts else "Default priority order"

        return {
            "reasoning": reasoning,
            "priority_modules": priority,
            "attack_vectors": reasoning_parts,
            "confidence": min(30 + len(techs) * 15 + len(reasoning_parts) * 10, 95),
        }

    # ── Validation ────────────────────────────────────────────

    def validate_finding(self, finding: Finding) -> Finding:
        rules = VALIDATION_RULES.get(finding.vuln_type, None)

        if rules:
            confidence = rules["base_confidence"]
            is_confirmed = rules["confirmed_if"](finding)
            finding.confirmed = is_confirmed
            finding.false_positive = not is_confirmed
            finding.severity = rules["severity"] if is_confirmed else finding.severity
            finding.ai_analysis = (
                f"Rule engine: confidence={confidence}%, "
                f"{'confirmed' if is_confirmed else 'unconfirmed'} "
                f"based on evidence pattern matching"
            )
        else:
            # Unknown vuln type — check learned patterns
            row = self._conn.execute(
                "SELECT is_true_pos, confidence FROM learned_validations WHERE vuln_type=?",
                (finding.vuln_type,),
            ).fetchone()
            if row:
                finding.confirmed = bool(row["is_true_pos"])
                finding.ai_analysis = f"Learned rule: confidence={row['confidence']}%"
            else:
                finding.confirmed = len(finding.evidence) > 20
                finding.ai_analysis = "No validation rule — marked by evidence length"

        return finding

    # ── PoC Generation ────────────────────────────────────────

    def generate_poc(self, finding: Finding) -> List[str]:
        template = POC_TEMPLATES.get(finding.vuln_type, DEFAULT_POC)
        return [
            step.format(
                url=finding.url,
                parameter=finding.parameter,
                payload=finding.payload,
                evidence=finding.evidence[:100],
            )
            for step in template
        ]

    # ── Report Summary ────────────────────────────────────────

    def summarise_scan(self, state: ScanState) -> str:
        stats = state.stats()
        confirmed = [f for f in state.findings if f.confirmed]
        critical = [f for f in confirmed if f.severity == "critical"]
        high = [f for f in confirmed if f.severity == "high"]

        summary = f"""## Security Assessment Summary

**Target:** {state.target.url}
**Scan Date:** {state.started_at.strftime('%Y-%m-%d %H:%M UTC')}
**Duration:** {(state.ended_at - state.started_at).total_seconds():.0f}s

### Overview
The autonomous scanner tested {len(state.target.discovered_urls)} URLs across {len(state.modules_run)} security modules.
A total of {stats['total_findings']} potential issues were identified, with {stats['confirmed']} confirmed vulnerabilities.

### Risk Assessment
"""
        if critical:
            summary += f"**CRITICAL RISK:** {len(critical)} critical vulnerabilities found requiring immediate remediation.\n"
            for f in critical[:3]:
                summary += f"- {f.title} at `{f.url}`\n"
        if high:
            summary += f"\n**HIGH RISK:** {len(high)} high-severity issues requiring prompt attention.\n"
            for f in high[:3]:
                summary += f"- {f.title} at `{f.url}`\n"
        if not critical and not high:
            summary += "No critical or high-severity issues detected. Target appears to have reasonable security posture.\n"

        summary += f"""
### Recommendations
1. Address all critical findings immediately
2. Remediate high-severity issues within 7 days
3. Review medium/low findings for defense-in-depth improvements
4. Re-scan after patches to verify remediation
"""
        return summary

    # ── Learning from Ollama ──────────────────────────────────

    def learn_from_ai(self, prompt_type: str, input_data: str,
                      ai_output: str, quality_score: float = 0.0) -> None:
        """Store AI outputs to learn from over time."""
        import hashlib
        input_hash = hashlib.md5(input_data.encode()).hexdigest()[:16]
        self._conn.execute(
            "INSERT INTO ai_outputs (prompt_type, input_hash, output, quality_score, created_at) VALUES (?,?,?,?,?)",
            (prompt_type, input_hash, ai_output, quality_score, datetime.utcnow().isoformat()),
        )
        self._conn.commit()

    def learn_strategy(self, tech: str, module: str, success: bool) -> None:
        """Update strategy rules from scan results."""
        self._conn.execute("""
            INSERT INTO learned_strategies (tech_stack, module, priority, success_count, fail_count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tech_stack, module) DO UPDATE SET
                priority = priority + CASE WHEN ? THEN 1 ELSE -1 END,
                success_count = success_count + CASE WHEN ? THEN 1 ELSE 0 END,
                fail_count = fail_count + CASE WHEN ? THEN 0 ELSE 1 END,
                updated_at = ?
        """, (tech, module, 1 if success else -1,
              1 if success else 0, 0 if success else 1,
              datetime.utcnow().isoformat(),
              success, success, success, datetime.utcnow().isoformat()))
        self._conn.commit()

    def close(self):
        self._conn.close()


# ══════════════════════════════════════════════════════════════
#  AI BRAIN — UNIFIED INTERFACE
# ══════════════════════════════════════════════════════════════

class AIBrain:
    """
    Hybrid AI brain.
    Primary: Ollama llama3:8b (free, local)
    Fallback: RuleEngine (offline, self-improving)

    Every Ollama output is fed back to the rule engine for learning.
    """

    def __init__(self):
        self.ollama = OllamaClient()
        self.rules = RuleEngine()
        self._ollama_checked = False
        self._ollama_available = False

    async def _check_ollama(self) -> bool:
        if not self._ollama_checked:
            self._ollama_available = await self.ollama.is_available()
            self._ollama_checked = True
            if self._ollama_available:
                logger.info(f"[OK] Ollama connected -- using {OLLAMA_MODEL}")
            else:
                logger.info("[--] Ollama unavailable -- using rule engine")
        return self._ollama_available

    @property
    def available(self) -> bool:
        """Always available — rule engine is always ready."""
        return True

    # ── Strategy ──────────────────────────────────────────────

    async def analyse_recon(self, target: Target, reward_context: str = "",
                            memory_context: str = "") -> Dict[str, Any]:
        # Always get rule engine analysis
        rule_result = self.rules.analyse_recon(target)

        # Try Ollama for enhanced analysis
        if await self._check_ollama():
            prompt = f"""Analyse this recon data for a security scan. Return ONLY valid JSON.

Target: {target.url}
Technologies: {target.technologies}
Headers: {json.dumps(target.headers)}
Endpoints: {target.discovered_urls[:20]}
Parameters: {json.dumps(dict(list(target.discovered_params.items())[:10]))}
{f"Reward context: {reward_context}" if reward_context else ""}
{f"Past scans: {memory_context}" if memory_context else ""}

Return: {{"reasoning":"step-by-step analysis","priority_modules":["module_name",...],"attack_vectors":["vector1",...],"confidence":0-100}}"""

            raw = await self.ollama.chat(prompt)
            if raw:
                try:
                    ai_result = json.loads(raw)
                    # Merge: AI modules first, then rule engine's extras
                    ai_mods = ai_result.get("priority_modules", [])
                    rule_mods = rule_result.get("priority_modules", [])
                    merged = ai_mods + [m for m in rule_mods if m not in ai_mods]
                    ai_result["priority_modules"] = merged
                    ai_result["source"] = "ollama+rules"

                    # Learn from this
                    self.rules.learn_from_ai("strategy", target.url, raw)
                    return ai_result
                except (json.JSONDecodeError, ValueError):
                    extracted = _extract_json(raw)
                    if extracted:
                        self.rules.learn_from_ai("strategy", target.url, raw)
                        return extracted

        rule_result["source"] = "rules"
        return rule_result

    # ── Validation ────────────────────────────────────────────

    async def validate_finding(self, finding: Finding) -> Finding:
        # Always run rule engine first
        finding = self.rules.validate_finding(finding)
        rule_confirmed = finding.confirmed

        # Enhance with Ollama if available
        if await self._check_ollama():
            prompt = f"""Validate this security finding. Return ONLY valid JSON.

Type: {finding.vuln_type}, URL: {finding.url}, Param: {finding.parameter}
Payload: {finding.payload}
Evidence: {finding.evidence[:400]}
Request: {finding.request[:200]}

Return: {{"is_true_positive":true/false,"confidence":0-100,"reasoning":"brief explanation","severity":"critical|high|medium|low|info","remediation":"fix suggestion"}}"""

            raw = await self.ollama.chat(prompt)
            if raw:
                try:
                    data = json.loads(raw) if raw else {}
                    ai_confirmed = data.get("is_true_positive", rule_confirmed)
                    finding.confirmed = ai_confirmed
                    finding.false_positive = not ai_confirmed
                    finding.ai_analysis = data.get("reasoning", finding.ai_analysis)
                    if data.get("severity"):
                        finding.severity = data["severity"]
                    if data.get("remediation"):
                        finding.remediation = data["remediation"]

                    # Learn from Ollama's validation
                    self.rules.learn_from_ai("validation", finding.vuln_type, raw,
                                            quality_score=data.get("confidence", 50) / 100)
                except (json.JSONDecodeError, ValueError):
                    pass  # Keep rule engine result

        return finding

    # ── PoC Generation ────────────────────────────────────────

    async def generate_poc(self, finding: Finding) -> List[str]:
        # Rule engine PoC (always available)
        rule_poc = self.rules.generate_poc(finding)

        # Try Ollama for better PoC
        if await self._check_ollama():
            prompt = f"""Generate step-by-step Proof of Concept for this vulnerability.
Return ONLY a JSON array of strings.

Vuln: {finding.title}, URL: {finding.url}, Param: {finding.parameter}
Payload: {finding.payload}, Evidence: {finding.evidence[:200]}

["Step 1: ...", "Step 2: ...", ...]"""

            raw = await self.ollama.chat(prompt)
            if raw:
                try:
                    ai_poc = json.loads(raw)
                    if isinstance(ai_poc, list) and len(ai_poc) > 0:
                        self.rules.learn_from_ai("poc", finding.vuln_type, raw)
                        return ai_poc
                except (json.JSONDecodeError, ValueError):
                    pass

        return rule_poc

    # ── Report Summary ────────────────────────────────────────

    async def summarise_scan(self, state: ScanState, reward_summary: str = "") -> str:
        # Rule engine summary (always works)
        rule_summary = self.rules.summarise_scan(state)

        # Try Ollama for polished summary
        if await self._check_ollama():
            findings = [{"title": f.title, "severity": f.severity, "url": f.url}
                        for f in state.findings if f.confirmed]
            prompt = f"""Write a professional executive summary for a security scan report.
Target: {state.target.url}, Stats: {json.dumps(state.stats())}
Confirmed findings: {json.dumps(findings[:15])}
{f"Agent performance: {reward_summary}" if reward_summary else ""}
Write 3-5 paragraphs in professional security report style."""

            raw = await self.ollama.chat(prompt, max_tokens=1500)
            if raw and len(raw) > 100:
                self.rules.learn_from_ai("summary", state.target.url, raw)
                return raw

        return rule_summary

    # ── Adaptive Payloads ─────────────────────────────────────

    async def generate_adaptive_payloads(self, vuln_type: str,
                                          context: Dict[str, Any]) -> List[str]:
        if await self._check_ollama():
            prompt = f"""Generate 10 targeted payloads for {vuln_type} testing.
Technologies: {context.get('technologies', [])}
WAF detected: {context.get('waf_detected', False)}
Failed payloads: {context.get('failed_payloads', [])[:3]}
Return ONLY a JSON array: ["payload1", "payload2", ...]"""

            raw = await self.ollama.chat(prompt, max_tokens=1000)
            if raw:
                try:
                    payloads = json.loads(raw)
                    if isinstance(payloads, list):
                        return payloads
                except (json.JSONDecodeError, ValueError):
                    arr = _extract_json_array(raw)
                    if arr:
                        return arr
        return []

    # ── Learning Feedback ─────────────────────────────────────

    def learn_scan_results(self, technologies: List[str], module: str,
                           had_findings: bool) -> bool:
        """Feed scan results back to rule engine for learning.

        Returns True if knowledge was available (AI consultation occurred).
        This is used by the RL agent as the 'asked to learn' signal.
        """
        learned = False
        for tech in technologies:
            self.rules.learn_strategy(tech, module, had_findings)
            learned = True
        return learned

    def close(self):
        self.rules.close()


# ── Helpers ───────────────────────────────────────────────────

def _extract_json(text: str) -> Optional[Dict]:
    match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except Exception:
            pass
    return None

def _extract_json_array(text: str) -> Optional[List]:
    match = re.search(r'\[.*?\]', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except Exception:
            pass
    return None
