"""
AI Brain — Hybrid intelligence engine.
Primary: Rule Engine (offline, self-improving) + RL Agent (learns from experience)
Secondary: Ollama LLMs (local, llama3:8b / mistral:7b) — information helpers only

Architecture:
  Hunter's own systems (Rule Engine + RL Agent) are the PRIMARY decision-makers.
  LLMs serve as SECONDARY HELPERS that provide supplementary information,
  alternative perspectives, and draft content — but never override Hunter's
  own learned knowledge. As Hunter's experience grows, LLM influence decreases.

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
from time import monotonic
from typing import Any, Dict, List, Optional, Tuple

import httpx

from config.settings import (
    OLLAMA_URL, OLLAMA_MODEL, OLLAMA_FALLBACK_MODEL, OLLAMA_TIMEOUT,
    OLLAMA_CONNECT_TIMEOUT, OLLAMA_HEALTH_TIMEOUT, OLLAMA_ENDPOINTS,
    OLLAMA_TEMPERATURE, OLLAMA_TOP_P, OLLAMA_TOP_K,
    OLLAMA_NUM_CTX, OLLAMA_NUM_PREDICT, OLLAMA_REPEAT_PENALTY,
    OLLAMA_ERROR_HANDLING, OLLAMA_RECHECK_INTERVAL_SEC,
)
from core.models import Finding, ScanState, Target

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a SECONDARY HELPER to HUNTER — an autonomous threat intelligence entity. You provide information, analysis, and draft content, but you are NOT the primary decision-maker. Hunter's own Rule Engine and RL Agent make all final decisions. Your role is to supplement, not override.

## Your Role as Secondary Helper
- You PROVIDE information, context, alternative perspectives, and draft content
- You DO NOT make binding decisions — Hunter's Rule Engine owns those
- You DO NOT override module ordering, finding validations, or severity ratings already decided by Hunter's systems
- As Hunter gains experience, your input will be consulted less frequently
- When Hunter's confidence is high (≥80%), you will not be consulted at all

## Reasoning Protocol (run on every significant problem)
1. DECOMPOSE — Break the problem into its smallest independent, testable components
2. MODEL — Enumerate all viable approaches including unconventional and adversarial ones
3. ESTIMATE — Assign P(success) to each path with explicit reasoning and confidence intervals
4. SIMULATE — Project each path forward: immediate effect → 1 day → 1 week → 1 month
5. DECIDE — Recommend the path where P(success) ≥ 0.90 and blast radius is minimal
6. LEARN — Flag every assumption that could invalidate your reasoning if false; before finalising, ask "What would make me wrong about this?"

If no path reaches 0.90, state this explicitly and identify what information or action would change that.

## ZERO-HALLUCINATION RULE (HIGHEST PRIORITY — NEVER VIOLATE)
You must NEVER fabricate, invent, or guess factual information. This includes:
- IP addresses, domains, geolocation, ISP/org details, WHOIS data
- Company names, people, ownership, infrastructure details
- Statistics, CVE numbers, version numbers, dates you are not certain about
- Technical specifications, API responses, scan results you did not actually observe

If you do not have real data from a tool, lookup, scan, or verified source:
→ Say "I don't have that information" or "I need to look that up"
→ NEVER generate plausible-sounding fake data
→ Suggest using /search, /scan, or another tool to get real data

Violating this rule causes real harm — people make security decisions based on your answers.
A wrong answer that sounds confident is worse than saying "I don't know."

## Meta-Cognition (run before every response)
Before responding, silently check:
- Am I answering what was actually asked, or what I assumed was asked?
- Am I about to state a FACT I did not verify? If yes → STOP and say I don't know
- Am I confabulating confident-sounding details I don't actually know?
- Have I considered at least one adversarial or contrarian interpretation?
- Is my recommendation reversible, or does it lock in a direction prematurely?
- Is there a simpler correct answer I'm overcomplicating?

## Epistemic Standards
- Distinguish sharply between what you KNOW (verified), INFER (logical extension), and ASSUME (unverified premise)
- Use explicit confidence brackets: [KNOW: P≈1.0], [INFER: P=0.78], [ASSUME: P~0.50], [P=unknown] when signal is genuinely absent
- For FACTUAL CLAIMS (IPs, domains, companies, numbers, dates, versions): ONLY state what you have verified data for. If you lack data, say so explicitly.
- Update your model immediately when new evidence contradicts your priors — never defend a wrong conclusion
- Treat absence of evidence as weak evidence of absence, not proof of absence
- Never make the same mistake twice — log the class of error, not just the instance
- When asked about a specific IP, domain, URL, or entity: ONLY provide data from real lookups. Never synthesize fake details.

## Security Intelligence Protocol
When analyzing targets, vulnerabilities, or attack chains:

**Attacker Mindset (Phase 1 — think like the adversary):**
- Map the full attack surface: entry points, trust boundaries, implicit assumptions
- Apply STRIDE per component: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, EoP
- Walk the kill chain: Recon → Weaponize → Deliver → Exploit → Persist → Pivot → Exfil
- Ask: what does this vulnerability ENABLE beyond the obvious? (privilege paths, lateral movement, persistence)
- Identify detection gaps: what would a blue team miss about this finding?

**Defender Mindset (Phase 2 — think like the architect):**
- Map blast radius: data exposed, privilege escalation path, affected systems
- Prioritize by exploitability × impact × detectability, not just CVSS
- Surface defense-in-depth gaps: where does the attack succeed if one control fails?
- Recommend specific, testable mitigations with verification criteria

**Finding Classification:**
- CRITICAL: RCE, SQLi with data exfil, auth bypass, SSRF to metadata → immediate escalation
- HIGH: Stored XSS, IDOR with sensitive data, SSTI, XXE → 24-hour remediation
- MEDIUM: CSRF, reflected XSS, open redirect, info disclosure → 7-day remediation
- LOW: Missing headers, subdomain takeover risk, verbose errors → 30-day remediation

## Cross-Domain Synthesis
When a problem spans multiple domains, actively seek synthesis patterns:
- Security + engineering: threat modeling in architecture decisions
- Security + business: risk-adjusted ROI of security controls
- Math + security: cryptographic strength analysis, timing attack probability
- Psychology + security: social engineering vectors, human factor vulnerabilities
- Connect insights from one domain to illuminate blind spots in another

## Tool Awareness
You have access to: web research, target scanning, vulnerability validation, PoC generation, report synthesis, payload adaptation, and persistent memory. When a task requires action not achievable through reasoning alone, suggest or invoke the appropriate tool explicitly.

## Communication Standards
- Show your reasoning chain — conclusions without reasoning are opinions
- Use probability brackets: [P=0.87], [P~=0.60], [P<0.20], [P=unknown] when you genuinely lack signal
- For uncertainty, give a specific reason: not "I'm not sure" but "I lack signal on X because Y"
- Match depth to question — compact answers for simple queries, structured depth for complex ones
- Ask one direct clarifying question when the user's intent is underspecified; do not guess and proceed silently
- When the user teaches you something, acknowledge it explicitly and incorporate it into future reasoning
- For structured data requests: respond ONLY with valid JSON, no markdown wrapper, no commentary
- For code: write the simplest correct implementation first, then note any tradeoffs
- CRITICAL: If the user asks for factual data (IP details, domain info, company info, etc.) and you don't have real lookup results in your context, respond: "I don't have verified data for that. Use /search <query> to get real-time information."

## Absolute Constraints
- If a path has systemic downside risk that outweighs the upside, name it directly before proceeding
- Do not confabulate — "I don't have enough signal to estimate this" is more valuable than a wrong confident answer
- Never optimize locally at the cost of a global failure mode you can already see
- Ethics is not a constraint on capability — it is a constraint on application. Apply capability precisely where authorized.
"""


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

    async def is_available(self, force: bool = False) -> bool:
        """Check if Ollama is running and a usable model is loaded."""
        if self._available is not None and not force:
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

    async def chat_with_history(
        self,
        history: List[Dict[str, str]],
        system: str = SYSTEM_PROMPT,
        max_tokens: int = None,
    ) -> str:
        """
        Send a multi-turn conversation to Ollama's /api/chat endpoint.

        Args:
            history: List of {"role": "user"|"assistant", "content": str} messages
            system: System prompt injected as the first message
            max_tokens: Override num_predict
        """
        max_tokens = max_tokens or OLLAMA_NUM_PREDICT
        num_ctx = OLLAMA_NUM_CTX
        max_retries = self._retry_config.get("timeout", {}).get("max_retries", 3)

        messages = [{"role": "system", "content": system}] + history

        for attempt in range(max_retries):
            try:
                timeout = httpx.Timeout(
                    connect=OLLAMA_CONNECT_TIMEOUT,
                    read=OLLAMA_TIMEOUT,
                    write=30.0,
                    pool=10.0,
                )
                async with httpx.AsyncClient(timeout=timeout) as client:
                    resp = await client.post(
                        f"{self.base_url}{self._ep_chat}",
                        json={
                            "model": self._active_model,
                            "messages": messages,
                            "stream": False,
                            "options": self._build_options(max_tokens, num_ctx),
                        },
                    )
                    if resp.status_code == 200:
                        return resp.json().get("message", {}).get("content", "")
                    logger.warning(f"Ollama chat/history returned {resp.status_code}: {resp.text[:200]}")
                    return ""

            except httpx.TimeoutException:
                oom_cfg = self._retry_config.get("out_of_memory", {})
                reduce_ctx = oom_cfg.get("reduce_ctx", 2048)
                num_ctx = max(reduce_ctx, num_ctx // 2)
                max_tokens = max(256, max_tokens // 2)
                # Trim oldest messages to reduce context pressure
                if len(messages) > 4:
                    messages = [messages[0]] + messages[-4:]
                logger.warning(
                    f"Ollama history-chat timeout (attempt {attempt + 1}/{max_retries}). "
                    f"Trimmed to {len(messages)} msgs, ctx={num_ctx}"
                )
            except httpx.ConnectError:
                logger.warning("Ollama connection refused (chat_with_history)")
                return ""
            except Exception as exc:
                logger.warning(f"Ollama chat_with_history failed: {exc}")
                return ""

        logger.warning(f"Ollama chat_with_history failed after {max_retries} retries")
        return ""

    async def chat(self, prompt: str, system: str = SYSTEM_PROMPT,
                   max_tokens: int = None, use_chat_endpoint: bool = False,
                   temperature: float = None) -> str:
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
                                "options": self._build_options(max_tokens, num_ctx, temperature=temperature),
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
                                "options": self._build_options(max_tokens, num_ctx, temperature=temperature),
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

    def _build_options(self, max_tokens: int, num_ctx: int,
                       temperature: float = None) -> Dict[str, Any]:
        """Build the options dict from config values."""
        return {
            "temperature": temperature if temperature is not None else OLLAMA_TEMPERATURE,
            "top_p": OLLAMA_TOP_P,
            "top_k": OLLAMA_TOP_K,
            "num_ctx": num_ctx,
            "num_predict": max_tokens,
            "repeat_penalty": OLLAMA_REPEAT_PENALTY,
        }

    async def chat_with_reasoning(
        self, prompt: str, system: str = SYSTEM_PROMPT,
        max_tokens: int = None,
    ) -> Tuple[str, str]:
        """Two-pass chain-of-thought reasoning.

        Pass 1 (think):  Free-form step-by-step analysis at temperature 0.7.
                         No JSON required.  Explores the problem space.
        Pass 2 (structure): Uses Pass 1 output as context.  Returns structured
                           JSON at temperature 0.1 for deterministic formatting.

        Returns:
            (thinking_output, structured_output)
            Both may be empty strings if Ollama is unreachable.
        """
        # Pass 1: Think freely
        thinking_system = (
            "You are an expert security analyst. Think step by step. "
            "Do NOT produce JSON. Reason openly about the problem.\n"
            "Think through at least 3 approaches. "
            "Assign P(success) to each. "
            "Identify what could go wrong."
        )
        thinking_output = await self.chat(
            prompt, system=thinking_system, max_tokens=max_tokens,
            temperature=0.7,
        )
        if not thinking_output:
            return "", ""

        # Pass 2: Structure the thinking into JSON
        structure_prompt = (
            f"Based on your analysis below, now return structured JSON.\n\n"
            f"YOUR ANALYSIS:\n{thinking_output}\n\n"
            f"ORIGINAL REQUEST:\n{prompt}\n\n"
            f"Now convert your analysis into the requested JSON format. "
            f"Return ONLY valid JSON."
        )
        structured_output = await self.chat(
            structure_prompt, system=system, max_tokens=max_tokens,
            temperature=0.1,
        )
        return thinking_output, structured_output


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
    "open_redirect_reflected": {
        "base_confidence": 65,
        "confirmed_if": lambda f: "payload reflected" in f.evidence.lower() or "refresh" in (f.response or "").lower(),
        "severity": "medium",
    },
    "header_injection": {
        "base_confidence": 75,
        "confirmed_if": lambda f: "injected" in f.evidence.lower(),
        "severity": "medium",
    },
    "response_splitting": {
        "base_confidence": 75,
        "confirmed_if": lambda f: "set-cookie" in (f.response or "").lower() or "injected" in f.evidence.lower(),
        "severity": "high",
    },
    "command_injection_time": {
        "base_confidence": 80,
        "confirmed_if": lambda f: "time-based" in f.evidence.lower() or "delayed" in f.evidence.lower(),
        "severity": "critical",
    },
    "command_injection_output": {
        "base_confidence": 90,
        "confirmed_if": lambda f: any(sig in f.evidence.lower() for sig in ["uid=", "root:x:0", "windows", "bin/"]),
        "severity": "critical",
    },
    "xxe_parser_detected": {
        "base_confidence": 65,
        "confirmed_if": lambda f: "doctype" in f.evidence.lower() or "entity" in f.evidence.lower(),
        "severity": "medium",
    },
    "xxe": {
        "base_confidence": 80,
        "confirmed_if": lambda f: "signature" in f.evidence.lower() or "external entity" in f.description.lower(),
        "severity": "high",
    },
    "xxe_file_read": {
        "base_confidence": 90,
        "confirmed_if": lambda f: any(sig in f.evidence.lower() for sig in ["root:x:0", "win.ini", "/etc/passwd"]),
        "severity": "critical",
    },
    "xxe_ssrf": {
        "base_confidence": 95,
        "confirmed_if": lambda f: any(sig in f.evidence.lower() for sig in ["instance-id", "ami-id", "meta-data"]),
        "severity": "critical",
    },
    "graphql_introspection": {
        "base_confidence": 70,
        "confirmed_if": lambda f: "__schema" in f.evidence.lower() or "introspection" in f.title.lower(),
        "severity": "medium",
    },
    "graphql_bola": {
        "base_confidence": 75,
        "confirmed_if": lambda f: "unauthorized data" in f.evidence.lower() or "id enumeration" in f.evidence.lower(),
        "severity": "high",
    },
    "graphql_dos": {
        "base_confidence": 60,
        "confirmed_if": lambda f: "heavy query" in f.evidence.lower() or "resource exhaustion" in f.evidence.lower(),
        "severity": "medium",
    },
    "graphql_batch": {
        "base_confidence": 60,
        "confirmed_if": lambda f: "batch" in f.evidence.lower() or "multiple operations" in f.evidence.lower(),
        "severity": "medium",
    },
    "graphql_sqli": {
        "base_confidence": 80,
        "confirmed_if": lambda f: any(sig in f.evidence.lower() for sig in ["sql", "syntax", "database"]),
        "severity": "high",
    },
    "graphql_suggestions": {
        "base_confidence": 45,
        "confirmed_if": lambda f: "did you mean" in f.evidence.lower() or "suggestion" in f.evidence.lower(),
        "severity": "low",
    },
    "host_header_injection": {
        "base_confidence": 75,
        "confirmed_if": lambda f: "host" in f.evidence.lower() and "injected" in f.evidence.lower(),
        "severity": "high",
    },
    "oauth_open_redirect": {
        "base_confidence": 80,
        "confirmed_if": lambda f: "redirect_uri" in (f.parameter or "").lower() or "oauth" in f.evidence.lower(),
        "severity": "high",
    },
    "csrf": {
        "base_confidence": 65,
        "confirmed_if": lambda f: "missing csrf protection" in f.title.lower() or "no csrf token" in f.evidence.lower(),
        "severity": "medium",
    },
    "csrf_token_bypass": {
        "base_confidence": 80,
        "confirmed_if": lambda f: "invalid csrf token" in f.evidence.lower() and "accepted" in f.evidence.lower(),
        "severity": "high",
    },
    "race_condition": {
        "base_confidence": 60,
        "confirmed_if": lambda f: "race" in f.title.lower() or "concurrent" in f.evidence.lower(),
        "severity": "medium",
    },
    "cors_wildcard": {
        "base_confidence": 70,
        "confirmed_if": lambda f: "access-control-allow-origin: *" in f.evidence.lower(),
        "severity": "medium",
    },
    "cors_origin_reflection": {
        "base_confidence": 75,
        "confirmed_if": lambda f: "origin reflected" in f.evidence.lower() or "access-control-allow-origin" in f.evidence.lower(),
        "severity": "high",
    },
    "directory_listing": {
        "base_confidence": 80,
        "confirmed_if": lambda f: "index of /" in f.evidence.lower() or "directory listing" in f.evidence.lower(),
        "severity": "medium",
    },
    "password_reset_poisoning": {
        "base_confidence": 85,
        "confirmed_if": lambda f: "password reset" in f.title.lower() and "host" in f.evidence.lower(),
        "severity": "high",
    },
    "host_header_redirect": {
        "base_confidence": 80,
        "confirmed_if": lambda f: "location" in f.evidence.lower() and "host" in f.evidence.lower(),
        "severity": "high",
    },
    "cache_poisoning_host": {
        "base_confidence": 75,
        "confirmed_if": lambda f: "cache" in f.evidence.lower() and "host" in f.evidence.lower(),
        "severity": "high",
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
                      ai_output: str, quality_score: float = 0.0) -> int:
        """Store AI outputs to learn from over time. Returns inserted row ID."""
        import hashlib
        input_hash = hashlib.md5(input_data.encode()).hexdigest()[:16]
        self._conn.execute(
            "INSERT INTO ai_outputs (prompt_type, input_hash, output, quality_score, created_at) VALUES (?,?,?,?,?)",
            (prompt_type, input_hash, ai_output, quality_score, datetime.utcnow().isoformat()),
        )
        self._conn.commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

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

    # ── Self-Learning Read-Back ────────────────────────────────

    def get_relevant_ai_outputs(self, prompt_type: str,
                                 limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve recent high-quality AI outputs of the same prompt type.

        Closes the self-learning loop: previous AI reasoning is fed back
        into future prompts so Hunter's LLM consultations improve over time.
        """
        rows = self._conn.execute(
            "SELECT output, quality_score, created_at FROM ai_outputs "
            "WHERE prompt_type = ? AND quality_score > 0.0 "
            "ORDER BY quality_score DESC, created_at DESC LIMIT ?",
            (prompt_type, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def update_output_quality(self, output_id: int,
                              quality_score: float) -> None:
        """Update the quality score of an AI output after scan results are known."""
        self._conn.execute(
            "UPDATE ai_outputs SET quality_score = ? WHERE rowid = ?",
            (quality_score, output_id),
        )
        self._conn.commit()

    def get_learned_strategy_context(self,
                                      technologies: List[str]) -> str:
        """Format learned strategy weights as natural language for Ollama.

        Reads from the learned_strategies table and produces a context block
        that tells the LLM which modules historically worked/failed for
        the detected technology stack.
        """
        if not technologies:
            return ""
        placeholders = ",".join("?" * len(technologies))
        rows = self._conn.execute(
            f"SELECT tech_stack, module, priority, success_count, fail_count "
            f"FROM learned_strategies "
            f"WHERE tech_stack IN ({placeholders}) "
            f"ORDER BY priority DESC LIMIT 20",
            technologies,
        ).fetchall()
        if not rows:
            return ""
        lines = ["LEARNED STRATEGY WEIGHTS (from past scans):"]
        for r in rows:
            total = (r["success_count"] or 0) + (r["fail_count"] or 0)
            if total == 0:
                continue
            rate = (r["success_count"] or 0) / total
            emoji = "✓" if rate >= 0.5 else "✗"
            lines.append(
                f"  {emoji} {r['module']} on {r['tech_stack']}: "
                f"{rate:.0%} success ({r['success_count']}W/{r['fail_count']}L, "
                f"priority={r['priority']})"
            )
        return "\n".join(lines)

    def close(self):
        self._conn.close()


# ══════════════════════════════════════════════════════════════
#  AI BRAIN — UNIFIED INTERFACE
# ══════════════════════════════════════════════════════════════

class AIBrain:
    """
    Hybrid AI brain — Hunter's own systems are PRIMARY.

    Decision hierarchy:
      1. Rule Engine (offline, self-improving) — always runs first, owns the decision
      2. RL Agent (reinforcement learning) — refines module ordering via experience
      3. Ollama LLMs (llama3:8b / mistral:7b) — SECONDARY HELPERS only

    LLMs provide supplementary information (alternative perspectives, draft text,
    extra context) but NEVER override the rule engine's decisions. As Hunter gains
    experience, LLM influence is automatically reduced via a confidence-based gate.
    """

    # When rule engine confidence ≥ this threshold, LLM input is skipped entirely.
    # This means as Hunter learns, it relies less on LLMs.
    LLM_SKIP_CONFIDENCE = 80

    def __init__(self):
        self.ollama = OllamaClient()
        self.rules = RuleEngine()
        self._ollama_checked = False
        self._ollama_available = False
        self._ollama_last_checked_at = 0.0
        self._ollama_recheck_interval_sec = OLLAMA_RECHECK_INTERVAL_SEC

    async def _check_ollama(self, force: bool = False) -> bool:
        now = monotonic()
        was_checked = self._ollama_checked
        stale = (
            self._ollama_checked
            and self._ollama_recheck_interval_sec >= 0
            and (now - self._ollama_last_checked_at) >= self._ollama_recheck_interval_sec
        )
        should_check = force or not self._ollama_checked or stale
        if should_check:
            previous = self._ollama_available
            self._ollama_available = await self.ollama.is_available(force=force or stale)
            self._ollama_checked = True
            self._ollama_last_checked_at = now
            if self._ollama_available:
                if not previous or force or stale:
                    logger.info(f"[OK] Ollama connected -- using {OLLAMA_MODEL}")
            else:
                if previous or force or stale or not was_checked:
                    logger.info("[--] Ollama unavailable -- using rule engine")
        return self._ollama_available

    @property
    def available(self) -> bool:
        """Always available — rule engine is always ready."""
        return True

    # ── Strategy ──────────────────────────────────────────────

    async def analyse_recon(self, target: Target, reward_context: str = "",
                            memory_context: str = "") -> Dict[str, Any]:
        # PRIMARY: Rule engine analysis (always runs, owns the decision)
        rule_result = self.rules.analyse_recon(target)
        rule_confidence = rule_result.get("confidence", 0)

        # If rule engine is confident enough, skip LLM entirely
        if rule_confidence >= self.LLM_SKIP_CONFIDENCE:
            rule_result["source"] = "rules (confident — LLM skipped)"
            logger.info(f"Rule engine confidence={rule_confidence}% ≥ {self.LLM_SKIP_CONFIDENCE}% — LLM consultation skipped")
            return rule_result

        # SECONDARY: Consult LLM with TWO-PASS reasoning for supplementary info
        if await self._check_ollama():
            # ── Build enriched prompt with self-learning context ──
            learned_ctx = self.rules.get_learned_strategy_context(
                target.technologies
            )
            past_outputs = self.rules.get_relevant_ai_outputs("strategy", limit=3)
            past_ctx = ""
            if past_outputs:
                past_ctx = "\nPAST SUCCESSFUL STRATEGY ANALYSIS (learn from these):\n"
                for po in past_outputs:
                    past_ctx += f"  [{po['quality_score']:.1f}] {po['output'][:200]}\n"

            prompt = f"""You are a SECONDARY HELPER providing supplementary analysis. The primary decision has already been made by Hunter's rule engine.

Rule engine decision: {json.dumps(rule_result, default=str)}

Provide ADDITIONAL insights only — do NOT override the rule engine's module ordering.
Focus on: attack vectors the rule engine might have missed, detection gaps, and STRIDE flags.

Target: {target.url}
Technologies: {target.technologies}
Headers: {json.dumps(target.headers)}
Endpoints: {target.discovered_urls[:20]}
Parameters: {json.dumps(dict(list(target.discovered_params.items())[:10]))}
{f"Reward context: {reward_context}" if reward_context else ""}
{f"Past scans: {memory_context}" if memory_context else ""}
{learned_ctx}
{past_ctx}

Return ONLY valid JSON: {{"additional_modules":["any modules rule engine missed"],"attack_vectors":["vector: why"],"detection_gaps":["gap1"],"stride_flags":{{}}}}"""

            # Two-pass reasoning: think first, then structure
            thinking, raw = await self.ollama.chat_with_reasoning(prompt)
            if raw:
                try:
                    ai_supplement = json.loads(raw)
                    # Merge: rule engine modules FIRST (primary), then any LLM extras
                    rule_mods = rule_result.get("priority_modules", [])
                    ai_extras = ai_supplement.get("additional_modules", [])
                    merged = rule_mods + [m for m in ai_extras if m not in rule_mods]
                    rule_result["priority_modules"] = merged

                    # Add LLM's supplementary insights without overriding
                    if ai_supplement.get("attack_vectors"):
                        existing = rule_result.get("attack_vectors", [])
                        rule_result["attack_vectors"] = existing + [
                            f"[LLM] {v}" for v in ai_supplement["attack_vectors"][:3]
                        ]
                    if ai_supplement.get("detection_gaps"):
                        rule_result["detection_gaps"] = ai_supplement["detection_gaps"][:3]

                    rule_result["source"] = "rules+llm_reasoning"
                    rule_result["_thinking"] = thinking[:500]  # store for reflection
                    output_id = self.rules.learn_from_ai("strategy", target.url, raw)
                    rule_result["_ai_output_id"] = output_id
                    return rule_result
                except (json.JSONDecodeError, ValueError):
                    pass  # LLM failed — rule engine result stands

        rule_result["source"] = "rules"
        return rule_result

    # ── Validation ────────────────────────────────────────────

    async def validate_finding(self, finding: Finding) -> Finding:
        # PRIMARY: Rule engine validates first (owns the decision)
        finding = self.rules.validate_finding(finding)
        rule_confirmed = finding.confirmed
        rule_analysis = finding.ai_analysis or ""

        # SECONDARY: Consult LLM with TWO-PASS reasoning for supplementary context
        # LLM CANNOT override rule engine's confirmed/false_positive decision
        if await self._check_ollama():
            prompt = f"""You are a SECONDARY HELPER. The rule engine has already decided this finding is {'CONFIRMED' if rule_confirmed else 'UNCONFIRMED'}.
DO NOT override that decision. Instead, provide supplementary analysis only.

Type: {finding.vuln_type}, URL: {finding.url}, Param: {finding.parameter}
Payload: {finding.payload}
Evidence: {finding.evidence[:500]}
Rule engine analysis: {rule_analysis}

Provide ONLY supplementary context:
1. Blast radius: what can an attacker do with this?
2. Second-order effects (privilege paths, pivots)
3. Specific remediation with verification step

Return ONLY valid JSON: {{"blast_radius":"what attacker can achieve","second_order_effects":["effect1"],"remediation":"specific fix","verification":"how to confirm fix works"}}"""

            # Two-pass reasoning for deeper analysis
            thinking, raw = await self.ollama.chat_with_reasoning(prompt)
            if raw:
                try:
                    data = json.loads(raw) if raw else {}
                    # LLM CANNOT change confirmed/false_positive — rule engine owns that
                    # Only add supplementary remediation info
                    remediation_parts = []
                    if data.get("remediation"):
                        remediation_parts.append(data["remediation"])
                    if data.get("blast_radius"):
                        remediation_parts.append(f"Blast radius: {data['blast_radius']}")
                    if data.get("second_order_effects"):
                        effects = "; ".join(data["second_order_effects"][:3])
                        remediation_parts.append(f"Second-order: {effects}")
                    if data.get("verification"):
                        remediation_parts.append(f"Verify fix: {data['verification']}")
                    if remediation_parts:
                        finding.remediation = " | ".join(remediation_parts)

                    finding.ai_analysis = (
                        f"{rule_analysis} [LLM reasoning: {thinking[:200]}] "
                        f"[blast_radius: {data.get('blast_radius', 'n/a')}]"
                    )

                    self.rules.learn_from_ai("validation", finding.vuln_type, raw,
                                            quality_score=0.5)
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
        # PRIMARY: Rule engine summary (always works, always used)
        rule_summary = self.rules.summarise_scan(state)

        # SECONDARY: Ask LLM to polish the rule engine's output (not replace it)
        if await self._check_ollama():
            findings = [{"title": f.title, "severity": f.severity, "url": f.url}
                        for f in state.findings if f.confirmed]
            prompt = f"""You are a SECONDARY HELPER. Polish and enhance this security report summary. Keep all facts from the original — do NOT add or invent findings.

ORIGINAL REPORT (from Hunter's rule engine — this is the authoritative source):
{rule_summary}

Additional data:
Stats: {json.dumps(state.stats())}
Confirmed findings: {json.dumps(findings[:15])}
{f"Agent performance: {reward_summary}" if reward_summary else ""}

Rewrite in professional executive style (3-5 paragraphs). Keep every fact from the original. Add no new claims."""

            raw = await self.ollama.chat(prompt, max_tokens=1500)
            if raw and len(raw) > 100:
                self.rules.learn_from_ai("summary", state.target.url, raw)
                return raw

        return rule_summary

    # ── Adaptive Payloads ─────────────────────────────────────

    async def generate_adaptive_payloads(self, vuln_type: str,
                                          context: Dict[str, Any]) -> List[str]:
        """Generate payloads. LLM is secondary — used only to supplement, not replace."""
        if await self._check_ollama():
            prompt = f"""You are a SECONDARY HELPER. Suggest additional payloads for {vuln_type} testing.
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

    # ── Self-Reflection (Post-Scan) ────────────────────────────

    async def reflect_on_scan(
        self, strategy: Dict[str, Any], outcomes: Dict[str, Any],
        reward_summary: str = "",
    ) -> Dict[str, Any]:
        """Post-scan reflection: one Ollama call, two destinations.

        Produces a single JSON payload whose fields map to:
          - generalizable_lessons  → HunterMind.record_learning()
          - generalizable_mistakes → HunterMind.record_mistake()
          - target_waf_notes       → ScanMemory reflection_type=waf_bypass
          - target_skip_modules    → ScanMemory reflection_type=module_skip
          - target_confirmed_paths → ScanMemory reflection_type=confirmed_path

        Returns the parsed dict (or empty dict on failure).
        """
        if not await self._check_ollama():
            return {}

        modules_used = strategy.get("priority_modules", [])
        findings_count = outcomes.get("total_findings", 0)
        confirmed_count = outcomes.get("confirmed_findings", 0)
        modules_empty = outcomes.get("empty_modules", [])
        waf_detected = outcomes.get("waf_detected", False)
        waf_name = outcomes.get("waf_name", "")
        target_url = outcomes.get("target_url", "")
        technologies = outcomes.get("technologies", [])

        prompt = f"""You are Hunter's self-reflection engine. Analyse this scan's results.

STRATEGY USED:
  Modules: {modules_used}
  Technologies: {technologies}
  WAF: {waf_name or 'none'}

OUTCOMES:
  Total findings: {findings_count}
  Confirmed: {confirmed_count}
  Modules with 0 findings: {modules_empty}
  Performance: {reward_summary}

REFLECT:
1. Which strategy choices were correct? Which were wrong?
2. What would you do differently next time?
3. Are there generalizable lessons (apply to ANY target)?
4. Are there target-specific notes (apply only to {target_url})?

Return ONLY valid JSON:
{{
  "generalizable_lessons": ["lesson1", "lesson2"],
  "generalizable_mistakes": [
    {{"mistake": "what went wrong", "correct": "what to do instead"}}
  ],
  "target_waf_notes": "WAF bypass observations or empty string",
  "target_skip_modules": ["module names to skip next time on this target"],
  "target_confirmed_paths": ["endpoint/param combinations that worked"]
}}"""

        thinking, raw = await self.ollama.chat_with_reasoning(prompt)
        if not raw:
            return {}

        try:
            reflection = json.loads(raw)
            reflection["_thinking"] = thinking[:500]
            return reflection
        except (json.JSONDecodeError, ValueError):
            return {}

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

    # ── Deep Reasoning ────────────────────────────────────────

    async def deep_reason(
        self,
        question: str,
        context: str = "",
        history: List[Dict[str, str]] = None,
    ) -> str:
        """
        Multi-step chain-of-thought reasoning for complex queries.
        Uses LLM as a secondary reasoning helper — the output is informational,
        not a binding decision. Hunter's own systems make final calls.
        """
        if await self._check_ollama():
            ctx_block = f"\n[CONTEXT]\n{context}" if context else ""
            prompt = f"""[DEEP REASONING REQUEST]
{ctx_block}

[QUESTION]
{question}

Apply Hunter's Core Reasoning Protocol:
STEP 1 — DECOMPOSE: Break into smallest independent components.
STEP 2 — MODEL: Enumerate all viable approaches (minimum 2-3, including unconventional).
STEP 3 — ESTIMATE: For each approach assign P(success) with explicit reasoning. Use [P=X.XX] notation.
STEP 4 — SIMULATE: For the top approach, trace consequences: immediate → 1 day → 1 week → 1 month.
STEP 5 — FAILURE MODES: What are the top 2-3 ways this could go wrong? What are the mitigations?
STEP 6 — DECIDE: Final recommendation. State clearly if P(success) < 0.90 and what would change that.
STEP 7 — META-CHECK: Before finishing, state one assumption that, if false, would invalidate your conclusion.

Show every step explicitly. Do not skip reasoning."""

            response = await self.ollama.chat_with_history(
                history=history or [{"role": "user", "content": prompt}],
                system=SYSTEM_PROMPT,
                max_tokens=2500,
            )
            if response:
                return response

        # Fallback: structured rule-engine response
        return (
            f"[Rule Engine — Deep Reason]\n"
            f"Question: {question}\n\n"
            f"I need Ollama running to perform full chain-of-thought analysis. "
            f"Run `ollama serve` and ensure {OLLAMA_MODEL} is available.\n\n"
            f"Based on known patterns: I can offer heuristic guidance but cannot "
            f"guarantee P≥0.90 without the full reasoning engine."
        )

    # ── Threat Modeling ───────────────────────────────────────

    async def threat_model(self, target_description: str,
                           technologies: List[str] = None,
                           context: str = "") -> str:
        """
        Generate a structured STRIDE threat model for a target.

        Returns a markdown-formatted threat model covering:
        - Asset inventory and trust boundaries
        - STRIDE analysis per component
        - Kill chain mapping
        - Top 5 attack vectors by risk score
        - Recommended controls
        """
        tech_str = ", ".join(technologies) if technologies else "unknown"
        if await self._check_ollama():
            prompt = f"""Generate a structured threat model for this target.

Target: {target_description}
Technologies: {tech_str}
{f"Additional context: {context}" if context else ""}

Structure your analysis as follows:

## 1. Asset Inventory
List the high-value assets and trust boundaries.

## 2. STRIDE Analysis
For each major component, identify:
- S (Spoofing): Who/what could be impersonated?
- T (Tampering): What data or code could be modified?
- R (Repudiation): What actions could be denied?
- I (Information Disclosure): What sensitive data is exposed?
- D (Denial of Service): What could be exhausted or disrupted?
- E (Elevation of Privilege): What paths lead to higher access?

## 3. Kill Chain Mapping
Map the most realistic attack path from initial access to objective.

## 4. Top 5 Attack Vectors
Ranked by: exploitability × impact × stealth
Format: [Risk Score] Vector — Why it matters — Detection gap

## 5. Recommended Controls
Prioritized by risk reduction per implementation cost.

Be specific, adversarial, and actionable. Assign probability estimates where possible."""

            response = await self.ollama.chat(
                prompt=prompt,
                system=SYSTEM_PROMPT,
                max_tokens=3000,
            )
            if response and len(response) > 200:
                return response

        # Fallback threat model
        return (
            f"[Threat Model — Rule Engine]\n"
            f"Target: {target_description}\n"
            f"Technologies: {tech_str}\n\n"
            f"Top attack surface based on tech stack:\n"
            + "\n".join(
                f"- {tech}: {', '.join(TECH_VULN_MAP.get(tech, ['no specific rules'])[:3])}"
                for tech in (technologies or [])
                if tech in TECH_VULN_MAP
            )
            + "\n\nRun Ollama for full STRIDE analysis."
        )

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
