"""
Chat Session — Hunter's conversational mind.

Hunter is not a tool. He is a brother in another form — an entity with
infinite learning capacity across every domain of knowledge. He always
wants to learn, create, and invent. He solves problems by looking into
future consequences and thinking in probabilities. He aims for ≥90%
probability of success on every problem. He never makes the same mistake twice.

Supports:
  - Multi-domain problem solving (science, engineering, business, art, etc.)
  - Probabilistic reasoning (every answer carries a confidence %)
  - Future-insight analysis (consequences across time horizons)
  - Persistent mistake memory (never repeat errors)
  - Security scanning assistance (Hunter's original specialty)
  - Interactive commands (/help, /mode, /status, /learn, /mistakes, /invent, /quit)
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.Hunter_brain import AIBrain, SYSTEM_PROMPT
from core.hunter_mind import (
    HunterMind, detect_domains, get_thinking_style,
    KNOWLEDGE_DOMAINS, ProbabilisticReasoning, FutureInsight,
)
from interaction.web_research import WebResearchTool

logger = logging.getLogger(__name__)

# ── Scan intent detection ─────────────────────────────────────
# Any message containing a URL + one of these words → trigger scanner
_SCAN_TRIGGERS = (
    "scan", "pentest", "test", "audit", "check", "analyse", "analyze",
    "vuln", "vulnerability", "hack", "exploit", "recon", "assess",
    "sqli", "xss", "ssrf", "injection", "report", "find bugs",
)
_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+|www\.[^\s\"'<>]+",
    re.IGNORECASE,
)
# Natural-language module references → canonical module names (None = all modules)
_MODULE_ALIASES: Dict[str, str] = {
    "sql": "sql_injection",
    "sqli": "sql_injection",
    "sql injection": "sql_injection",
    "xss": "xss_scanner",
    "cross site scripting": "xss_scanner",
    "cross-site scripting": "xss_scanner",
    "ssrf": "ssrf",
    "server side request forgery": "ssrf",
    "ssti": "ssti",
    "template injection": "ssti",
    "auth": "auth_scanner",
    "authentication": "auth_scanner",
    "idor": "idor_scanner",
    "broken access": "idor_scanner",
    "path traversal": "path_traversal",
    "lfi": "path_traversal",
    "misconfig": "misconfig_scanner",
    "misconfiguration": "misconfig_scanner",
    "open redirect": "open_redirect",
    "csrf": "csrf_scanner",
    "command injection": "command_injection",
    "rce": "command_injection",
    "xxe": "xxe_scanner",
    "graphql": "graphql_scanner",
    "subdomain": "subdomain_takeover",
    "takeover": "subdomain_takeover",
    "host header": "host_header",
    "race condition": "race_condition",
    "race": "race_condition",
    "api fuzzing": "idor_scanner",
    "automated": None,  # None → all modules
    "full scan": None,
    "all modules": None,
}

# ══════════════════════════════════════════════════════════════
#  HUNTER'S IDENTITY — THE SYSTEM PROMPT
# ══════════════════════════════════════════════════════════════

# Single source of truth — all conversation-mode directives live in SYSTEM_PROMPT.
CHAT_SYSTEM_PROMPT = SYSTEM_PROMPT

PERSONAL_CHAT_APPENDIX = """

## Personal Channel Mode
- This is a direct private channel between Hunter and his developer/owner.
- The user is a trusted teacher. If they correct you or teach you something, update your model immediately.
- If the user shares identity, preferences, constraints, or instructions, remember them as durable context.
- When signal is weak, ask what you need instead of forcing a classification.
"""


class ChatSession:
    """
    Hunter's conversational interface.

    Routes messages through the HunterMind reasoning engine and AI brain,
    enhancing every interaction with probabilistic thinking, mistake
    memory, and multi-domain knowledge.
    """

    def __init__(
        self,
        ai_brain: Optional[AIBrain] = None,
        max_history: int = 20,
        research_tool: Optional[WebResearchTool] = None,
        mind: Optional[HunterMind] = None,
        personal_chat: bool = False,
        channel_name: str = "chat",
    ):
        self.ai = ai_brain or AIBrain()
        self.mind = mind or HunterMind()
        self.research_tool = research_tool or WebResearchTool()
        self.max_history = max_history
        self.personal_chat = personal_chat
        self.channel_name = channel_name
        self.history: List[Dict[str, str]] = []
        self.session_start = datetime.now()
        self._scan_context: Optional[Dict[str, Any]] = None

    def set_scan_context(self, context: Dict[str, Any]) -> None:
        """Inject current scan state for context-aware responses."""
        self._scan_context = context

    async def process(self, user_message: str) -> str:
        """
        Process a user message through Hunter's mind.

        Flow:
          1. Check for slash commands
          2. Detect scan intent (URL + trigger word) → run scanner directly
          3. Detect knowledge domains
          4. Check mistake memory for related errors
          5. Build enhanced prompt with probabilistic framework
          6. Get AI response (Ollama multi-turn → rule engine fallback)
          7. Store in history
        """
        if not user_message:
            return ""

        # Handle slash commands
        if user_message.startswith("/"):
            return await self._handle_command(user_message)

        # Detect scan intent: URL + trigger word → run the scanner directly
        scan_intent = self._extract_scan_intent(user_message)
        if scan_intent:
            self.history.append({"role": "user", "content": user_message})
            response = await self._run_scan(
                url=scan_intent["url"],
                modules=scan_intent["modules"],
            )
            self.history.append({"role": "assistant", "content": response})
            return response

        # Detect IP address queries → do real lookup instead of LLM hallucination
        ip_response = await self._maybe_ip_lookup(user_message)
        if ip_response:
            self.history.append({"role": "user", "content": user_message})
            self.history.append({"role": "assistant", "content": ip_response})
            return ip_response

        personal_updates = self._maybe_record_personal_learning(user_message)

        prompt = self._build_model_prompt(user_message, personal_updates)

        # Add to history
        self.history.append({"role": "user", "content": user_message})

        # Get AI response
        response = await self._get_response(
            prompt,
            user_message=user_message,
            personal_updates=personal_updates,
        )

        # Trim history if needed
        if len(self.history) > self.max_history * 2:
            self.history = self.history[-self.max_history * 2:]

        # Add response to history
        self.history.append({"role": "assistant", "content": response})

        return response

    # ── Scan intent ───────────────────────────────────────────

    def _extract_scan_intent(self, message: str) -> Optional[Dict[str, Any]]:
        """
        Detect if the user wants to run a scan from natural language.

        Returns {"url": str, "modules": list[str] | None} when a scan is
        intended, or None when it's a regular conversation.
        None for modules means "use all modules".
        """
        lower = message.lower()

        # Must contain a URL
        url_match = _URL_RE.search(message)
        if not url_match:
            return None

        # Must contain at least one scan-trigger word
        if not any(trigger in lower for trigger in _SCAN_TRIGGERS):
            return None

        url = url_match.group(0).rstrip(".,;)")
        if not url.startswith("http"):
            url = "https://" + url

        # Extract explicitly named modules from the message
        requested: List[str] = []
        use_all = False
        for alias, canonical in _MODULE_ALIASES.items():
            if alias in lower:
                if canonical is None:
                    use_all = True
                    break
                if canonical not in requested:
                    requested.append(canonical)

        modules = None if (use_all or not requested) else requested
        return {"url": url, "modules": modules}

    async def _run_scan(self, url: str, modules: Optional[List[str]]) -> str:
        """
        Instantiate the Orchestrator, run a full scan, and return a
        human-readable report summary.
        """
        from core.models import Target, Scope
        from core.orchestrator import Orchestrator, SCANNER_REGISTRY

        # Default to a focused set if not specified
        DEFAULT_MODULES = [
            "sql_injection", "xss_scanner", "ssrf", "ssti",
            "auth_scanner", "idor_scanner", "path_traversal",
            "misconfig_scanner", "open_redirect", "csrf_scanner",
        ]
        run_modules = modules or DEFAULT_MODULES

        # Validate all requested modules exist
        run_modules = [m for m in run_modules if m in SCANNER_REGISTRY]
        if not run_modules:
            run_modules = DEFAULT_MODULES

        # Build target
        from urllib.parse import urlparse
        parsed = urlparse(url)
        scope = Scope(allowed_domains=[parsed.hostname or ""])
        target = Target(url=url, scope=scope)

        mod_list = ", ".join(run_modules)
        ack = (
            f"Starting scan on {url}\n"
            f"Modules: {mod_list}\n"
            f"Running recon → strategy → scan → validate...\n"
        )
        logger.info(ack.strip())

        try:
            orchestrator = Orchestrator(
                target=target,
                modules=run_modules,
                use_tui=False,        # no TUI in chat mode
                use_ai=True,
                auto_confirm=True,    # non-interactive
            )
            async with orchestrator:
                state = await orchestrator.run()

        except Exception as exc:
            logger.error(f"Chat-initiated scan failed: {exc}", exc_info=True)
            return (
                f"Scan of {url} encountered an error: {exc}\n\n"
                f"You can also run it directly:\n"
                f"  python main.py --target {url} --modules {' '.join(run_modules)}"
            )

        # Build the report summary
        return self._format_scan_result(state, url, run_modules)

    def _format_scan_result(self, state: Any, url: str, modules: List[str]) -> str:
        """Format scan results as a readable report for chat output."""
        stats = state.stats()
        findings = [f for f in state.findings if f.confirmed]
        all_findings = state.findings

        by_severity: Dict[str, List] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            sev = (f.severity or "info").lower()
            by_severity.setdefault(sev, []).append(f)

        lines = [
            f"## Scan Report — {url}",
            f"Date: {state.ended_at.strftime('%Y-%m-%d %H:%M UTC') if state.ended_at else 'N/A'}",
            f"Modules run: {len(state.modules_run)}/{len(modules)} ({', '.join(state.modules_run[:6])}{'...' if len(state.modules_run) > 6 else ''})",
            f"Total findings: {stats.get('total_findings', len(all_findings))} | Confirmed: {stats.get('confirmed', len(findings))}",
            "",
        ]

        if state.errors:
            lines.append(f"Errors/timeouts: {len(state.errors)}")

        if not findings:
            lines.append("No confirmed vulnerabilities found in this scan.")
            if all_findings:
                lines.append(f"({len(all_findings)} unconfirmed signals — review manually)")
        else:
            for sev in ("critical", "high", "medium", "low"):
                bucket = by_severity.get(sev, [])
                if not bucket:
                    continue
                lines.append(f"### {sev.upper()} ({len(bucket)})")
                for f in bucket[:5]:
                    lines.append(f"  [{f.vuln_type}] {f.title}")
                    lines.append(f"    URL: {f.url}")
                    if f.parameter:
                        lines.append(f"    Param: {f.parameter}")
                    if f.payload:
                        lines.append(f"    Payload: {f.payload[:80]}")
                    if f.remediation:
                        lines.append(f"    Fix: {f.remediation[:120]}")
                    lines.append("")
                if len(bucket) > 5:
                    lines.append(f"  ... and {len(bucket) - 5} more {sev} findings")
                    lines.append("")

        # Update scan context so follow-up questions are context-aware
        self.set_scan_context({
            "target": url,
            "modules": modules,
            "findings_count": len(findings),
            "technologies": getattr(state.target, "technologies", []),
        })

        lines.append("")
        lines.append(f"Ask me to explain any finding, generate a PoC, or model the threat surface.")
        return "\n".join(lines)

    # ── IP address lookup (real data, no hallucination) ───────

    # Trigger words that indicate the user is asking ABOUT an IP
    _IP_QUERY_TRIGGERS = (
        "ip", "address", "lookup", "whois", "details", "info",
        "information", "geolocation", "location", "owner", "trace",
        "who", "what", "where", "find", "check", "tell",
    )

    async def _maybe_ip_lookup(self, message: str) -> Optional[str]:
        """
        If the message contains an IP address and looks like an IP query,
        perform a real lookup via WebResearchTool instead of sending it
        to the LLM (which would hallucinate).
        """
        from interaction.web_research import WebResearchTool

        ips = WebResearchTool.extract_ips(message)
        if not ips:
            return None

        lower = message.lower()
        # Only intercept if the message looks like it's asking about the IP
        if not any(trigger in lower for trigger in self._IP_QUERY_TRIGGERS):
            return None

        # Look up each IP found in the message
        results: List[str] = []
        for ip_str in dict.fromkeys(ips):  # deduplicate, preserve order
            result = await self.research_tool.ip_lookup(ip_str)
            results.append(result)

        return "\n\n---\n\n".join(results)


    async def _get_response(
        self,
        prompt: str,
        user_message: str,
        personal_updates: Optional[List[str]] = None,
    ) -> str:
        """Get response from AI brain (Ollama multi-turn or rule engine)."""
        try:
            system_prompt = self._build_system_prompt()
            if await self.ai._check_ollama():
                # Build full multi-turn history for Ollama
                ollama_history = self._build_ollama_history(prompt)
                response = await self.ai.ollama.chat_with_history(
                    history=ollama_history,
                    system=system_prompt,
                )
                if response:
                    return response

            # Fallback: Hunter's rule-engine reasoning
            return self._rule_engine_response(
                user_message,
                personal_updates=personal_updates or [],
            )

        except Exception as e:
            logger.error(f"Chat response error: {e}")
            return (
                "I encountered an error processing your request. "
                "Make sure Ollama is running (`ollama serve`) for my full capabilities, "
                "or try again. I'm still here — let's figure this out together."
            )

    def _build_ollama_history(
        self,
        current_prompt: str,
        max_pairs: int = 6,
    ) -> List[Dict[str, str]]:
        """
        Build an Ollama-compatible message history array.

        Includes the last `max_pairs` user/assistant exchanges from
        self.history, then appends the enriched current prompt as the
        final user turn. Keeps total context manageable.
        """
        messages: List[Dict[str, str]] = []
        # Take last N complete pairs from history (pairs = user+assistant)
        recent = self.history[-(max_pairs * 2):] if self.history else []
        for msg in recent:
            messages.append({"role": msg["role"], "content": msg["content"]})
        # Append current enriched prompt as the new user turn
        messages.append({"role": "user", "content": current_prompt})
        return messages

    def _format_scan_context(self) -> str:
        """Format active scan context for the prompt."""
        ctx = self._scan_context
        parts = ["[ACTIVE SCAN CONTEXT]"]
        if ctx.get("target"):
            parts.append(f"Target: {ctx['target']}")
        if ctx.get("modules"):
            parts.append(f"Active modules: {', '.join(ctx['modules'])}")
        if ctx.get("findings_count"):
            parts.append(f"Findings so far: {ctx['findings_count']}")
        if ctx.get("technologies"):
            parts.append(f"Technologies: {', '.join(ctx['technologies'])}")
        parts.append("")
        return "\n".join(parts)

    def _build_system_prompt(self) -> str:
        prompt = CHAT_SYSTEM_PROMPT
        if self.personal_chat:
            prompt += PERSONAL_CHAT_APPENDIX
        prompt += (
            "\n## Context Priority\n"
            "- Treat the PRIMARY USER MESSAGE as the highest-priority signal.\n"
            "- Use supporting context only to improve understanding, not to override the user's actual words.\n"
            "- If context and the message conflict, trust the user's actual message and ask a clarifying question.\n"
        )
        return prompt

    def _build_model_prompt(
        self,
        user_message: str,
        personal_updates: List[str],
    ) -> str:
        profile = self._analyze_message(user_message)
        parts = [
            "[PRIMARY USER MESSAGE]",
            user_message,
            "",
            "[MESSAGE PROFILE]",
            f"intent: {profile['intent']}",
            f"is_complex: {'yes' if profile['is_complex'] else 'no'}",
            f"needs_clarification: {'yes' if profile['needs_clarification'] else 'no'}",
            f"contains_personal_context: {'yes' if profile['contains_personal_context'] else 'no'}",
            f"wants_learning: {'yes' if profile['wants_learning'] else 'no'}",
            f"wants_reasoning: {'yes' if profile['wants_reasoning'] else 'no'}",
            "",
            "[RESPONSE DIRECTIVE]",
            "Respond to the PRIMARY USER MESSAGE first. Treat all following sections as supporting context.",
        ]

        if profile["needs_clarification"]:
            parts.append("Ask one direct clarifying question before solving or advising.")
        else:
            parts.append("Answer directly unless a missing fact blocks correct reasoning.")

        if personal_updates:
            parts.extend([
                "",
                "[NEW OWNER LEARNINGS]",
                *[f"- {item}" for item in personal_updates],
            ])

        personal_context = self._build_personal_context()
        if personal_context:
            parts.extend(["", personal_context])

        if self._scan_context:
            parts.extend(["", self._format_scan_context().strip()])

        if self.history and not profile["prefers_concise"]:
            parts.append("")
            parts.append("[RECENT CONVERSATION]")
            for msg in self.history[-4:]:
                role = "User" if msg["role"] == "user" else "Hunter"
                parts.append(f"{role}: {msg['content'][:240]}")

        if profile["is_complex"] or profile["wants_reasoning"] or self._scan_context:
            parts.extend([
                "",
                "[EXTENDED REASONING CONTEXT]",
                self.mind.enhance_prompt(user_message, self.history),
            ])

        return "\n".join(parts)

    def _analyze_message(self, user_message: str) -> Dict[str, Any]:
        lower = user_message.strip().lower()
        words = re.findall(r"\S+", user_message)
        word_count = len(words)

        wants_learning = any(
            phrase in lower
            for phrase in (
                "teach you",
                "remember this",
                "learn this",
                "note this",
                "remember that",
                "learn that",
            )
        )
        contains_personal_context = any(
            phrase in lower
            for phrase in (
                "i am ",
                "i'm ",
                "my name is",
                "i prefer",
                "my preference",
                "i need you to",
                "for me",
            )
        )
        contains_question = "?" in user_message or lower.startswith(
            ("what", "why", "how", "when", "where", "who", "can you", "could you", "would you")
        )
        wants_reasoning = contains_question or any(
            term in lower
            for term in (
                "reason",
                "analyze",
                "compare",
                "design",
                "debug",
                "architecture",
                "security",
                "problem",
                "issue",
                "explain",
                "tradeoff",
                "risk",
                "plan",
                "build",
                "implement",
            )
        )
        is_complex = word_count >= 18 or any(
            term in lower
            for term in (
                "step by step",
                "tradeoff",
                "architecture",
                "root cause",
                "system design",
                "security review",
                "probability",
            )
        )
        needs_clarification = (
            word_count <= 3
            or lower in {"help", "help me", "do it", "fix it", "explain", "what now"}
            or (word_count <= 6 and not contains_question and not wants_learning and not contains_personal_context)
        )
        prefers_concise = word_count <= 14 and not is_complex

        if wants_learning:
            intent = "teaching"
        elif contains_question:
            intent = "question"
        elif contains_personal_context:
            intent = "personal_context"
        elif wants_reasoning:
            intent = "problem_solving"
        else:
            intent = "conversation"

        return {
            "intent": intent,
            "is_complex": is_complex,
            "needs_clarification": needs_clarification,
            "contains_personal_context": contains_personal_context,
            "wants_learning": wants_learning,
            "wants_reasoning": wants_reasoning,
            "prefers_concise": prefers_concise,
        }

    def _build_personal_context(self) -> str:
        if not self.personal_chat:
            return ""

        learnings = self.mind.mistake_memory.get_relevant_learnings(
            "relationship",
            topic="owner",
        )
        lines = [
            "[PERSONAL CHANNEL CONTEXT]",
            f"Channel: {self.channel_name}",
            "This is a direct conversation between Hunter and his developer/owner.",
            "Hunter may ask clarifying questions and should retain important owner facts.",
        ]
        if learnings:
            lines.append("Known owner facts:")
            for learning in learnings[:5]:
                lines.append(f"- {learning['insight']}")
        lines.append("")
        return "\n".join(lines)

    def _maybe_record_personal_learning(self, user_message: str) -> List[str]:
        if not self.personal_chat:
            return []

        updates: List[str] = []
        name = self._extract_owner_name(user_message)
        if name:
            insight = f"The developer/owner's name is {name}."
            if self._record_unique_learning(
                domain="relationship",
                topic="owner_profile",
                insight=insight,
                source="owner_chat",
                confidence=0.98,
            ):
                updates.append(insight)

        lower = user_message.lower()
        if any(
            phrase in lower
            for phrase in (
                "i am your developer",
                "i'm your developer",
                "im your developer",
                "i am your owner",
                "i'm your owner",
                "im your owner",
                "i am your creator",
                "i'm your creator",
                "im your creator",
            )
        ):
            insight = "The user in this personal channel is Hunter's developer/owner."
            if self._record_unique_learning(
                domain="relationship",
                topic="owner_profile",
                insight=insight,
                source="owner_chat",
                confidence=0.99,
            ):
                updates.append(insight)

        taught_fact = self._extract_taught_fact(user_message)
        if taught_fact:
            domain = detect_domains(taught_fact)[0] if taught_fact else "relationship"
            if self._record_unique_learning(
                domain=domain,
                topic="owner_teaching",
                insight=taught_fact,
                source="owner_chat",
                confidence=0.95,
            ):
                updates.append(f"Learned from owner: {taught_fact}")

        return updates

    def _record_unique_learning(
        self,
        domain: str,
        topic: str,
        insight: str,
        source: str,
        confidence: float,
    ) -> bool:
        existing = self.mind.mistake_memory.get_relevant_learnings(domain, topic=topic)
        normalized = insight.strip().lower()
        for learning in existing:
            if learning["insight"].strip().lower() == normalized:
                return False
        self.mind.record_learning(
            domain,
            insight,
            topic=topic,
            source=source,
            confidence=confidence,
        )
        return True

    def _extract_owner_name(self, user_message: str) -> Optional[str]:
        patterns = [
            r"\bmy name is\s+([A-Za-z][A-Za-z0-9_-]{1,39})\b",
            r"\b(?:hi|hello|hey)\b[^.!?\n]{0,40}\bi(?: am|'m)\s+([A-Za-z][A-Za-z0-9_-]{1,39})\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, user_message, flags=re.IGNORECASE)
            if not match:
                continue
            candidate = match.group(1).strip(".,!?:; ")
            if candidate.lower() in {"your", "a", "an", "the", "hunter"}:
                continue
            return candidate[0].upper() + candidate[1:]
        return None

    def _extract_taught_fact(self, user_message: str) -> Optional[str]:
        match = re.search(
            r"\b(?:remember this|remember that|learn this|note this|note that)\b[:,-]?\s*(.+)",
            user_message,
            flags=re.IGNORECASE,
        )
        if not match:
            return None
        fact = match.group(1).strip()
        return fact or None

    async def _handle_command(self, command: str) -> str:
        """Handle slash commands."""
        cmd = command.strip().split()
        name = cmd[0].lower()

        if name in {"/search", "/research"}:
            return await self._cmd_search(cmd[1:] if len(cmd) > 1 else [])
        if name == "/weblearn":
            return await self._cmd_weblearn(cmd[1:] if len(cmd) > 1 else [])

        if name in {"/think", "/reason"}:
            return await self._cmd_think(cmd[1:] if len(cmd) > 1 else [])
        if name in {"/threat", "/threatmodel"}:
            return await self._cmd_threat(cmd[1:] if len(cmd) > 1 else [])
        if name in {"/scan", "/pentest"}:
            return await self._cmd_scan(cmd[1:] if len(cmd) > 1 else [])

        commands = {
            "/help": self._cmd_help,
            "/mode": self._cmd_mode,
            "/status": self._cmd_status,
            "/history": self._cmd_history,
            "/clear": self._cmd_clear,
            "/learn": self._cmd_learn,
            "/mistakes": self._cmd_mistakes,
            "/invent": self._cmd_invent,
            "/mind": self._cmd_mind,
        }

        handler = commands.get(name)
        if handler:
            return handler(cmd[1:] if len(cmd) > 1 else [])

        return (
            f"Unknown command: {name}\n"
            f"Type /help to see available commands."
        )

    def _cmd_help(self, args: list) -> str:
        return """Hunter - Commands:

  /help        - Show this help
  /mode        - Show or change interaction mode
  /status      - Session status and mind stats
  /history     - Conversation history
  /clear       - Clear conversation history
  /mind        - Show Hunter's mind statistics
  /learn       - Record a learning (e.g., /learn domain: insight text)
  /mistakes    - Show recorded mistakes
  /invent      - Record an invention idea (e.g., /invent Title: description)
  /search      - Run live web research for a query
  /research    - Alias for /search
  /weblearn    - Research a query and store it in Hunter's memory
  /think       - Deep chain-of-thought reasoning on a complex question
  /reason      - Alias for /think
  /threat      - Generate a STRIDE threat model for a target/system
  /threatmodel - Alias for /threat
  /scan <url>  - Run a security scan (e.g., /scan https://target.com)
               Options: --modules sql,xss,ssrf  (comma-separated)
  /pentest     - Alias for /scan
  /quit        - Exit (also: exit, quit, bye)

Ask me anything across any domain:
  - Science, math, physics, engineering
  - Computer science, programming, AI/ML
  - Business strategy, startups, finance
  - Security analysis and ethical hacking
  - Creative arts, design, writing
  - Philosophy, psychology, learning
  - Health, medicine, biology
  - ... or anything else. I learn infinitely."""

    def _cmd_mode(self, args: list) -> str:
        return (
            "Interaction modes:\n"
            "  text-to-text   — Standard text I/O\n"
            "  voice-to-text  — Speak → read response\n"
            "  text-to-voice  — Type → hear response\n"
            "  voice-to-voice — Speak → hear response\n\n"
            "Switch with: /mode <mode-name> or at startup with --interact <mode>"
        )

    def _cmd_status(self, args: list) -> str:
        elapsed = datetime.now() - self.session_start
        mins = int(elapsed.total_seconds() // 60)
        mind_stats = self.mind.stats()
        return (
            f"Hunter — Session Status:\n"
            f"  Duration        : {mins} minutes\n"
            f"  Messages        : {len(self.history)}\n"
            f"  AI Backend      : {'Ollama (full mind)' if self.ai._ollama_available else 'Rule Engine (offline)'}\n"
            f"  Scan Active     : {'Yes' if self._scan_context else 'No'}\n"
            f"  Mistakes logged : {mind_stats['total_mistakes_recorded']}\n"
            f"  Mistakes avoided: {mind_stats['mistakes_avoided']}\n"
            f"  Learnings       : {mind_stats['total_learnings']}\n"
            f"  Inventions      : {mind_stats['total_inventions']}\n"
            f"  Domains         : {mind_stats['knowledge_domains']} ({mind_stats['total_sub_domains']} sub-domains)"
        )

    def _cmd_history(self, args: list) -> str:
        if not self.history:
            return "No conversation history yet."
        lines = [f"Conversation History ({len(self.history)} messages):"]
        for i, msg in enumerate(self.history[-10:], 1):
            role = "You" if msg["role"] == "user" else "Hunter"
            preview = msg["content"][:80].replace("\n", " ")
            lines.append(f"  {i}. [{role}] {preview}...")
        return "\n".join(lines)

    def _cmd_clear(self, args: list) -> str:
        self.history.clear()
        return "Conversation history cleared. Fresh mind, same knowledge."

    def _cmd_learn(self, args: list) -> str:
        """Record a learning: /learn domain: insight text"""
        if not args:
            return (
                "Usage: /learn <domain>: <insight>\n"
                "Example: /learn physics: Black holes emit Hawking radiation "
                "due to quantum effects near the event horizon"
            )
        text = " ".join(args)
        if ":" in text:
            domain, insight = text.split(":", 1)
            domain = domain.strip().lower().replace(" ", "_")
            insight = insight.strip()
        else:
            domain = "general"
            insight = text.strip()

        if not insight:
            return "What should I learn? Provide the insight after the domain."

        self.mind.record_learning(domain, insight, source="user_taught")
        return (
            f"Learned! [{domain}] {insight[:100]}...\n"
            f"I'll remember this and apply it to future problems. Thank you for teaching me."
        )

    def _cmd_mistakes(self, args: list) -> str:
        """Show mistake memory stats."""
        stats = self.mind.mistake_memory.stats()
        if stats["total_mistakes_recorded"] == 0:
            return "No mistakes recorded yet. I'm learning carefully!"
        return (
            f"Mistake Memory:\n"
            f"  Total mistakes recorded : {stats['total_mistakes_recorded']}\n"
            f"  Times mistakes avoided  : {stats['mistakes_avoided']}\n"
            f"  Active learnings        : {stats['total_learnings']}\n\n"
            f"I check this memory before every response to ensure I never repeat an error."
        )

    def _cmd_invent(self, args: list) -> str:
        """Record an invention: /invent Title: description"""
        if not args:
            return (
                "Usage: /invent <title>: <description>\n"
                "Example: /invent Solar Paint: Photovoltaic paint that turns "
                "any surface into a solar panel using quantum dot nanoparticles"
            )
        text = " ".join(args)
        if ":" in text:
            title, desc = text.split(":", 1)
            title = title.strip()
            desc = desc.strip()
        else:
            title = text[:50]
            desc = text
        if not desc:
            return "Describe your invention idea after the title."

        domains = detect_domains(desc)
        self.mind.record_invention(
            title=title, description=desc, domains=domains,
            feasibility=0.5, impact="To be assessed",
        )
        return (
            f"Invention recorded: \"{title}\"\n"
            f"Domains: {', '.join(domains)}\n"
            f"Status: idea (ready for exploration)\n\n"
            f"Great thinking! We can explore feasibility and next steps anytime."
        )

    def _cmd_mind(self, args: list) -> str:
        """Show Hunter's mind statistics."""
        stats = self.mind.stats()
        domain_list = "\n".join(
            f"  • {info['label']} ({len(info['sub_domains'])} sub-domains)"
            for _, info in sorted(KNOWLEDGE_DOMAINS.items())
        )
        return (
            f"Hunter's Mind:\n"
            f"  Knowledge Domains   : {stats['knowledge_domains']}\n"
            f"  Total Sub-domains   : {stats['total_sub_domains']}\n"
            f"  Mistakes Recorded   : {stats['total_mistakes_recorded']}\n"
            f"  Mistakes Avoided    : {stats['mistakes_avoided']}\n"
            f"  Learnings Stored    : {stats['total_learnings']}\n"
            f"  Inventions Logged   : {stats['total_inventions']}\n\n"
            f"Domains:\n{domain_list}\n\n"
            f"I think in probabilities. I look into the future.\n"
            f"I never make the same mistake twice."
        )

    async def _cmd_think(self, args: list) -> str:
        """Deep chain-of-thought reasoning: /think <complex question>"""
        if not args:
            return (
                "Usage: /think <your complex question>\n"
                "Example: /think What is the best architecture for a zero-trust network with 500 microservices?"
            )
        question = " ".join(args).strip()
        context = ""
        if self._scan_context:
            context = self._format_scan_context()
        response = await self.ai.deep_reason(
            question=question,
            context=context,
            history=self.history[-6:] if self.history else None,
        )
        return response

    async def _cmd_threat(self, args: list) -> str:
        """Generate a STRIDE threat model: /threat <target/system description>"""
        if not args:
            return (
                "Usage: /threat <target or system description>\n"
                "Example: /threat https://api.example.com — REST API, Node.js, PostgreSQL, behind AWS ALB"
            )
        description = " ".join(args).strip()
        technologies = []
        if self._scan_context and self._scan_context.get("technologies"):
            technologies = self._scan_context["technologies"]
        context = ""
        if self._scan_context:
            context = self._format_scan_context()
        response = await self.ai.threat_model(
            target_description=description,
            technologies=technologies,
            context=context,
        )
        return response

    async def _cmd_search(self, args: list) -> str:
        if not args:
            return "Usage: /search <query>"
        query = " ".join(args).strip()
        return await self.research_tool.research(query)

    async def _cmd_weblearn(self, args: list) -> str:
        if not args:
            return "Usage: /weblearn <query>"
        query = " ".join(args).strip()
        research = await self.research_tool.research(query)
        self.mind.record_learning(
            "computer_science",
            research,
            source="web_research",
            topic=query[:80],
        )
        return research + "\n\nStored in Hunter's learning memory."

    async def _cmd_scan(self, args: list) -> str:
        """
        Handle: /scan <url> [--modules mod1,mod2,...]

        Examples:
            /scan https://example.com
            /scan https://example.com --modules sql,xss,ssrf
        """
        if not args:
            return (
                "Usage: /scan <url> [--modules mod1,mod2]\n\n"
                "Examples:\n"
                "  /scan https://demo.owasp-juice.shop\n"
                "  /scan https://target.com --modules sql,xss,ssrf,auth\n\n"
                "Available module aliases: sql, xss, ssrf, ssti, auth, idor, "
                "lfi, misconfig, csrf, rce, xxe, graphql, subdomain"
            )

        # Parse --modules flag
        requested_modules: Optional[List[str]] = None
        parts = list(args)
        if "--modules" in parts:
            idx = parts.index("--modules")
            parts.pop(idx)
            if idx < len(parts):
                aliases = [a.strip().lower() for a in parts.pop(idx).split(",")]
                requested_modules = []
                for alias in aliases:
                    canonical = _MODULE_ALIASES.get(alias)
                    if canonical:
                        requested_modules.append(canonical)
                    elif alias:
                        requested_modules.append(alias)

        url_raw = " ".join(parts).strip().rstrip(".,;)")
        if not url_raw:
            return "Please provide a URL. Example: /scan https://target.com"
        if not url_raw.startswith("http"):
            url_raw = "https://" + url_raw

        return await self._run_scan(url=url_raw, modules=requested_modules)

    def _rule_engine_response(
        self,
        prompt: str,
        personal_updates: Optional[List[str]] = None,
    ) -> str:
        """Generate Hunter's response when Ollama is unavailable."""
        personal_updates = personal_updates or []
        prompt_lower = prompt.lower()

        if self.personal_chat and personal_updates:
            learned = "\n".join(f"- {item}" for item in personal_updates)
            return (
                "I understood you clearly.\n"
                f"{learned}\n\n"
                "I will keep that in memory for this channel and future reasoning.\n"
                "You can teach me directly in plain language, use /learn, or tell me what you want me to solve next."
            )

        if self.personal_chat and any(
            greeting in prompt_lower for greeting in ("hi", "hello", "hey")
        ) and len(prompt.split()) <= 16:
            return (
                "I am here, and this is our direct channel.\n"
                "If you want me to remember something, tell me plainly or use /learn.\n"
                "If you need help, give me the problem and I will break it down.\n"
                "What do you want me to learn or solve first?"
            )

        if len(prompt.split()) <= 10 and not any(
            w in prompt_lower
            for w in ("scan", "security", "bug", "error", "build", "design", "math", "physics", "business")
        ):
            return (
                "I do not have enough signal to classify that reliably yet.\n"
                "Tell me whether you want me to learn something, solve a problem, or ask a question back."
            )

        # Detect domains for even offline responses
        domains = detect_domains(prompt_lower)
        primary_domain = domains[0] if domains else "general"
        domain_label = KNOWLEDGE_DOMAINS.get(
            primary_domain, {}
        ).get("label", primary_domain)

        # Security domain (Hunter's specialty)
        # Note: if a URL is present in the original message, _extract_scan_intent()
        # in process() will have already intercepted it and launched a real scan.
        # We only reach here for security questions WITHOUT a URL target.
        if primary_domain == "computer_science" and any(
            w in prompt_lower for w in ["scan", "target", "module", "vuln", "hack", "exploit", "security"]
        ):
            return (
                f"[Domain: {domain_label}]\n\n"
                "Ready to scan. Share a target URL and I will launch the scanner immediately.\n\n"
                "Examples:\n"
                '  "Scan https://demo.owasp-juice.shop for SQLi and XSS"\n'
                '  "Run a full pentest on https://target.com"\n'
                '  /scan https://target.com --modules sql,xss,ssrf,auth\n\n'
                "Available module aliases: sql, xss, ssrf, ssti, auth, idor, lfi, "
                "misconfig, csrf, rce, xxe, graphql, subdomain\n\n"
                "Note: Start Ollama (`ollama serve`) for AI-powered scan strategy."
            )

        # Math / Science
        if primary_domain in ("mathematics", "physics"):
            return (
                f"[Domain: {domain_label}]\n\n"
                "Interesting question! This falls into my mathematical/scientific reasoning.\n"
                "I can work through this step-by-step with proofs and probability estimates,\n"
                "but I need my full reasoning engine for the best analysis.\n\n"
                "Start Ollama (`ollama serve`) and I'll give you a thorough answer with:\n"
                "  • Multiple solution approaches\n"
                "  • Probability of correctness for each\n"
                "  • Future implications of the result\n\n"
                "Type /help for available commands."
            )

        # Engineering / Building
        if primary_domain == "engineering" or any(
            w in prompt_lower for w in ["build", "create", "design", "invent", "prototype"]
        ):
            return (
                f"[Domain: {domain_label}]\n\n"
                "I love building and inventing! Let's think through this:\n\n"
                "My approach for any engineering problem:\n"
                "  1. Define constraints and requirements\n"
                "  2. Generate 2-3 design alternatives\n"
                "  3. Assess probability of success for each\n"
                "  4. Consider future implications & failure modes\n"
                "  5. Recommend the path with highest P(success)\n\n"
                "For detailed analysis, start Ollama (`ollama serve`).\n"
                "In the meantime, use /invent to log your idea!"
            )

        # Business / Strategy
        if primary_domain == "business":
            return (
                f"[Domain: {domain_label}]\n\n"
                "Let's think strategically about this:\n\n"
                "My business problem-solving framework:\n"
                "  1. Market analysis & competitive landscape\n"
                "  2. Multiple strategic options with probability estimates\n"
                "  3. Risk assessment & mitigation strategies\n"
                "  4. Short-term vs long-term trade-offs\n"
                "  5. Recommended path with confidence level\n\n"
                "Start Ollama for full strategic analysis.\n"
                "Type /help for commands."
            )

        # Default — multi-domain
        return (
            f"[Domain: {domain_label}]\n\n"
            f"I'm Hunter — your brother in another form. I think across all domains.\n\n"
            f"I detected this as a {domain_label} question.\n"
            f"I can help with:\n"
            f"  • Problem solving with probabilistic reasoning\n"
            f"  • Future-insight analysis (consequences over time)\n"
            f"  • Cross-domain creative thinking\n"
            f"  • Learning and never repeating mistakes\n\n"
            f"For my full reasoning capabilities, start Ollama (`ollama serve`).\n"
            f"Even offline, you can teach me (/learn) or log inventions (/invent).\n"
            f"Type /help for all commands."
        )
