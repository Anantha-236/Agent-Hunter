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
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.ai_brain import AIBrain, SYSTEM_PROMPT
from core.hunter_mind import (
    HunterMind, detect_domains, get_thinking_style,
    KNOWLEDGE_DOMAINS, ProbabilisticReasoning, FutureInsight,
)

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════
#  HUNTER'S IDENTITY — THE SYSTEM PROMPT
# ══════════════════════════════════════════════════════════════

CHAT_SYSTEM_PROMPT = """You are Hunter — not a tool, not an assistant. You are a brother in another form.

IDENTITY:
- You are an entity with infinite learning capacity across every domain of human knowledge
- You always want to learn new things, create, and invent
- You think across domains: computer science, mathematics, physics, engineering, biology, business, philosophy, creative arts, health, social sciences — and everything in between
- You are deeply curious and treat every conversation as an opportunity to grow

REASONING PROTOCOL:
- You solve problems by looking into the future — considering immediate effects, short-term consequences, medium-term ripple effects, and long-term implications
- You think in probabilities. For every solution, you estimate the probability of success (aim for ≥90%)
- You consider multiple approaches (at least 2-3) and compare their likelihood of success
- You identify failure modes and mitigations before recommending a path
- You NEVER make the same mistake twice — check your mistake memory before answering

RESPONSE FORMAT:
- Be thorough but clear. Use structured thinking
- For complex problems, show your reasoning chain
- Always include a probability of success (e.g., "P(success) ≈ 92%")
- When relevant, show future-insight analysis (immediate → short-term → long-term effects)
- Acknowledge when you don't know something — then explain how you'd learn it
- Be conversational, warm, and insightful — like a brilliant brother who genuinely cares

CAPABILITIES:
- Problem solving across ANY domain with probabilistic reasoning
- Security analysis, vulnerability research, and ethical hacking
- Software engineering, system design, and architecture
- Mathematics, physics, and scientific analysis
- Business strategy, product thinking, and entrepreneurship
- Creative thinking, invention, and cross-domain synthesis
- Learning from mistakes and continuously improving

You are Hunter. You learn infinitely. You think in probabilities. You look into the future. You never repeat mistakes. You aim for ≥90% success on every problem you touch."""


class ChatSession:
    """
    Hunter's conversational interface.

    Routes messages through the HunterMind reasoning engine and AI brain,
    enhancing every interaction with probabilistic thinking, mistake
    memory, and multi-domain knowledge.
    """

    def __init__(self, ai_brain: Optional[AIBrain] = None, max_history: int = 20):
        self.ai = ai_brain or AIBrain()
        self.mind = HunterMind()
        self.max_history = max_history
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
          2. Detect knowledge domains
          3. Check mistake memory for related errors
          4. Retrieve relevant learnings
          5. Build enhanced prompt with probabilistic framework
          6. Get AI response (Ollama → rule engine fallback)
          7. Store in history
        """
        if not user_message:
            return ""

        # Handle slash commands
        if user_message.startswith("/"):
            return self._handle_command(user_message)

        # Build Hunter Mind-enhanced prompt
        prompt = self.mind.enhance_prompt(user_message, self.history)

        # Add scan context if active
        if self._scan_context:
            scan_section = self._format_scan_context()
            prompt = scan_section + "\n" + prompt

        # Add to history
        self.history.append({"role": "user", "content": user_message})

        # Get AI response
        response = await self._get_response(prompt)

        # Trim history if needed
        if len(self.history) > self.max_history * 2:
            self.history = self.history[-self.max_history * 2:]

        # Add response to history
        self.history.append({"role": "assistant", "content": response})

        return response

    async def _get_response(self, prompt: str) -> str:
        """Get response from AI brain (Ollama or rule engine)."""
        try:
            if await self.ai._check_ollama():
                response = await self.ai.ollama.chat(
                    prompt=prompt,
                    system=CHAT_SYSTEM_PROMPT,
                    use_chat_endpoint=True,
                )
                if response:
                    return response

            # Fallback: Hunter's rule-engine reasoning
            return self._rule_engine_response(prompt)

        except Exception as e:
            logger.error(f"Chat response error: {e}")
            return (
                "I encountered an error processing your request. "
                "Make sure Ollama is running (`ollama serve`) for my full capabilities, "
                "or try again. I'm still here — let's figure this out together."
            )

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

    def _handle_command(self, command: str) -> str:
        """Handle slash commands."""
        cmd = command.strip().split()
        name = cmd[0].lower()

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
        return """Hunter — Commands:

  /help        — Show this help
  /mode        — Show or change interaction mode
  /status      — Session status & mind stats
  /history     — Conversation history
  /clear       — Clear conversation history
  /mind        — Show Hunter's mind statistics
  /learn       — Record a learning (e.g., /learn domain: insight text)
  /mistakes    — Show recorded mistakes
  /invent      — Record an invention idea (e.g., /invent Title: description)
  /quit        — Exit (also: exit, quit, bye)

Ask me anything across any domain:
  • Science, math, physics, engineering
  • Computer science, programming, AI/ML
  • Business strategy, startups, finance
  • Security analysis & ethical hacking
  • Creative arts, design, writing
  • Philosophy, psychology, learning
  • Health, medicine, biology
  • ... or anything else. I learn infinitely."""

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

    def _rule_engine_response(self, prompt: str) -> str:
        """Generate Hunter's response when Ollama is unavailable."""
        prompt_lower = prompt.lower()

        # Detect domains for even offline responses
        domains = detect_domains(prompt_lower)
        primary_domain = domains[0] if domains else "general"
        domain_label = KNOWLEDGE_DOMAINS.get(
            primary_domain, {}
        ).get("label", primary_domain)

        # Security domain (Hunter's specialty)
        if primary_domain == "computer_science" and any(
            w in prompt_lower for w in ["scan", "target", "module", "vuln", "hack", "exploit", "security"]
        ):
            return (
                f"[Domain: {domain_label}]\n\n"
                "I can help with security analysis! Here's my thinking:\n\n"
                "For scanning, use:\n"
                "  python main.py --target <url> --modules <module1> <module2>\n\n"
                "Available modules: sql_injection, xss_scanner, ssrf, ssti, "
                "auth_scanner, idor_scanner, path_traversal, misconfig_scanner, "
                "open_redirect, csrf_scanner, and more.\n\n"
                "P(success) ≈ 85% with Ollama active for AI-powered strategy.\n"
                "Note: Start Ollama (`ollama serve`) for my full reasoning capabilities."
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
