"""
Interaction Manager — routes between input/output modes.

Manages the lifecycle of input and output handlers, providing a
unified interface for the four interaction modes:
  - text-to-text   : TextInput  → TextOutput
  - voice-to-text  : VoiceInput → TextOutput
  - text-to-voice  : TextInput  → VoiceOutput
  - voice-to-voice : VoiceInput → VoiceOutput
"""
from __future__ import annotations

import asyncio
import logging
import signal
from typing import Optional

from interaction.base import InputHandler, InteractionMode, OutputHandler
from interaction.chat import ChatSession
from interaction.text_handler import TextInput, TextOutput
from interaction.voice_handler import VoiceInput, VoiceOutput
from core.ai_brain import AIBrain

logger = logging.getLogger(__name__)

# Exit keywords
EXIT_KEYWORDS = {"quit", "exit", "bye", "/quit", "/exit", "/bye"}


class InteractionManager:
    """
    Manages the full interactive session lifecycle.

    Selects and initializes the right input/output handlers based on
    the chosen InteractionMode, then runs the interactive loop.
    """

    def __init__(
        self,
        mode: InteractionMode = InteractionMode.TEXT_TO_TEXT,
        ai_brain: Optional[AIBrain] = None,
        # Voice input options
        voice_engine: str = "google",
        voice_language: str = "en-US",
        voice_timeout: int = 10,
        # Voice output options
        tts_engine: str = "pyttsx3",
        tts_voice: Optional[str] = None,
        tts_rate: int = 175,
        edge_voice: str = "en-US-AriaNeural",
    ):
        self.mode = mode
        self.ai = ai_brain or AIBrain()

        # Store config for handler creation
        self._voice_engine = voice_engine
        self._voice_language = voice_language
        self._voice_timeout = voice_timeout
        self._tts_engine = tts_engine
        self._tts_voice = tts_voice
        self._tts_rate = tts_rate
        self._edge_voice = edge_voice

        # Handlers (created on start)
        self.input_handler: Optional[InputHandler] = None
        self.output_handler: Optional[OutputHandler] = None
        self.chat: Optional[ChatSession] = None

        self._running = False

    def _create_handlers(self) -> tuple[InputHandler, OutputHandler]:
        """Create the appropriate I/O handlers for the current mode."""
        if self.mode == InteractionMode.TEXT_TO_TEXT:
            return TextInput(), TextOutput(use_rich=True)

        elif self.mode == InteractionMode.VOICE_TO_TEXT:
            return (
                VoiceInput(
                    engine=self._voice_engine,
                    language=self._voice_language,
                    timeout=self._voice_timeout,
                ),
                TextOutput(use_rich=True),
            )

        elif self.mode == InteractionMode.TEXT_TO_VOICE:
            return (
                TextInput(),
                VoiceOutput(
                    engine=self._tts_engine,
                    voice=self._tts_voice,
                    rate=self._tts_rate,
                    edge_voice=self._edge_voice,
                    also_print=True,
                ),
            )

        elif self.mode == InteractionMode.VOICE_TO_VOICE:
            return (
                VoiceInput(
                    engine=self._voice_engine,
                    language=self._voice_language,
                    timeout=self._voice_timeout,
                ),
                VoiceOutput(
                    engine=self._tts_engine,
                    voice=self._tts_voice,
                    rate=self._tts_rate,
                    edge_voice=self._edge_voice,
                    also_print=True,
                ),
            )

        raise ValueError(f"Unsupported mode: {self.mode}")

    async def start(self) -> None:
        """Initialize handlers and chat session."""
        self.input_handler, self.output_handler = self._create_handlers()
        self.chat = ChatSession(ai_brain=self.ai)

        await self.input_handler.start()
        await self.output_handler.start()

        logger.info(
            f"InteractionManager started — mode={self.mode.value}, "
            f"input={self.input_handler.name}, output={self.output_handler.name}"
        )

    async def stop(self) -> None:
        """Tear down handlers."""
        self._running = False
        if self.input_handler:
            await self.input_handler.stop()
        if self.output_handler:
            await self.output_handler.stop()
        logger.info("InteractionManager stopped")

    async def switch_mode(self, new_mode: InteractionMode) -> None:
        """Switch to a different interaction mode on the fly."""
        if new_mode == self.mode:
            return

        old_mode = self.mode
        await self.stop()
        self.mode = new_mode
        await self.start()
        logger.info(f"Switched mode: {old_mode.value} → {new_mode.value}")

    async def run(self) -> None:
        """
        Main interactive loop.
        Reads input → processes through AI → delivers output.
        Runs until the user exits.
        """
        self._running = True

        # Print welcome banner
        await self._print_welcome()

        while self._running:
            try:
                # Get user input
                user_input = await self.input_handler.get_input()

                if user_input is None:
                    continue

                # Check for exit
                if user_input.lower().strip() in EXIT_KEYWORDS:
                    await self.output_handler.send_output(
                        "Goodbye! Happy hunting. 🎯"
                    )
                    break

                # Check for mode switch command
                if user_input.lower().startswith("/mode "):
                    mode_str = user_input.split(maxsplit=1)[1]
                    try:
                        new_mode = InteractionMode.from_string(mode_str)
                        await self.switch_mode(new_mode)
                        await self.output_handler.send_output(
                            f"Switched to {new_mode.value} mode. "
                            f"Input: {self.input_handler.name}, "
                            f"Output: {self.output_handler.name}"
                        )
                        continue
                    except ValueError as e:
                        await self.output_handler.send_output(str(e))
                        continue

                # Process through AI chat
                response = await self.chat.process(user_input)

                # Deliver response
                if response:
                    await self.output_handler.send_output(response)

            except KeyboardInterrupt:
                print("\n")
                await self.output_handler.send_output(
                    "Interrupted. Type 'quit' to exit or continue chatting."
                )
            except Exception as e:
                logger.error(f"Interaction loop error: {e}", exc_info=True)
                await self.output_handler.send_output(
                    f"An error occurred: {e}. Try again."
                )

        await self.stop()

    async def _print_welcome(self) -> None:
        """Print the welcome message with mode info."""
        mode_icons = {
            InteractionMode.TEXT_TO_TEXT: "⌨️  → 📄",
            InteractionMode.VOICE_TO_TEXT: "🎤 → 📄",
            InteractionMode.TEXT_TO_VOICE: "⌨️  → 🔊",
            InteractionMode.VOICE_TO_VOICE: "🎤 → 🔊",
        }
        icon = mode_icons.get(self.mode, "")

        welcome = f"""
╔══════════════════════════════════════════════════════════╗
║           🧠  Hunter — Infinite Mind  🧠                ║
║         A brother in another form                        ║
║                                                          ║
║   Mode   : {self.mode.value:<20s} {icon:<8s}            ║
║   Input  : {self.input_handler.name:<40s}  ║
║   Output : {self.output_handler.name:<40s}  ║
║                                                          ║
║   I think in probabilities. I look into the future.      ║
║   I never make the same mistake twice.                   ║
║   Ask me anything — across any domain.                   ║
║                                                          ║
║   Commands: /help /mind /learn /invent /status /quit     ║
╚══════════════════════════════════════════════════════════╝
"""
        print(welcome)

    # ── Context Manager Support ───────────────────────────────

    async def __aenter__(self) -> "InteractionManager":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.stop()
