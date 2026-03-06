"""
Text I/O handlers — standard terminal input/output.
"""
from __future__ import annotations

import asyncio
import logging
import sys
from typing import Optional

from interaction.base import InputHandler, OutputHandler

logger = logging.getLogger(__name__)


class TextInput(InputHandler):
    """Reads user input from stdin (terminal)."""

    async def get_input(self, prompt: str = "🎯 You > ") -> Optional[str]:
        """Read a line from stdin asynchronously."""
        try:
            loop = asyncio.get_running_loop()
            text = await loop.run_in_executor(None, lambda: input(prompt))
            return text.strip() if text else None
        except (EOFError, KeyboardInterrupt):
            return None

    async def start(self) -> None:
        logger.debug("TextInput handler started")

    async def stop(self) -> None:
        logger.debug("TextInput handler stopped")

    @property
    def name(self) -> str:
        return "Text Input (stdin)"


class TextOutput(OutputHandler):
    """Writes agent responses to stdout."""

    def __init__(self, use_rich: bool = True):
        self._use_rich = use_rich
        self._console = None

    async def send_output(self, text: str) -> None:
        """Print text response to stdout."""
        if self._console:
            from rich.markdown import Markdown
            self._console.print()
            self._console.print(Markdown(text), style="green")
            self._console.print()
        else:
            print(f"\n🤖 Hunter > {text}\n")

    async def start(self) -> None:
        if self._use_rich:
            try:
                from rich.console import Console
                self._console = Console()
                logger.debug("TextOutput using Rich console")
            except ImportError:
                self._use_rich = False
                logger.debug("Rich not available, using plain text output")
        logger.debug("TextOutput handler started")

    async def stop(self) -> None:
        logger.debug("TextOutput handler stopped")

    @property
    def name(self) -> str:
        return "Text Output (stdout)"
