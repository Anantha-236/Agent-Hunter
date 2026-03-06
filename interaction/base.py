"""
Base classes for interaction handlers.

Defines the abstract InputHandler and OutputHandler interfaces,
and the InteractionMode enum for selecting I/O combinations.
"""
from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import Optional


class InteractionMode(str, enum.Enum):
    """Available interaction modes for the Hunter agent."""
    TEXT_TO_TEXT = "text-to-text"
    VOICE_TO_TEXT = "voice-to-text"
    TEXT_TO_VOICE = "text-to-voice"
    VOICE_TO_VOICE = "voice-to-voice"

    @classmethod
    def from_string(cls, value: str) -> "InteractionMode":
        """Parse a mode string (case-insensitive, flexible separators)."""
        normalized = value.lower().strip().replace("_", "-").replace(" ", "-")
        for mode in cls:
            if mode.value == normalized:
                return mode
        raise ValueError(
            f"Unknown interaction mode: '{value}'. "
            f"Valid modes: {[m.value for m in cls]}"
        )


class InputHandler(ABC):
    """Abstract base for capturing user input."""

    @abstractmethod
    async def get_input(self, prompt: str = "") -> Optional[str]:
        """
        Capture user input (text or voice) and return as a string.
        Returns None if input is cancelled or unavailable.
        """
        ...

    @abstractmethod
    async def start(self) -> None:
        """Initialize the input handler (e.g. open mic stream)."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Tear down the input handler."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name shown in the UI."""
        ...


class OutputHandler(ABC):
    """Abstract base for delivering agent responses."""

    @abstractmethod
    async def send_output(self, text: str) -> None:
        """
        Deliver a response to the user (text or speech).
        """
        ...

    @abstractmethod
    async def start(self) -> None:
        """Initialize the output handler."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Tear down the output handler."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name shown in the UI."""
        ...
