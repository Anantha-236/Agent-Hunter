"""
Interaction Module — Multi-modal input/output for the Hunter agent.

Supported modes:
  - text-to-text   : Standard terminal text I/O
  - voice-to-text  : Microphone speech recognition → text output
  - text-to-voice  : Text input → synthesized speech output
  - voice-to-voice : Microphone input → synthesized speech output
"""

from interaction.base import InputHandler, OutputHandler, InteractionMode
from interaction.manager import InteractionManager

__all__ = [
    "InputHandler",
    "OutputHandler",
    "InteractionMode",
    "InteractionManager",
]
