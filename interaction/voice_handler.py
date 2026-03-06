"""
Voice I/O handlers — speech recognition and text-to-speech.

Voice Input:  Uses SpeechRecognition library with multiple backend support:
              - Whisper (local, via OpenAI whisper model)
              - Google Speech API (online, free)
              - Sphinx (offline, lower quality)

Voice Output: Uses pyttsx3 (offline, cross-platform) with optional
              edge-tts for higher-quality async synthesis.
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import threading
from typing import Optional

from interaction.base import InputHandler, OutputHandler

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
#  Voice Input — Speech Recognition
# ──────────────────────────────────────────────────────────────

class VoiceInput(InputHandler):
    """
    Captures audio from the microphone and transcribes to text.

    Supports multiple recognition backends (configured via `engine`):
      - "google"  : Free Google Web Speech API (default, requires internet)
      - "whisper" : Local OpenAI Whisper model (requires `openai-whisper`)
      - "sphinx"  : CMU Sphinx (offline, lower accuracy)
    """

    def __init__(
        self,
        engine: str = "google",
        language: str = "en-US",
        timeout: int = 10,
        phrase_time_limit: int = 30,
        energy_threshold: int = 300,
        dynamic_energy: bool = True,
    ):
        self.engine = engine.lower()
        self.language = language
        self.timeout = timeout
        self.phrase_time_limit = phrase_time_limit
        self.energy_threshold = energy_threshold
        self.dynamic_energy = dynamic_energy

        self._recognizer = None
        self._microphone = None
        self._available = False

    async def start(self) -> None:
        """Initialize the speech recognition engine and microphone."""
        try:
            import speech_recognition as sr

            self._recognizer = sr.Recognizer()
            self._recognizer.energy_threshold = self.energy_threshold
            self._recognizer.dynamic_energy_threshold = self.dynamic_energy

            # Test microphone availability
            self._microphone = sr.Microphone()
            with self._microphone as source:
                self._recognizer.adjust_for_ambient_noise(source, duration=1)

            self._available = True
            logger.info(
                f"VoiceInput started — engine={self.engine}, "
                f"energy_threshold={self._recognizer.energy_threshold:.0f}"
            )
        except ImportError:
            logger.error(
                "SpeechRecognition not installed. "
                "Install with: pip install SpeechRecognition pyaudio"
            )
            self._available = False
        except OSError as e:
            logger.error(f"Microphone not available: {e}")
            self._available = False

    async def stop(self) -> None:
        self._recognizer = None
        self._microphone = None
        self._available = False
        logger.debug("VoiceInput handler stopped")

    async def get_input(self, prompt: str = "") -> Optional[str]:
        """Listen for voice input and return transcribed text."""
        if not self._available:
            logger.warning("Voice input not available, falling back to text")
            return await self._fallback_text_input(prompt)

        import speech_recognition as sr

        if prompt:
            print(f"\n🎤 {prompt}")
        else:
            print("\n🎤 Listening... (speak now, or press Ctrl+C for text input)")

        loop = asyncio.get_running_loop()
        try:
            text = await loop.run_in_executor(None, self._listen_and_transcribe)
            if text:
                print(f"   📝 Heard: \"{text}\"")
                return text
            else:
                print("   ⚠️  Could not understand. Try again or type your input:")
                return await self._fallback_text_input("")
        except KeyboardInterrupt:
            return await self._fallback_text_input("\n⌨️  Switched to text > ")

    def _listen_and_transcribe(self) -> Optional[str]:
        """Blocking call — records audio and transcribes."""
        import speech_recognition as sr

        try:
            with self._microphone as source:
                audio = self._recognizer.listen(
                    source,
                    timeout=self.timeout,
                    phrase_time_limit=self.phrase_time_limit,
                )

            # Transcribe with selected engine
            if self.engine == "google":
                return self._recognizer.recognize_google(audio, language=self.language)
            elif self.engine == "whisper":
                return self._recognizer.recognize_whisper(
                    audio, language=self.language[:2]
                )
            elif self.engine == "sphinx":
                return self._recognizer.recognize_sphinx(audio)
            else:
                logger.warning(f"Unknown engine '{self.engine}', using Google")
                return self._recognizer.recognize_google(audio, language=self.language)

        except sr.WaitTimeoutError:
            logger.debug("Listening timed out")
            return None
        except sr.UnknownValueError:
            logger.debug("Speech not recognized")
            return None
        except sr.RequestError as e:
            logger.error(f"Speech recognition API error: {e}")
            return None

    async def _fallback_text_input(self, prompt: str) -> Optional[str]:
        """Fall back to text input when voice fails."""
        try:
            loop = asyncio.get_running_loop()
            if not prompt:
                prompt = "⌨️  Type instead > "
            text = await loop.run_in_executor(None, lambda: input(prompt))
            return text.strip() if text else None
        except (EOFError, KeyboardInterrupt):
            return None

    @property
    def name(self) -> str:
        return f"Voice Input ({self.engine})"


# ──────────────────────────────────────────────────────────────
#  Voice Output — Text-to-Speech
# ──────────────────────────────────────────────────────────────

class VoiceOutput(OutputHandler):
    """
    Synthesizes speech from text responses.

    Supports multiple TTS backends (configured via `engine`):
      - "pyttsx3"  : Offline, cross-platform (Windows SAPI, macOS NSSpeech, Linux espeak)
      - "edge-tts" : Microsoft Edge TTS (high quality, async, free, requires internet)
    """

    def __init__(
        self,
        engine: str = "pyttsx3",
        voice: Optional[str] = None,
        rate: int = 175,
        volume: float = 1.0,
        edge_voice: str = "en-US-AriaNeural",
        also_print: bool = True,
    ):
        self.engine = engine.lower()
        self.voice = voice
        self.rate = rate
        self.volume = volume
        self.edge_voice = edge_voice
        self.also_print = also_print

        self._tts_engine = None
        self._available = False

    async def start(self) -> None:
        """Initialize the TTS engine."""
        if self.engine == "pyttsx3":
            await self._init_pyttsx3()
        elif self.engine == "edge-tts":
            await self._init_edge_tts()
        else:
            logger.warning(f"Unknown TTS engine '{self.engine}', trying pyttsx3")
            self.engine = "pyttsx3"
            await self._init_pyttsx3()

    async def _init_pyttsx3(self) -> None:
        """Initialize pyttsx3 offline TTS engine."""
        try:
            import pyttsx3

            self._tts_engine = pyttsx3.init()
            self._tts_engine.setProperty("rate", self.rate)
            self._tts_engine.setProperty("volume", self.volume)

            # Set voice if specified
            if self.voice:
                voices = self._tts_engine.getProperty("voices")
                for v in voices:
                    if self.voice.lower() in v.name.lower() or self.voice == v.id:
                        self._tts_engine.setProperty("voice", v.id)
                        break

            self._available = True
            logger.info("VoiceOutput started — engine=pyttsx3")
        except ImportError:
            logger.error("pyttsx3 not installed. Install with: pip install pyttsx3")
            self._available = False
        except Exception as e:
            logger.error(f"Failed to initialize pyttsx3: {e}")
            self._available = False

    async def _init_edge_tts(self) -> None:
        """Check if edge-tts is available."""
        try:
            import edge_tts
            self._available = True
            logger.info(f"VoiceOutput started — engine=edge-tts, voice={self.edge_voice}")
        except ImportError:
            logger.error("edge-tts not installed. Install with: pip install edge-tts")
            logger.info("Falling back to pyttsx3...")
            self.engine = "pyttsx3"
            await self._init_pyttsx3()

    async def stop(self) -> None:
        """Clean up TTS engine."""
        if self._tts_engine and self.engine == "pyttsx3":
            try:
                self._tts_engine.stop()
            except Exception:
                pass
        self._tts_engine = None
        self._available = False
        logger.debug("VoiceOutput handler stopped")

    async def send_output(self, text: str) -> None:
        """Speak the text and optionally print it."""
        # Always print text alongside speech for accessibility
        if self.also_print:
            print(f"\n🤖 Hunter > {text}\n")

        if not self._available:
            logger.warning("TTS not available, text-only output")
            if not self.also_print:
                print(f"\n🤖 Hunter > {text}\n")
            return

        # Strip markdown/special characters for cleaner speech
        clean_text = self._clean_for_speech(text)

        if self.engine == "pyttsx3":
            await self._speak_pyttsx3(clean_text)
        elif self.engine == "edge-tts":
            await self._speak_edge_tts(clean_text)

    async def _speak_pyttsx3(self, text: str) -> None:
        """Speak using pyttsx3 (runs in thread to avoid blocking)."""
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._pyttsx3_say, text)
        except Exception as e:
            logger.error(f"pyttsx3 speech error: {e}")

    def _pyttsx3_say(self, text: str) -> None:
        """Blocking pyttsx3 speak call."""
        self._tts_engine.say(text)
        self._tts_engine.runAndWait()

    async def _speak_edge_tts(self, text: str) -> None:
        """Speak using edge-tts (async, high quality)."""
        try:
            import edge_tts

            # Generate speech to temp file and play it
            with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as tmp:
                tmp_path = tmp.name

            communicate = edge_tts.Communicate(text, self.edge_voice)
            await communicate.save(tmp_path)

            # Play the audio file
            await self._play_audio(tmp_path)

            # Cleanup
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        except Exception as e:
            logger.error(f"edge-tts speech error: {e}")

    async def _play_audio(self, filepath: str) -> None:
        """Play an audio file cross-platform."""
        import platform
        system = platform.system()
        loop = asyncio.get_running_loop()

        try:
            if system == "Windows":
                # Use Windows Media Player via PowerShell
                proc = await asyncio.create_subprocess_exec(
                    "powershell", "-c",
                    f'(New-Object Media.SoundPlayer "{filepath}").PlaySync()',
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
            elif system == "Darwin":
                proc = await asyncio.create_subprocess_exec(
                    "afplay", filepath,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
            else:
                # Linux — try mpv, then aplay, then ffplay
                for player in ["mpv --no-video", "aplay", "ffplay -nodisp -autoexit"]:
                    cmd = player.split() + [filepath]
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.DEVNULL,
                            stderr=asyncio.subprocess.DEVNULL,
                        )
                        await proc.wait()
                        break
                    except FileNotFoundError:
                        continue
        except Exception as e:
            logger.warning(f"Could not play audio: {e}")

    @staticmethod
    def _clean_for_speech(text: str) -> str:
        """Strip markdown formatting and special chars for cleaner TTS."""
        import re
        # Remove markdown headers
        text = re.sub(r"#{1,6}\s*", "", text)
        # Remove markdown bold/italic
        text = re.sub(r"\*{1,3}(.*?)\*{1,3}", r"\1", text)
        # Remove markdown links [text](url) → text
        text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
        # Remove code blocks
        text = re.sub(r"```[\s\S]*?```", "", text)
        # Remove inline code
        text = re.sub(r"`([^`]+)`", r"\1", text)
        # Remove bullet points
        text = re.sub(r"^\s*[-*+]\s+", "", text, flags=re.MULTILINE)
        # Remove emojis (basic range)
        text = re.sub(
            r"[\U0001f300-\U0001f9ff\U00002700-\U000027bf\U0001fa00-\U0001faff]",
            "", text
        )
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @property
    def name(self) -> str:
        return f"Voice Output ({self.engine})"


# ──────────────────────────────────────────────────────────────
#  Utility: List available voices
# ──────────────────────────────────────────────────────────────

def list_pyttsx3_voices() -> list[dict]:
    """List available pyttsx3 voices on the system."""
    try:
        import pyttsx3
        engine = pyttsx3.init()
        voices = engine.getProperty("voices")
        result = [{"id": v.id, "name": v.name, "languages": v.languages}
                  for v in voices]
        engine.stop()
        return result
    except Exception as e:
        logger.error(f"Cannot list voices: {e}")
        return []


async def list_edge_tts_voices() -> list[dict]:
    """List available edge-tts voices."""
    try:
        import edge_tts
        voices = await edge_tts.list_voices()
        return [{"name": v["ShortName"], "gender": v["Gender"],
                 "locale": v["Locale"]} for v in voices]
    except Exception as e:
        logger.error(f"Cannot list edge-tts voices: {e}")
        return []
