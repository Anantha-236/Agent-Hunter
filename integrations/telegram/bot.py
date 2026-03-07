"""Telegram polling bridge for Hunter."""
from __future__ import annotations

import asyncio
import logging
from typing import Callable, Dict, Optional

from integrations.telegram.client import TelegramBotClient
from interaction.chat import ChatSession

logger = logging.getLogger(__name__)


class TelegramBotService:
    def __init__(
        self,
        token: str,
        client: Optional[TelegramBotClient] = None,
        chat_factory: Optional[Callable[[], ChatSession]] = None,
        poll_interval: float = 1.0,
    ):
        self.token = token
        self.client = client or TelegramBotClient(token)
        self.chat_factory = chat_factory or (
            lambda: ChatSession(personal_chat=True, channel_name="telegram")
        )
        self.poll_interval = poll_interval
        self._sessions: Dict[int, ChatSession] = {}
        self._offset: Optional[int] = None

    def _session_for(self, chat_id: int) -> ChatSession:
        if chat_id not in self._sessions:
            self._sessions[chat_id] = self.chat_factory()
        return self._sessions[chat_id]

    async def handle_update(self, update: Dict) -> None:
        message = update.get("message") or update.get("edited_message") or {}
        chat = message.get("chat") or {}
        text = (message.get("text") or "").strip()
        chat_id = chat.get("id")

        if not chat_id or not text:
            return

        session = self._session_for(int(chat_id))
        response = await session.process(text)
        if response:
            await self.client.send_message(int(chat_id), response)

    async def poll_once(self, timeout: int = 20) -> int:
        updates = await self.client.get_updates(offset=self._offset, timeout=timeout)
        handled = 0
        for update in updates:
            update_id = update.get("update_id")
            try:
                await self.handle_update(update)
                handled += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Telegram update handling failed for update_id=%s", update_id)
            finally:
                if isinstance(update_id, int):
                    self._offset = update_id + 1
        return handled

    async def start(self) -> None:
        async with self.client:
            me = await self.client.get_me()
            logger.info("Telegram bot connected: @%s", me.get("username", "unknown"))
            await self.client.delete_webhook()
            while True:
                try:
                    handled = await self.poll_once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Telegram polling loop failed; retrying")
                    await asyncio.sleep(max(self.poll_interval, 0.2))
                    continue
                if handled == 0:
                    await asyncio.sleep(self.poll_interval)
