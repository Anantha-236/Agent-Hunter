"""Minimal Telegram Bot API client."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx


class TelegramBotClient:
    def __init__(self, token: str, timeout: float = 30.0):
        self.token = token
        self.timeout = timeout
        self.base_url = f"https://api.telegram.org/bot{token}"
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "TelegramBotClient":
        self._client = httpx.AsyncClient(timeout=self.timeout)
        return self

    async def __aexit__(self, *_args) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)

        response = await self._client.request(method, f"{self.base_url}/{path}", **kwargs)
        response.raise_for_status()
        payload = response.json()
        if not payload.get("ok", False):
            raise RuntimeError(payload.get("description", "Telegram API error"))
        return payload.get("result", {})

    async def get_me(self) -> Dict[str, Any]:
        return await self._request("GET", "getMe")

    async def delete_webhook(self) -> Dict[str, Any]:
        return await self._request("POST", "deleteWebhook", json={"drop_pending_updates": False})

    async def get_updates(self, offset: Optional[int] = None, timeout: int = 20) -> List[Dict[str, Any]]:
        payload: Dict[str, Any] = {"timeout": timeout}
        if offset is not None:
            payload["offset"] = offset
        result = await self._request("POST", "getUpdates", json=payload)
        return result if isinstance(result, list) else []

    async def send_message(self, chat_id: int, text: str) -> None:
        max_len = 4000
        chunks = [text[i:i + max_len] for i in range(0, len(text), max_len)] or [""]
        for chunk in chunks:
            await self._request(
                "POST",
                "sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": chunk,
                    "disable_web_page_preview": True,
                },
            )
