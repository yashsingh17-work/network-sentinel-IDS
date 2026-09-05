"""WebSocket hub that safely accepts messages from capture-thread code."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import WebSocket


class RealtimeHub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._clients.add(websocket)
        self._loop = asyncio.get_running_loop()

    def disconnect(self, websocket: WebSocket) -> None:
        self._clients.discard(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        for client in list(self._clients):
            try:
                await client.send_json(payload)
            except Exception:
                self._clients.discard(client)

    def publish_from_thread(self, payload: dict[str, Any]) -> None:
        if self._loop is not None and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(payload), self._loop)

    async def serve(self, websocket: WebSocket, initial_payload: Callable[[], dict[str, Any]]) -> None:
        await self.connect(websocket)
        try:
            await websocket.send_json(initial_payload())
            while True:
                await websocket.receive_text()
        except Exception:
            self.disconnect(websocket)
