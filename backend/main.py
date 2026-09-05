"""FastAPI application entrypoint: uvicorn backend.main:app --reload."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api import router
from backend.api.dashboard_payload import alert_payload, dashboard_payload
from backend.api.realtime import RealtimeHub
from backend.services import ApplicationServices, build_services


def create_app(services: ApplicationServices | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async def publish_updates() -> None:
            while True:
                await app.state.hub.broadcast(dashboard_payload(app.state.services))
                await asyncio.sleep(1)

        task = asyncio.create_task(publish_updates())
        yield
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    app = FastAPI(title="Network Sentinel", version="1.0.0", lifespan=lifespan)
    app.state.services = services or build_services()
    app.state.hub = RealtimeHub()
    app.state.services.monitoring.set_alert_callback(
        lambda alerts: app.state.hub.publish_from_thread({"type": "alerts", "data": [alert_payload(alert) for alert in alerts]})
    )
    app.include_router(router)

    frontend = Path(__file__).resolve().parent.parent / "frontend"
    app.mount("/static", StaticFiles(directory=frontend), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(frontend / "index.html")

    @app.websocket("/ws")
    async def websocket_dashboard(websocket: WebSocket) -> None:
        await app.state.hub.serve(websocket, lambda: dashboard_payload(app.state.services))

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
