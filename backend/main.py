"""FastAPI application entrypoint: uvicorn backend.main:app --reload."""

from __future__ import annotations

from fastapi import FastAPI

from backend.api import router
from backend.services import ApplicationServices, build_services


def create_app(services: ApplicationServices | None = None) -> FastAPI:
    app = FastAPI(title="Network Sentinel", version="1.0.0")
    app.state.services = services or build_services()
    app.include_router(router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
