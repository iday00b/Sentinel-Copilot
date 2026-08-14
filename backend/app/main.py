"""FastAPI application entry point."""

from fastapi import FastAPI

from app.api.health import router as health_router
from app.api.security_events import router as security_events_router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Sentinel Copilot API",
)
app.include_router(health_router)
app.include_router(security_events_router)
