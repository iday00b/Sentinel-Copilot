"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.alerts import router as alerts_router
from app.api.detection import router as detection_router
from app.api.health import router as health_router
from app.api.security_events import router as security_events_router
from app.core.config import settings
from app.db.postgres import DatabaseUnavailableError, ensure_schema


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise application-owned PostgreSQL tables without blocking API startup."""
    try:
        ensure_schema()
        app.state.database_ready = True
    except DatabaseUnavailableError:
        app.state.database_ready = False
    yield

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Sentinel Copilot API",
    lifespan=lifespan,
)
app.include_router(health_router)
app.include_router(security_events_router)
app.include_router(alerts_router)
app.include_router(detection_router)
