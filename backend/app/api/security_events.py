"""Read-only API for normalized security events."""

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from app.services.security_events import (
    SecurityEventsUnavailableError,
    get_recent_security_events,
)

router = APIRouter(prefix="/security-events", tags=["security-events"])


@router.get("/recent")
def recent_security_events(
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, list[dict[str, Any]]]:
    """Return the most recent normalized security events."""
    try:
        events = get_recent_security_events(limit)
    except SecurityEventsUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security events are temporarily unavailable",
        ) from exc

    return {"events": events}
