"""Alert lifecycle API backed by Elasticsearch and PostgreSQL audit records."""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.db.postgres import DatabaseUnavailableError
from app.services.alerts import (
    AlertNotFoundError,
    AlertsUnavailableError,
    alert_summary,
    get_alert,
    list_alerts,
    update_alert_status,
)

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertActionRequest(BaseModel):
    action: Literal["acknowledge", "dismiss", "escalate"]
    actor: str = Field(default="analyst", min_length=1, max_length=120)
    comment: str | None = Field(default=None, max_length=2_000)


def _unavailable(exc: Exception) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Alerts are temporarily unavailable",
    )


@router.get("")
def alerts(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: int | None = Query(default=None, ge=1, le=10),
    host: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    from_timestamp: datetime | None = Query(default=None, alias="from"),
    to_timestamp: datetime | None = Query(default=None, alias="to"),
) -> dict[str, object]:
    try:
        return list_alerts(
            limit=limit,
            offset=offset,
            status=status_filter,
            severity=severity,
            host=host,
            rule_id=rule_id,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
        )
    except AlertsUnavailableError as exc:
        raise _unavailable(exc) from exc


@router.get("/summary")
def summary() -> dict[str, int]:
    try:
        return alert_summary()
    except AlertsUnavailableError as exc:
        raise _unavailable(exc) from exc


@router.get("/{alert_id}")
def alert(alert_id: str) -> dict[str, object]:
    try:
        return get_alert(alert_id)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found") from exc
    except AlertsUnavailableError as exc:
        raise _unavailable(exc) from exc


@router.patch("/{alert_id}")
def action_alert(alert_id: str, request: AlertActionRequest) -> dict[str, object]:
    try:
        return update_alert_status(
            alert_id=alert_id,
            action=request.action,
            actor=request.actor,
            comment=request.comment,
        )
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found") from exc
    except (AlertsUnavailableError, DatabaseUnavailableError) as exc:
        raise _unavailable(exc) from exc
