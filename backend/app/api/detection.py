"""Detection-rule and worker health API."""

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.db import postgres
from app.db.postgres import DatabaseUnavailableError

router = APIRouter(tags=["detection"])


class RuleUpdateRequest(BaseModel):
    enabled: bool


def _unavailable(exc: Exception) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Detection configuration is temporarily unavailable",
    )


@router.get("/detection-rules")
def detection_rules() -> dict[str, list[dict[str, Any]]]:
    try:
        return {"rules": postgres.list_rules()}
    except DatabaseUnavailableError as exc:
        raise _unavailable(exc) from exc


@router.patch("/detection-rules/{rule_id}")
def update_detection_rule(rule_id: str, request: RuleUpdateRequest) -> dict[str, Any]:
    try:
        rule = postgres.set_rule_enabled(rule_id, request.enabled)
    except DatabaseUnavailableError as exc:
        raise _unavailable(exc) from exc
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection rule not found")
    return rule


@router.get("/detection-health")
def detection_health() -> dict[str, object]:
    try:
        checkpoints = postgres.get_checkpoints()
        rules = postgres.list_rules()
    except DatabaseUnavailableError as exc:
        raise _unavailable(exc) from exc
    return {
        "enabled_rules": sum(1 for rule in rules if rule["enabled"]),
        "total_rules": len(rules),
        "checkpoints": checkpoints,
    }
