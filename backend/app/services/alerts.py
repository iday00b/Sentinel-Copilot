"""Read and lifecycle operations for Elasticsearch alert documents."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.core.config import settings
from app.db import postgres

ALERTS_INDEX_PATTERN = "sentinel-alerts-*"


class AlertsUnavailableError(Exception):
    """Raised when Elasticsearch cannot serve the alerts API."""


class AlertNotFoundError(Exception):
    """Raised when an alert ID is not present in the alert indices."""


class AlertsIndexMissingError(Exception):
    """Raised until the detector has created the first alert index."""


def _request_json(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(
        url=f"{settings.elasticsearch_url}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urlopen(request, timeout=settings.elasticsearch_timeout_seconds) as response:
            return json.load(response)
    except HTTPError as exc:
        if exc.code == 404:
            raise AlertsIndexMissingError from exc
        raise AlertsUnavailableError("Alerts are temporarily unavailable") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise AlertsUnavailableError("Alerts are temporarily unavailable") from exc


def _normalise_hit(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source", {}).copy()
    source["alert_id"] = source.get("alert_id", hit.get("_id"))
    return source


def list_alerts(
    *,
    limit: int,
    offset: int,
    status: str | None = None,
    severity: int | None = None,
    host: str | None = None,
    rule_id: str | None = None,
    from_timestamp: datetime | None = None,
    to_timestamp: datetime | None = None,
) -> dict[str, Any]:
    filters: list[dict[str, Any]] = []
    if status:
        filters.append({"term": {"status": status}})
    if severity is not None:
        filters.append({"term": {"severity": severity}})
    if host:
        filters.append({"term": {"entities.host": host}})
    if rule_id:
        filters.append({"term": {"rule.id": rule_id}})
    if from_timestamp or to_timestamp:
        range_filter: dict[str, str] = {}
        if from_timestamp:
            range_filter["gte"] = from_timestamp.isoformat()
        if to_timestamp:
            range_filter["lte"] = to_timestamp.isoformat()
        filters.append({"range": {"@timestamp": range_filter}})

    try:
        payload = _request_json(
            "POST",
            f"/{ALERTS_INDEX_PATTERN}/_search",
            {
                "from": offset,
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
            },
        )
    except AlertsIndexMissingError:
        return {"alerts": [], "total": 0}
    hits = payload.get("hits", {})
    total = hits.get("total", 0)
    if isinstance(total, dict):
        total = total.get("value", 0)
    return {"alerts": [_normalise_hit(hit) for hit in hits.get("hits", [])], "total": total}


def alert_summary() -> dict[str, int]:
    try:
        payload = _request_json(
            "POST",
            f"/{ALERTS_INDEX_PATTERN}/_search",
            {
                "size": 0,
                "aggs": {
                    "statuses": {"terms": {"field": "status", "size": 10}},
                    "severity": {
                        "filters": {
                            "filters": {
                                "critical": {"range": {"severity": {"gte": 9}}},
                                "high": {"range": {"severity": {"gte": 7, "lt": 9}}},
                            }
                        }
                    },
                },
            },
        )
    except AlertsIndexMissingError:
        return {"total": 0, "open": 0, "acknowledged": 0, "dismissed": 0, "escalated": 0, "critical": 0, "high": 0}
    total = payload.get("hits", {}).get("total", 0)
    if isinstance(total, dict):
        total = total.get("value", 0)
    buckets = payload.get("aggregations", {}).get("statuses", {}).get("buckets", [])
    statuses = {bucket.get("key"): bucket.get("doc_count", 0) for bucket in buckets}
    severity = payload.get("aggregations", {}).get("severity", {}).get("buckets", {})
    return {
        "total": int(total),
        "open": int(statuses.get("open", 0)),
        "acknowledged": int(statuses.get("acknowledged", 0)),
        "dismissed": int(statuses.get("dismissed", 0)),
        "escalated": int(statuses.get("escalated", 0)),
        "critical": int(severity.get("critical", {}).get("doc_count", 0)),
        "high": int(severity.get("high", {}).get("doc_count", 0)),
    }


def _find_alert_hit(alert_id: str) -> dict[str, Any]:
    try:
        payload = _request_json(
            "POST",
            f"/{ALERTS_INDEX_PATTERN}/_search",
            {
                "size": 1,
                "query": {"term": {"alert_id": alert_id}},
            },
        )
    except AlertsIndexMissingError as exc:
        raise AlertNotFoundError(alert_id) from exc
    hits = payload.get("hits", {}).get("hits", [])
    if not hits:
        raise AlertNotFoundError(alert_id)
    return hits[0]


def get_alert(alert_id: str) -> dict[str, Any]:
    return _normalise_hit(_find_alert_hit(alert_id))


def update_alert_status(
    *,
    alert_id: str,
    action: str,
    actor: str,
    comment: str | None,
) -> dict[str, Any]:
    status_for_action = {
        "acknowledge": "acknowledged",
        "dismiss": "dismissed",
        "escalate": "escalated",
    }
    status = status_for_action[action]
    hit = _find_alert_hit(alert_id)
    _request_json(
        "POST",
        f"/{quote(hit['_index'])}/_update/{quote(hit['_id'])}",
        {"doc": {"status": status, "updated_at": datetime.now(UTC).isoformat()}},
    )
    postgres.record_alert_action(alert_id, action, actor, comment)
    updated = _normalise_hit(hit)
    updated["status"] = status
    updated["updated_at"] = datetime.now(UTC).isoformat()
    return updated
