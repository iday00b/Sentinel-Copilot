"""Idempotent detection worker for normalized security events."""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.core.config import settings
from app.db import postgres
from app.models.detection import DetectionRule

SECURITY_EVENTS_INDEX_PATTERN = "sentinel-security-events-*"
ALERTS_INDEX_PREFIX = "sentinel-alerts-"


class DetectionUnavailableError(Exception):
    """Raised when Elasticsearch cannot serve detector work."""


def _value_at_path(document: dict[str, Any], path: str) -> Any:
    value: Any = document
    for segment in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(segment)
    return value


def rule_matches(rule: DetectionRule, event: dict[str, Any]) -> bool:
    """Return whether every persisted condition matches the event."""
    return all(_value_at_path(event, path) == expected for path, expected in rule.condition.items())


def alert_fingerprint(rule_id: str, source_index: str, source_event_id: str) -> str:
    """Build a stable detector idempotency key for a source event and rule."""
    value = f"{rule_id}:{source_index}:{source_event_id}".encode("utf-8")
    return sha256(value).hexdigest()


def _first_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, list):
        return next((item for item in value if isinstance(item, str) and item.strip()), None)
    return None


def build_alert_document(rule: DetectionRule, hit: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Build the schema-normalized alert document from an Elasticsearch hit."""
    source = hit["_source"]
    timestamp = source.get("@timestamp") or datetime.now(UTC).isoformat()
    created_at = (now or datetime.now(UTC)).isoformat()
    fingerprint = alert_fingerprint(rule.id, hit["_index"], hit["_id"])
    host = source.get("host") or {}
    user = source.get("user") or {}
    event_source = source.get("source") or {}
    related = source.get("related") or {}
    source_ip = _first_string(event_source.get("ip")) or _first_string(related.get("ip"))

    return {
        "@timestamp": timestamp,
        "created_at": created_at,
        "updated_at": created_at,
        "alert_id": fingerprint,
        "fingerprint": fingerprint,
        "status": "open",
        "severity": rule.severity,
        "title": rule.name,
        "message": source.get("message") or rule.name,
        "rule": {"id": rule.id, "name": rule.name, "version": rule.version},
        "source_event": {"id": hit["_id"], "index": hit["_index"], "timestamp": timestamp},
        "entities": {
            "host": _first_string(host.get("name")) or _first_string(host.get("hostname")),
            "user": _first_string(user.get("name")) or _first_string(related.get("user")),
            "source_ip": source_ip,
        },
        "mitre": {"tactic": rule.mitre_tactic, "technique": rule.mitre_technique},
    }


def _request_json(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(
        url=f"{settings.elasticsearch_url}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urlopen(request, timeout=settings.elasticsearch_timeout_seconds) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        if exc.code == 409:
            return exc.code, json.load(exc)
        raise DetectionUnavailableError("Elasticsearch is unavailable") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise DetectionUnavailableError("Elasticsearch is unavailable") from exc


def fetch_events(checkpoint: datetime | None) -> list[dict[str, Any]]:
    query: dict[str, Any] = {"match_all": {}}
    if checkpoint is not None:
        query = {"range": {"@timestamp": {"gt": checkpoint.isoformat()}}}
    _, payload = _request_json(
        "POST",
        f"/{SECURITY_EVENTS_INDEX_PATTERN}/_search",
        {
            "size": settings.detector_batch_size,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": query,
        },
    )
    return [hit for hit in payload.get("hits", {}).get("hits", []) if "_source" in hit]


def index_alert(alert: dict[str, Any]) -> bool:
    """Create an alert only once; duplicate detector passes return False."""
    index = f"{ALERTS_INDEX_PREFIX}{datetime.now(UTC):%Y.%m.%d}"
    status, _ = _request_json("PUT", f"/{index}/_create/{quote(alert['alert_id'])}", alert)
    return status in {200, 201}


def _latest_timestamp(hits: list[dict[str, Any]]) -> datetime | None:
    values: list[datetime] = []
    for hit in hits:
        timestamp = hit.get("_source", {}).get("@timestamp")
        if not isinstance(timestamp, str):
            continue
        try:
            values.append(datetime.fromisoformat(timestamp.replace("Z", "+00:00")))
        except ValueError:
            continue
    return max(values) if values else None


def run_detection_once() -> dict[str, int]:
    """Evaluate all enabled rules and persist idempotent alert documents."""
    postgres.ensure_schema()
    created = 0
    evaluated = 0
    for row in postgres.list_rules():
        rule = DetectionRule.from_row(row)
        if not rule.enabled:
            continue
        checkpoint = postgres.get_checkpoint(rule.id)
        hits = fetch_events(checkpoint)
        matched = 0
        for hit in hits:
            evaluated += 1
            if not rule_matches(rule, hit["_source"]):
                continue
            matched += 1
            if index_alert(build_alert_document(rule, hit)):
                created += 1
        postgres.update_checkpoint(rule.id, _latest_timestamp(hits) or checkpoint, len(hits), matched)
    return {"events_evaluated": evaluated, "alerts_created": created}
