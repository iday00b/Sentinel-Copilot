"""Elasticsearch queries for normalized security events."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.core.config import settings

SECURITY_EVENTS_INDEX_PATTERN = "sentinel-security-events-*"


class SecurityEventsUnavailableError(Exception):
    """Raised when Elasticsearch cannot serve the security-event query."""


def get_recent_security_events(limit: int) -> list[dict[str, Any]]:
    """Return the newest normalized security events from Elasticsearch."""
    request_body = json.dumps(
        {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"match_all": {}},
        }
    ).encode("utf-8")
    request = Request(
        url=f"{settings.elasticsearch_url}/{SECURITY_EVENTS_INDEX_PATTERN}/_search",
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=settings.elasticsearch_timeout_seconds) as response:
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise SecurityEventsUnavailableError("Elasticsearch is unavailable") from exc

    hits = payload.get("hits", {}).get("hits", [])
    return [hit["_source"] for hit in hits if "_source" in hit]
