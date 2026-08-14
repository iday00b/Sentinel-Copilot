import io
import json
from urllib.error import URLError

from fastapi.testclient import TestClient

from app.main import app
from app.services import security_events


class FakeResponse(io.BytesIO):
    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


def test_get_recent_security_events_queries_normalized_index(monkeypatch) -> None:
    captured_request = None

    def fake_urlopen(request, timeout):
        nonlocal captured_request
        captured_request = request
        assert timeout == 5
        return FakeResponse(
            json.dumps(
                {
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "message": "Failed SSH login",
                                    "event": {"outcome": "failure"},
                                }
                            }
                        ]
                    }
                }
            ).encode()
        )

    monkeypatch.setattr(security_events, "urlopen", fake_urlopen)

    events = security_events.get_recent_security_events(limit=5)

    assert events == [{"message": "Failed SSH login", "event": {"outcome": "failure"}}]
    assert captured_request.full_url.endswith("/sentinel-security-events-*/_search")
    assert json.loads(captured_request.data) == {
        "size": 5,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }


def test_recent_security_events_returns_events(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.api.security_events.get_recent_security_events",
        lambda limit: [{"message": "Failed SSH login", "event": {"outcome": "failure"}}],
    )

    response = TestClient(app).get("/security-events/recent?limit=1")

    assert response.status_code == 200
    assert response.json() == {
        "events": [{"message": "Failed SSH login", "event": {"outcome": "failure"}}]
    }


def test_recent_security_events_returns_service_unavailable(monkeypatch) -> None:
    def unavailable(_: int) -> None:
        raise security_events.SecurityEventsUnavailableError

    monkeypatch.setattr("app.api.security_events.get_recent_security_events", unavailable)

    response = TestClient(app).get("/security-events/recent")

    assert response.status_code == 503
    assert response.json() == {"detail": "Security events are temporarily unavailable"}


def test_get_recent_security_events_wraps_elasticsearch_connection_errors(monkeypatch) -> None:
    def failing_urlopen(*args, **kwargs):
        raise URLError("connection refused")

    monkeypatch.setattr(security_events, "urlopen", failing_urlopen)

    try:
        security_events.get_recent_security_events(limit=1)
    except security_events.SecurityEventsUnavailableError:
        pass
    else:
        raise AssertionError("Elasticsearch connection errors must be normalized")
