from fastapi.testclient import TestClient

from app.main import app


def test_alert_summary_returns_service_data(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.api.alerts.alert_summary",
        lambda: {"total": 2, "open": 1, "acknowledged": 1, "dismissed": 0, "escalated": 0, "critical": 0, "high": 1},
    )

    response = TestClient(app).get("/alerts/summary")

    assert response.status_code == 200
    assert response.json()["open"] == 1


def test_alert_action_delegates_lifecycle_update(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.api.alerts.update_alert_status",
        lambda **kwargs: {"alert_id": kwargs["alert_id"], "status": "acknowledged"},
    )

    response = TestClient(app).patch("/alerts/alert-1", json={"action": "acknowledge", "actor": "analyst"})

    assert response.status_code == 200
    assert response.json() == {"alert_id": "alert-1", "status": "acknowledged"}
