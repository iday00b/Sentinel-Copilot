from datetime import UTC, datetime

from app.models.detection import DetectionRule
from app.services.detector import alert_fingerprint, build_alert_document, rule_matches


def ssh_failure_rule() -> DetectionRule:
    return DetectionRule(
        id="AUTH-SSH-FAILED-LOGIN",
        name="SSH failed login",
        enabled=True,
        severity=6,
        mitre_tactic="Credential Access",
        mitre_technique="T1110",
        condition={"event.action": "ssh_login", "event.outcome": "failure"},
        version=1,
    )


def test_rule_matches_nested_normalized_event() -> None:
    assert rule_matches(ssh_failure_rule(), {"event": {"action": "ssh_login", "outcome": "failure"}})
    assert not rule_matches(ssh_failure_rule(), {"event": {"action": "ssh_login", "outcome": "success"}})


def test_alert_document_has_stable_idempotency_key_and_entities() -> None:
    hit = {
        "_index": "sentinel-security-events-2026.08.14",
        "_id": "event-1",
        "_source": {
            "@timestamp": "2026-08-14T08:30:00Z",
            "message": "Failed SSH login",
            "host": {"name": "web-01"},
            "user": {"name": "admin"},
            "source": {"ip": "203.0.113.42"},
        },
    }

    alert = build_alert_document(ssh_failure_rule(), hit, now=datetime(2026, 8, 14, 9, tzinfo=UTC))

    assert alert["alert_id"] == alert_fingerprint("AUTH-SSH-FAILED-LOGIN", hit["_index"], "event-1")
    assert alert["status"] == "open"
    assert alert["entities"] == {"host": "web-01", "user": "admin", "source_ip": "203.0.113.42"}
    assert alert["mitre"] == {"tactic": "Credential Access", "technique": "T1110"}
