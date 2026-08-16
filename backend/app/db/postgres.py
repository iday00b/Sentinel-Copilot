"""PostgreSQL storage for detection configuration and analyst audit history."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.core.config import settings


class DatabaseUnavailableError(Exception):
    """Raised when PostgreSQL cannot serve application data."""


DEFAULT_RULE = {
    "id": "AUTH-SSH-FAILED-LOGIN",
    "name": "SSH failed login",
    "description": "Detect a failed SSH authentication attempt.",
    "enabled": True,
    "severity": 6,
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110",
    "condition": {"event.action": "ssh_login", "event.outcome": "failure"},
    "version": 1,
}


@contextmanager
def connection() -> Iterator[psycopg.Connection[Any]]:
    """Yield a transaction-aware PostgreSQL connection."""
    try:
        with psycopg.connect(settings.postgres_dsn, row_factory=dict_row) as conn:
            yield conn
    except psycopg.Error as exc:
        raise DatabaseUnavailableError("PostgreSQL is unavailable") from exc


def ensure_schema() -> None:
    """Create Module 004 application tables and the first detection rule."""
    statements = [
        """
        CREATE TABLE IF NOT EXISTS detection_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 10),
            mitre_tactic TEXT,
            mitre_technique TEXT,
            condition JSONB NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS detection_rule_versions (
            rule_id TEXT NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
            version INTEGER NOT NULL,
            definition JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (rule_id, version)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS detector_checkpoints (
            rule_id TEXT PRIMARY KEY REFERENCES detection_rules(id) ON DELETE CASCADE,
            last_event_timestamp TIMESTAMPTZ,
            last_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            events_evaluated INTEGER NOT NULL DEFAULT 0,
            alerts_created INTEGER NOT NULL DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS alert_actions (
            id BIGSERIAL PRIMARY KEY,
            alert_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            comment TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS alert_actions_alert_id_idx ON alert_actions(alert_id)",
    ]
    with connection() as conn:
        with conn.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)
            cursor.execute(
                """
                INSERT INTO detection_rules (
                    id, name, description, enabled, severity, mitre_tactic,
                    mitre_technique, condition, version
                ) VALUES (
                    %(id)s, %(name)s, %(description)s, %(enabled)s, %(severity)s,
                    %(mitre_tactic)s, %(mitre_technique)s, %(condition)s::jsonb, %(version)s
                ) ON CONFLICT (id) DO NOTHING
                """,
                {**DEFAULT_RULE, "condition": Jsonb(DEFAULT_RULE["condition"])},
            )
            cursor.execute(
                """
                INSERT INTO detection_rule_versions (rule_id, version, definition)
                VALUES (%(id)s, %(version)s, %(definition)s::jsonb)
                ON CONFLICT (rule_id, version) DO NOTHING
                """,
                {
                    "id": DEFAULT_RULE["id"],
                    "version": DEFAULT_RULE["version"],
                    "definition": Jsonb(DEFAULT_RULE),
                },
            )


def list_rules() -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cursor:
        cursor.execute("SELECT * FROM detection_rules ORDER BY id")
        return list(cursor.fetchall())


def set_rule_enabled(rule_id: str, enabled: bool) -> dict[str, Any] | None:
    with connection() as conn, conn.cursor() as cursor:
        cursor.execute(
            """
            UPDATE detection_rules
            SET enabled = %s, updated_at = NOW()
            WHERE id = %s
            RETURNING *
            """,
            (enabled, rule_id),
        )
        return cursor.fetchone()


def get_checkpoints() -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.*, r.name AS rule_name, r.enabled
            FROM detector_checkpoints AS c
            JOIN detection_rules AS r ON r.id = c.rule_id
            ORDER BY c.last_run_at DESC
            """
        )
        return list(cursor.fetchall())


def get_checkpoint(rule_id: str) -> datetime | None:
    with connection() as conn, conn.cursor() as cursor:
        cursor.execute(
            "SELECT last_event_timestamp FROM detector_checkpoints WHERE rule_id = %s",
            (rule_id,),
        )
        row = cursor.fetchone()
        return row["last_event_timestamp"] if row else None


def update_checkpoint(
    rule_id: str,
    last_event_timestamp: datetime | None,
    events_evaluated: int,
    alerts_created: int,
) -> None:
    with connection() as conn, conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO detector_checkpoints (
                rule_id, last_event_timestamp, last_run_at, events_evaluated, alerts_created
            ) VALUES (%s, %s, NOW(), %s, %s)
            ON CONFLICT (rule_id) DO UPDATE SET
                last_event_timestamp = EXCLUDED.last_event_timestamp,
                last_run_at = EXCLUDED.last_run_at,
                events_evaluated = EXCLUDED.events_evaluated,
                alerts_created = EXCLUDED.alerts_created
            """,
            (rule_id, last_event_timestamp, events_evaluated, alerts_created),
        )


def record_alert_action(alert_id: str, action: str, actor: str, comment: str | None) -> dict[str, Any]:
    with connection() as conn, conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO alert_actions (alert_id, action, actor, comment)
            VALUES (%s, %s, %s, %s)
            RETURNING *
            """,
            (alert_id, action, actor, comment),
        )
        row = cursor.fetchone()
        assert row is not None
        return row
