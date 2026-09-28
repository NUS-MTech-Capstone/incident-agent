from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from alembic import command
from incident_agent.migrate import CLAIM_REVISION, LEGACY_REVISION, run_migrations
from incident_agent.persistence.store import normalize_database_url

_ROOT = Path(__file__).parents[1]
_BASELINE_INDEXES = {
    "incidents_alarm_idx",
    "incidents_state_idx",
    "alerts_status_idx",
    "alerts_group_idx",
    "alerts_incident_idx",
    "incident_events_incident_idx",
    "incident_events_alert_idx",
    "approval_decisions_incident_idx",
}


@pytest.fixture(autouse=True)
def postgres_database() -> Iterator[str]:
    database_url = os.getenv("INCIDENT_TEST_DATABASE_URL", "")
    if not database_url:
        pytest.skip("INCIDENT_TEST_DATABASE_URL is not configured")
    _reset_database(database_url)
    try:
        yield database_url
    finally:
        _reset_database(database_url)


def test_empty_database_migrates_to_head_and_is_idempotent(postgres_database: str) -> None:
    run_migrations(postgres_database, _ROOT / "alembic.ini")
    run_migrations(postgres_database, _ROOT / "alembic.ini")

    assert _revision(postgres_database) == CLAIM_REVISION
    inspector = _inspect(postgres_database)
    assert "incidents_active_group_unique" in {item["name"] for item in inspector.get_indexes("incidents")}


def test_unversioned_revision_0004_is_validated_repaired_and_upgraded(postgres_database: str) -> None:
    _upgrade_to(postgres_database, LEGACY_REVISION)
    engine = create_engine(normalize_database_url(postgres_database), future=True)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
        for index_name in _BASELINE_INDEXES:
            connection.execute(text(f'DROP INDEX IF EXISTS "{index_name}"'))  # noqa: S608 - fixed test identifiers
    engine.dispose()

    run_migrations(postgres_database, _ROOT / "alembic.ini")

    assert _revision(postgres_database) == CLAIM_REVISION
    inspector = _inspect(postgres_database)
    actual_indexes = {
        item["name"]
        for table_name in ("alerts", "incidents", "incident_events", "approval_decisions")
        for item in inspector.get_indexes(table_name)
    }
    assert _BASELINE_INDEXES <= actual_indexes


def test_unversioned_incompatible_schema_fails_without_stamping(postgres_database: str) -> None:
    _upgrade_to(postgres_database, LEGACY_REVISION)
    engine = create_engine(normalize_database_url(postgres_database), future=True)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
        connection.execute(text("ALTER TABLE incidents DROP COLUMN explanation_json"))
    engine.dispose()

    with pytest.raises(RuntimeError, match="missing columns explanation_json"):
        run_migrations(postgres_database, _ROOT / "alembic.ini")

    assert "alembic_version" not in _inspect(postgres_database).get_table_names()
    assert "processing_claim_token" not in _column_names(postgres_database, "incidents")


def test_conflicting_alert_groups_fail_without_leaking_values_or_partial_schema(postgres_database: str) -> None:
    _upgrade_to(postgres_database, LEGACY_REVISION)
    now = datetime.now(UTC)
    engine = create_engine(normalize_database_url(postgres_database), future=True)
    with engine.begin() as connection:
        _insert_incident(connection, "incident-1", "source-1", now)
        _insert_alert(connection, "alert-1", "source-1", "incident-1", "sensitive-group-one", now)
        _insert_alert(connection, "alert-2", "source-2", "incident-1", "sensitive-group-two", now)
    engine.dispose()

    with pytest.raises(RuntimeError) as exc_info:
        run_migrations(postgres_database, _ROOT / "alembic.ini")

    assert "alerts disagree for 1 incident record" in str(exc_info.value)
    assert "sensitive-group" not in str(exc_info.value)
    assert _revision(postgres_database) == LEGACY_REVISION
    assert "processing_claim_token" not in _column_names(postgres_database, "incidents")


def test_unversioned_duplicate_active_groups_fail_before_stamping(postgres_database: str) -> None:
    _upgrade_to(postgres_database, LEGACY_REVISION)
    now = datetime.now(UTC)
    engine = create_engine(normalize_database_url(postgres_database), future=True)
    with engine.begin() as connection:
        for index in (1, 2):
            _insert_incident(connection, f"incident-{index}", f"source-{index}", now)
            _insert_alert(
                connection,
                f"alert-{index}",
                f"source-{index}",
                f"incident-{index}",
                "sensitive-duplicate-group",
                now,
            )
        connection.execute(text("DROP TABLE alembic_version"))
    engine.dispose()

    with pytest.raises(RuntimeError) as exc_info:
        run_migrations(postgres_database, _ROOT / "alembic.ini")

    assert "resolve 1 duplicate active group" in str(exc_info.value)
    assert "sensitive-duplicate-group" not in str(exc_info.value)
    assert "alembic_version" not in _inspect(postgres_database).get_table_names()
    assert "processing_claim_token" not in _column_names(postgres_database, "incidents")


def _config(database_url: str) -> Config:
    os.environ["DATABASE_URL"] = database_url
    return Config(str(_ROOT / "alembic.ini"))


def _upgrade_to(database_url: str, revision: str) -> None:
    command.upgrade(_config(database_url), revision)


def _reset_database(database_url: str) -> None:
    engine = create_engine(normalize_database_url(database_url), future=True)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    engine.dispose()


def _inspect(database_url: str):  # type: ignore[no-untyped-def]
    engine = create_engine(normalize_database_url(database_url), future=True)
    return inspect(engine)


def _revision(database_url: str) -> str:
    engine = create_engine(normalize_database_url(database_url), future=True)
    with engine.connect() as connection:
        revision = str(connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one())
    engine.dispose()
    return revision


def _column_names(database_url: str, table_name: str) -> set[str]:
    inspector = _inspect(database_url)
    return {column["name"] for column in inspector.get_columns(table_name)}


def _insert_incident(connection, incident_id: str, source_id: str, now: datetime) -> None:  # type: ignore[no-untyped-def]
    connection.execute(
        text(
            """
            INSERT INTO incidents (
                id, source_id, alarm_arn, alarm_name, host_id, state, created_at, updated_at
            ) VALUES (
                :id, :source_id, 'arn:alarm', 'High 5xx', 'host-1', 'DIAGNOSING', :now, :now
            )
            """
        ),
        {"id": incident_id, "source_id": source_id, "now": now},
    )


def _insert_alert(
    connection,  # type: ignore[no-untyped-def]
    alert_id: str,
    source_id: str,
    incident_id: str,
    group_key: str,
    now: datetime,
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO alerts (
                id, source_id, alarm_arn, alarm_name, cloudwatch_state, host_id,
                status, group_key, incident_id, occurred_at, created_at, updated_at
            ) VALUES (
                :id, :source_id, 'arn:alarm', 'High 5xx', 'ALARM', 'host-1',
                'TRIAGING', :group_key, :incident_id, :now, :now, :now
            )
            """
        ),
        {
            "id": alert_id,
            "source_id": source_id,
            "group_key": group_key,
            "incident_id": incident_id,
            "now": now,
        },
    )
