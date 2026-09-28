from __future__ import annotations

import logging
import os
from pathlib import Path

import boto3
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine

from alembic import command
from incident_agent.config import load_settings
from incident_agent.persistence.store import normalize_database_url

logger = logging.getLogger(__name__)

LEGACY_REVISION = "0004_add_incident_explanation"
CLAIM_REVISION = "0005_atomic_incident_claims"

_LEGACY_COLUMNS = {
    "alerts": frozenset(
        {
            "id",
            "source_id",
            "source_type",
            "alarm_arn",
            "alarm_name",
            "cloudwatch_state",
            "host_id",
            "reason",
            "status",
            "group_key",
            "incident_id",
            "grouped",
            "error_summary",
            "occurred_at",
            "created_at",
            "updated_at",
        }
    ),
    "incidents": frozenset(
        {
            "id",
            "source_id",
            "alarm_arn",
            "alarm_name",
            "host_id",
            "runbook_version",
            "state",
            "reason",
            "run_id",
            "operations_url",
            "evidence_json",
            "triage_json",
            "plan_json",
            "plan_hash",
            "explanation_json",
            "plan_expires_at",
            "approver_subject",
            "approval_decision",
            "approval_at",
            "report",
            "report_json",
            "error_message",
            "created_at",
            "updated_at",
        }
    ),
    "incident_events": frozenset(
        {"id", "incident_id", "alert_id", "event_type", "actor", "message", "metadata_json", "created_at"}
    ),
    "approval_decisions": frozenset(
        {
            "id",
            "incident_id",
            "actor",
            "decision",
            "submitted_plan_hash",
            "outcome",
            "error_reason",
            "created_at",
        }
    ),
}
_CLAIM_COLUMNS = frozenset(
    {
        "group_key",
        "processing_claim_token",
        "processing_owner_id",
        "processing_lease_expires_at",
        "processing_attempt",
    }
)
_LEGACY_INDEX_DDL = {
    "incidents_alarm_idx": "CREATE INDEX IF NOT EXISTS incidents_alarm_idx ON incidents (alarm_arn, created_at)",
    "incidents_state_idx": "CREATE INDEX IF NOT EXISTS incidents_state_idx ON incidents (state, updated_at)",
    "alerts_status_idx": "CREATE INDEX IF NOT EXISTS alerts_status_idx ON alerts (status, updated_at)",
    "alerts_group_idx": "CREATE INDEX IF NOT EXISTS alerts_group_idx ON alerts (group_key, occurred_at)",
    "alerts_incident_idx": "CREATE INDEX IF NOT EXISTS alerts_incident_idx ON alerts (incident_id)",
    "incident_events_incident_idx": (
        "CREATE INDEX IF NOT EXISTS incident_events_incident_idx ON incident_events (incident_id, created_at)"
    ),
    "incident_events_alert_idx": "CREATE INDEX IF NOT EXISTS incident_events_alert_idx ON incident_events (alert_id)",
    "approval_decisions_incident_idx": (
        "CREATE INDEX IF NOT EXISTS approval_decisions_incident_idx ON approval_decisions (incident_id, created_at)"
    ),
}


def _database_url() -> str:
    settings = load_settings()
    database_url = settings.database_url
    if not database_url and settings.database_secret_id:
        client = boto3.client("secretsmanager", region_name=settings.aws_region)
        response = client.get_secret_value(SecretId=settings.database_secret_id)
        database_url = str(response.get("SecretString", "")).strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL or DATABASE_SECRET_ID is required")
    return database_url


def _config(config_path: Path | None = None) -> Config:
    path = config_path or Path(os.getenv("ALEMBIC_CONFIG", Path.cwd() / "alembic.ini"))
    return Config(str(path))


def _validate_legacy_schema(engine: Engine) -> None:
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    missing_tables = sorted(set(_LEGACY_COLUMNS) - table_names)
    if missing_tables:
        raise RuntimeError("unversioned incident database is missing managed tables: " + ", ".join(missing_tables))

    for table_name, expected_columns in _LEGACY_COLUMNS.items():
        actual_columns = {column["name"] for column in inspector.get_columns(table_name)}
        missing_columns = sorted(expected_columns - actual_columns)
        unexpected_columns = sorted(actual_columns - expected_columns)
        if missing_columns or unexpected_columns:
            details = []
            if missing_columns:
                details.append("missing columns " + ", ".join(missing_columns))
            if unexpected_columns:
                details.append("unexpected columns " + ", ".join(unexpected_columns))
            raise RuntimeError(f"unversioned table {table_name} does not match revision 0004: " + "; ".join(details))

        primary_key = set(inspector.get_pk_constraint(table_name).get("constrained_columns") or [])
        if primary_key != {"id"}:
            raise RuntimeError(f"unversioned table {table_name} does not have the expected primary key")

    for table_name in ("alerts", "incidents"):
        unique_constraints = inspector.get_unique_constraints(table_name)
        if not any(set(item.get("column_names") or []) == {"source_id"} for item in unique_constraints):
            raise RuntimeError(f"unversioned table {table_name} does not have the expected source_id uniqueness")


def _repair_legacy_indexes(engine: Engine) -> None:
    with engine.begin() as connection:
        for statement in _LEGACY_INDEX_DDL.values():
            connection.execute(text(statement))


def _validate_legacy_data(engine: Engine) -> None:
    with engine.connect() as connection:
        conflicting_candidates = connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM (
                    SELECT incident.id
                    FROM incidents AS incident
                    JOIN alerts AS source_alert
                      ON source_alert.source_id = incident.source_id
                      OR source_alert.incident_id = incident.id
                    WHERE source_alert.group_key <> ''
                    GROUP BY incident.id
                    HAVING COUNT(DISTINCT source_alert.group_key) > 1
                ) AS conflicts
                """
            )
        ).scalar_one()
        if conflicting_candidates:
            raise RuntimeError(
                "cannot migrate unversioned incident data because alerts disagree for "
                f"{conflicting_candidates} incident record(s)"
            )

        duplicate_active_groups = connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM (
                    SELECT candidate.group_key
                    FROM (
                        SELECT incident.id, incident.state, MIN(source_alert.group_key) AS group_key
                        FROM incidents AS incident
                        JOIN alerts AS source_alert
                          ON source_alert.source_id = incident.source_id
                          OR source_alert.incident_id = incident.id
                        WHERE source_alert.group_key <> ''
                        GROUP BY incident.id, incident.state
                    ) AS candidate
                    WHERE candidate.state IN ('DIAGNOSING', 'AWAITING_APPROVAL', 'EXECUTING')
                    GROUP BY candidate.group_key
                    HAVING COUNT(*) > 1
                ) AS conflicts
                """
            )
        ).scalar_one()
        if duplicate_active_groups:
            raise RuntimeError(
                "cannot migrate unversioned incident data; resolve "
                f"{duplicate_active_groups} duplicate active group(s) first"
            )


def _database_revision(engine: Engine) -> str | None:
    if "alembic_version" not in inspect(engine).get_table_names():
        return None
    with engine.connect() as connection:
        revisions = list(connection.execute(text("SELECT version_num FROM alembic_version")).scalars())
    if len(revisions) != 1 or not revisions[0]:
        raise RuntimeError("alembic_version must contain exactly one revision")
    return str(revisions[0])


def _verify_head(engine: Engine, config: Config) -> None:
    expected_head = ScriptDirectory.from_config(config).get_current_head()
    actual_revision = _database_revision(engine)
    if actual_revision != expected_head or actual_revision != CLAIM_REVISION:
        raise RuntimeError("incident database did not reach the expected Alembic head")

    inspector = inspect(engine)
    incident_columns = {column["name"] for column in inspector.get_columns("incidents")}
    missing_claim_columns = sorted(_CLAIM_COLUMNS - incident_columns)
    if missing_claim_columns:
        raise RuntimeError("incident database is missing claim columns: " + ", ".join(missing_claim_columns))

    indexes = {item["name"]: item for item in inspector.get_indexes("incidents")}
    claim_index = indexes.get("incidents_active_group_unique")
    if claim_index is None or not claim_index.get("unique"):
        raise RuntimeError("incident database is missing the active-group unique index")

    all_indexes = {item["name"] for table_name in _LEGACY_COLUMNS for item in inspector.get_indexes(table_name)}
    missing_indexes = sorted(set(_LEGACY_INDEX_DDL) - all_indexes)
    if missing_indexes:
        raise RuntimeError("incident database is missing baseline indexes: " + ", ".join(missing_indexes))


def run_migrations(database_url: str, config_path: Path | None = None) -> None:
    previous_database_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = database_url
    config = _config(config_path)
    engine = create_engine(normalize_database_url(database_url), future=True)
    try:
        table_names = set(inspect(engine).get_table_names())
        managed_tables = set(_LEGACY_COLUMNS) & table_names
        revision = _database_revision(engine)

        if revision is None and managed_tables:
            _validate_legacy_schema(engine)
            _validate_legacy_data(engine)
            _repair_legacy_indexes(engine)
            command.stamp(config, LEGACY_REVISION)
            logger.info("validated and stamped unversioned incident schema at revision 0004")
        elif revision is None:
            logger.info("initializing empty incident database")

        command.upgrade(config, "head")
        _verify_head(engine, config)
        logger.info("incident database migration completed at revision 0005")
    finally:
        engine.dispose()
        if previous_database_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_database_url


def main() -> None:
    run_migrations(_database_url())


if __name__ == "__main__":
    main()
