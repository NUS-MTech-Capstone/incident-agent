"""add atomic incident grouping and processing claims

Revision ID: 0005_atomic_incident_claims
Revises: 0004_add_incident_explanation
Create Date: 2026-08-28 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0005_atomic_incident_claims"
down_revision = "0004_add_incident_explanation"
branch_labels = None
depends_on = None

_ACTIVE_STATES = "'DIAGNOSING', 'AWAITING_APPROVAL', 'EXECUTING'"


def upgrade() -> None:
    op.add_column("incidents", sa.Column("group_key", sa.Text(), nullable=False, server_default=""))
    op.add_column(
        "incidents",
        sa.Column("processing_claim_token", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "incidents",
        sa.Column("processing_owner_id", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "incidents",
        sa.Column("processing_lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column("processing_attempt", sa.Integer(), nullable=False, server_default="0"),
    )

    connection = op.get_bind()
    conflicting_candidates = connection.execute(
        sa.text(
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
            f"cannot backfill incident groups because alerts disagree for {conflicting_candidates} incident record(s)"
        )

    connection.execute(
        sa.text(
            """
            UPDATE incidents AS incident
            SET group_key = candidate.group_key
            FROM (
                SELECT incident.id AS incident_id, MIN(source_alert.group_key) AS group_key
                FROM incidents AS incident
                JOIN alerts AS source_alert
                  ON source_alert.source_id = incident.source_id
                  OR source_alert.incident_id = incident.id
                WHERE source_alert.group_key <> ''
                GROUP BY incident.id
            ) AS candidate
            WHERE candidate.incident_id = incident.id
              AND incident.group_key = ''
            """
        )
    )
    active_conflicts = connection.execute(
        sa.text(
            f"""
            SELECT COUNT(*)
            FROM (
                SELECT group_key
                FROM incidents
                WHERE group_key <> '' AND state IN ({_ACTIVE_STATES})
                GROUP BY group_key
                HAVING COUNT(*) > 1
            ) AS conflicts
            """
        )
    ).scalar_one()
    if active_conflicts:
        raise RuntimeError(
            f"cannot enforce one active incident per group; resolve {active_conflicts} duplicate active group(s) first"
        )

    op.create_index(
        "incidents_active_group_unique",
        "incidents",
        ["group_key"],
        unique=True,
        postgresql_where=sa.text(f"group_key <> '' AND state IN ({_ACTIVE_STATES})"),
    )


def downgrade() -> None:
    op.drop_index("incidents_active_group_unique", table_name="incidents")
    op.drop_column("incidents", "processing_attempt")
    op.drop_column("incidents", "processing_lease_expires_at")
    op.drop_column("incidents", "processing_owner_id")
    op.drop_column("incidents", "processing_claim_token")
    op.drop_column("incidents", "group_key")
