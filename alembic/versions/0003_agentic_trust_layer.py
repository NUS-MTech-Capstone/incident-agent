"""add agentic trust layer tables

Revision ID: 0003_agentic_trust_layer
Revises: 0002_create_alerts
Create Date: 2026-07-06 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0003_agentic_trust_layer"
down_revision = "0002_create_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("grouped", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("incidents", sa.Column("plan_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "incidents",
        sa.Column("report_json", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.create_table(
        "incident_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("alert_id", sa.String(), nullable=False, server_default=""),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False, server_default=""),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("incident_events_incident_idx", "incident_events", ["incident_id", "created_at"])
    op.create_index("incident_events_alert_idx", "incident_events", ["alert_id"])
    op.create_table(
        "approval_decisions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False, server_default=""),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("submitted_plan_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("error_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("approval_decisions_incident_idx", "approval_decisions", ["incident_id", "created_at"])


def downgrade() -> None:
    op.drop_index("approval_decisions_incident_idx", table_name="approval_decisions")
    op.drop_table("approval_decisions")
    op.drop_index("incident_events_alert_idx", table_name="incident_events")
    op.drop_index("incident_events_incident_idx", table_name="incident_events")
    op.drop_table("incident_events")
    op.drop_column("incidents", "report_json")
    op.drop_column("incidents", "plan_expires_at")
    op.drop_column("alerts", "grouped")
