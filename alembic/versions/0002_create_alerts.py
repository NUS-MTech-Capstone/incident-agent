"""create alerts table and incident triage

Revision ID: 0002_create_alerts
Revises: 0001_create_incidents
Create Date: 2026-07-05 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0002_create_alerts"
down_revision = "0001_create_incidents"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("triage_json", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("source_id", sa.String(), nullable=False, unique=True),
        sa.Column("source_type", sa.Text(), nullable=False, server_default="managed-server"),
        sa.Column("alarm_arn", sa.Text(), nullable=False),
        sa.Column("alarm_name", sa.Text(), nullable=False),
        sa.Column("cloudwatch_state", sa.Text(), nullable=False),
        sa.Column("host_id", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("group_key", sa.Text(), nullable=False, server_default=""),
        sa.Column("incident_id", sa.Text(), nullable=False, server_default=""),
        sa.Column("error_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("alerts_status_idx", "alerts", ["status", "updated_at"])
    op.create_index("alerts_group_idx", "alerts", ["group_key", "occurred_at"])
    op.create_index("alerts_incident_idx", "alerts", ["incident_id"])


def downgrade() -> None:
    op.drop_index("alerts_incident_idx", table_name="alerts")
    op.drop_index("alerts_group_idx", table_name="alerts")
    op.drop_index("alerts_status_idx", table_name="alerts")
    op.drop_table("alerts")
    op.drop_column("incidents", "triage_json")
