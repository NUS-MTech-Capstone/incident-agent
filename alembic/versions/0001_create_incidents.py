"""create incidents table

Revision ID: 0001_create_incidents
Revises:
Create Date: 2026-07-02 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0001_create_incidents"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("source_id", sa.String(), nullable=False, unique=True),
        sa.Column("alarm_arn", sa.Text(), nullable=False),
        sa.Column("alarm_name", sa.Text(), nullable=False),
        sa.Column("host_id", sa.Text(), nullable=False),
        sa.Column("runbook_version", sa.Text(), nullable=False, server_default=""),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("run_id", sa.Text(), nullable=False, server_default=""),
        sa.Column("operations_url", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence_json", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("plan_json", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("plan_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("approver_subject", sa.Text(), nullable=False, server_default=""),
        sa.Column("approval_decision", sa.Text(), nullable=False, server_default=""),
        sa.Column("approval_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("report", sa.Text(), nullable=False, server_default=""),
        sa.Column("error_message", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("incidents_alarm_idx", "incidents", ["alarm_arn", "created_at"])
    op.create_index("incidents_state_idx", "incidents", ["state", "updated_at"])


def downgrade() -> None:
    op.drop_index("incidents_state_idx", table_name="incidents")
    op.drop_index("incidents_alarm_idx", table_name="incidents")
    op.drop_table("incidents")
