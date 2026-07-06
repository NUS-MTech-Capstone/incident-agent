"""add incident explanation metadata

Revision ID: 0004_add_incident_explanation
Revises: 0003_agentic_trust_layer
Create Date: 2026-07-06 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0004_add_incident_explanation"
down_revision = "0003_agentic_trust_layer"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("explanation_json", postgresql.JSONB(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("incidents", "explanation_json")
