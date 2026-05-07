"""create callers table

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-07

Phase 4 ships the callers table per docs/architecture.md § SQLite schema.
Other tables (nonces, transactions, etc.) land in Phase 5.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision: str | None = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "callers",
        sa.Column("name", sa.String(), primary_key=True),
        sa.Column("api_key_hash", sa.String(), nullable=False, unique=True),
        sa.Column("api_key_prefix", sa.String(), nullable=False),
        sa.Column("policy_path", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Index on api_key_prefix for the require_caller fast path.
    op.create_index(
        "idx_callers_prefix_active",
        "callers",
        ["api_key_prefix"],
        postgresql_where=sa.text("revoked_at IS NULL"),
        sqlite_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("idx_callers_prefix_active", table_name="callers")
    op.drop_table("callers")
