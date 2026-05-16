"""Phase 7 rate substrate schema

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-16

Creates rate_buckets and wallet_buckets tables per decisions.md D14.
These tables back the D14 10-step policy evaluation rate limiting:
  rate_buckets  — per-caller-wallet-contract-method call-count windows
  wallet_buckets — per-wallet aggregate spend + call-count windows
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision: str | None = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. rate_buckets: per-caller per-wallet per-contract per-method windows
    op.create_table(
        "rate_buckets",
        sa.Column("caller", sa.String(), nullable=False),
        sa.Column("wallet", sa.String(), nullable=False),
        sa.Column("contract", sa.String(), nullable=False),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("window_kind", sa.String(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("counter", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint(
            "caller", "wallet", "contract", "method", "window_kind", "window_start"
        ),
    )

    # 2. wallet_buckets: per-wallet aggregate spend + rate windows
    op.create_table(
        "wallet_buckets",
        sa.Column("wallet", sa.String(), nullable=False),
        sa.Column("window_kind", sa.String(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("counter", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("aggregate_value_wei", sa.String(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("wallet", "window_kind", "window_start"),
    )


def downgrade() -> None:
    op.drop_table("wallet_buckets")
    op.drop_table("rate_buckets")
