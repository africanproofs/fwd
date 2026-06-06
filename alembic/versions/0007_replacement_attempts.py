"""Replacement attempts substrate

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-27

Adds:
- `reserved_at` column (TIMESTAMP, nullable) to `transactions` — set at sign
  time; used for orphan-lease detection (GET /v1/admin/nonce/holes).
- `transaction_attempts` table — records every signed attempt for a tx_id
  (original = seq 1, each replacement = seq N+1) so the bump rule can read
  the prior attempt's fee and the retry cap can be enforced.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision: str | None = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add reserved_at to existing transactions table.
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.add_column(sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=True))

    # Create transaction_attempts table.
    op.create_table(
        "transaction_attempts",
        sa.Column("tx_id", sa.String(), nullable=False),
        sa.Column("sequence_num", sa.Integer(), nullable=False),
        sa.Column("gas", sa.Integer(), nullable=False),
        sa.Column("max_fee_per_gas", sa.Integer(), nullable=False),
        sa.Column("max_priority_fee_per_gas", sa.Integer(), nullable=False),
        sa.Column("signed_raw", sa.String(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tx_id", "sequence_num"),
    )


def downgrade() -> None:
    op.drop_table("transaction_attempts")
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.drop_column("reserved_at")
