"""FSP rate substrate

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-18

Dedicated FSP rate table (sibling of rate_buckets/wallet_buckets, per the
wallet_buckets precedent). SQLite cannot ALTER a column into an existing
composite PRIMARY KEY and alembic/env.py configures no batch mode, so a
discriminator column on rate_buckets is infeasible; a clean additive
create_table is the honest design.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision: str | None = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fsp_rate_buckets",
        sa.Column("caller", sa.String(), nullable=False),
        sa.Column("wallet", sa.String(), nullable=False),
        sa.Column("message_type", sa.String(), nullable=False),
        sa.Column("window_kind", sa.String(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("counter", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("caller", "wallet", "message_type", "window_kind", "window_start"),
    )


def downgrade() -> None:
    op.drop_table("fsp_rate_buckets")
