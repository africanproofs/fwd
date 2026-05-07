"""create wallets table

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-02

Phase 3b ships ONLY the wallets table. Phase 5 adds callers / nonces /
transactions / transaction_args / transaction_hashes / audit_log /
wallet_chains.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision: str | None = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wallets",
        sa.Column("name", sa.String(), primary_key=True),
        sa.Column("address", sa.String(), nullable=False),
        sa.Column("privkey_ciphertext", sa.String(), nullable=False),
        sa.Column("vault_master_key", sa.String(), nullable=False),
        sa.Column("policy_path", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
    )


def downgrade() -> None:
    op.drop_table("wallets")
