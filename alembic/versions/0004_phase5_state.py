"""Phase 5 state schema

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-11

Creates all Phase 5 tables per docs/architecture.md § SQLite schema:
  wallet_chains, nonces, transactions, transaction_args,
  transaction_hashes, audit_log.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision: str | None = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. wallet_chains — FK to wallets
    op.create_table(
        "wallet_chains",
        sa.Column("wallet", sa.String(), nullable=False),
        sa.Column("chain", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["wallet"], ["wallets.name"]),
        sa.PrimaryKeyConstraint("wallet", "chain"),
    )

    # 2. nonces — FK to wallets; composite PK (wallet, chain)
    op.create_table(
        "nonces",
        sa.Column("wallet", sa.String(), nullable=False),
        sa.Column("chain", sa.Integer(), nullable=False),
        sa.Column("next_nonce", sa.Integer(), nullable=False),
        sa.Column("last_confirmed", sa.Integer(), nullable=True),
        sa.Column(
            "last_reconciled_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.ForeignKeyConstraint(["wallet"], ["wallets.name"]),
        sa.PrimaryKeyConstraint("wallet", "chain"),
    )

    # 3. transactions — FK to wallets + callers; single PK tx_id
    op.create_table(
        "transactions",
        sa.Column("tx_id", sa.String(), primary_key=True),
        sa.Column("wallet", sa.String(), nullable=False),
        sa.Column("chain", sa.Integer(), nullable=False),
        sa.Column("caller", sa.String(), nullable=False),
        sa.Column("nonce", sa.Integer(), nullable=False),
        sa.Column("contract_address", sa.String(), nullable=False),
        sa.Column("method_name", sa.String(), nullable=False),
        sa.Column("value_wei", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=True),
        sa.Column("request_json", sa.String(), nullable=False),
        sa.Column("signed_raw", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("receipt_json", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.ForeignKeyConstraint(["wallet"], ["wallets.name"]),
        sa.ForeignKeyConstraint(["caller"], ["callers.name"]),
    )

    # 4. transaction_args — FK to transactions; composite PK (tx_id, arg_name)
    op.create_table(
        "transaction_args",
        sa.Column("tx_id", sa.String(), nullable=False),
        sa.Column("arg_name", sa.String(), nullable=False),
        sa.Column("arg_type", sa.String(), nullable=False),
        sa.Column("arg_value", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["tx_id"], ["transactions.tx_id"]),
        sa.PrimaryKeyConstraint("tx_id", "arg_name"),
    )

    # 5. transaction_hashes — FK to transactions; composite PK (tx_id, sequence_num)
    op.create_table(
        "transaction_hashes",
        sa.Column("tx_id", sa.String(), nullable=False),
        sa.Column("sequence_num", sa.Integer(), nullable=False),
        sa.Column("hash_hex", sa.String(), nullable=False),
        sa.Column(
            "submitted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.ForeignKeyConstraint(["tx_id"], ["transactions.tx_id"]),
        sa.PrimaryKeyConstraint("tx_id", "sequence_num"),
    )

    # 6. audit_log — standalone; seq AUTOINCREMENT PK
    op.create_table(
        "audit_log",
        sa.Column("seq", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("caller", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("request_json", sa.String(), nullable=True),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("decision_reason", sa.String(), nullable=True),
        sa.Column("outcome", sa.String(), nullable=True),
        sa.Column("prev_hash", sa.String(), nullable=False),
        sa.Column("row_hash", sa.String(), nullable=False),
    )

    # Indexes
    op.create_index(
        "idx_tx_idempotency",
        "transactions",
        ["caller", "idempotency_key"],
        unique=True,
        sqlite_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_index("idx_tx_status", "transactions", ["status"])
    op.create_index("idx_tx_wallet_chain_nonce", "transactions", ["wallet", "chain", "nonce"])
    op.create_index("idx_tx_method", "transactions", ["method_name", "contract_address"])
    op.create_index("idx_audit_caller_ts", "audit_log", ["caller", "ts"])


def downgrade() -> None:
    # Drop indexes first
    op.drop_index("idx_audit_caller_ts", table_name="audit_log")
    op.drop_index("idx_tx_method", table_name="transactions")
    op.drop_index("idx_tx_wallet_chain_nonce", table_name="transactions")
    op.drop_index("idx_tx_status", table_name="transactions")
    op.drop_index("idx_tx_idempotency", table_name="transactions")

    # Drop tables in reverse creation order
    op.drop_table("audit_log")
    op.drop_table("transaction_hashes")
    op.drop_table("transaction_args")
    op.drop_table("transactions")
    op.drop_table("nonces")
    op.drop_table("wallet_chains")
