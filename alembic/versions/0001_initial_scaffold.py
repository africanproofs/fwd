"""initial scaffold (no schema yet — Phase 5 lands the wallets/callers/nonces/transactions/audit_log tables)

Revision ID: 0001
Revises:
Create Date: 2026-05-01

"""

from __future__ import annotations

revision = "0001"
down_revision: str | None = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Empty scaffold. Phase 5 lands the actual schema migration that follows
    # docs/architecture.md § SQLite schema.
    pass


def downgrade() -> None:
    pass
