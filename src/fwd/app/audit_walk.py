"""App-layer walker for the hash-chained audit log.

The CLI (`clifwd audit`) must not import infra directly (layer rule: cli →
{app, domain} only). This module is the seam: it opens an AuditRepo via the
`get_audit_repo()` dependency and exposes three simple async functions for the
CLI to call.

In-process read-only access per D16 — no HTTP, no admin auth required. The
DB path is resolved by `fwd.infra.db.session_scope()` from FWD_DATABASE_URL
(or the default from Settings).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fwd.app.dependencies import get_audit_repo

if TYPE_CHECKING:
    from fwd.infra.audit_repo import AuditRow, VerifyResult


async def verify_chain(*, from_seq: int | None = None, to_seq: int | None = None) -> VerifyResult:
    """Walk the audit chain and return a VerifyResult.

    Delegates to AuditRepo.verify(); opens and closes a session_scope
    automatically via get_audit_repo().
    """
    async with get_audit_repo() as repo:
        return await repo.verify(from_seq=from_seq, to_seq=to_seq)


async def show_row(seq: int) -> AuditRow | None:
    """Return the AuditRow at *seq*, or None if absent."""
    async with get_audit_repo() as repo:
        return await repo.get(seq)


async def tail_rows(n: int = 20) -> list[AuditRow]:
    """Return the last *n* audit rows in ascending seq order."""
    async with get_audit_repo() as repo:
        return await repo.tail(n)
