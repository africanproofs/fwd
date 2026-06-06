"""Async repository for the nonces table.

Schema mirrors architecture.md § SQLite schema:
  nonces(wallet PK, chain PK, next_nonce, last_confirmed, last_reconciled_at)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, case, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

metadata = MetaData()

nonces = Table(
    "nonces",
    metadata,
    Column("wallet", String, nullable=False, primary_key=True),
    Column("chain", Integer, nullable=False, primary_key=True),
    Column("next_nonce", Integer, nullable=False),
    Column("last_confirmed", Integer, nullable=True),
    Column("last_reconciled_at", DateTime(timezone=True), nullable=False),
)


@dataclass(frozen=True)
class Nonce:
    wallet: str
    chain: int
    next_nonce: int
    last_confirmed: int | None
    last_reconciled_at: datetime


class NonceNotInitializedError(Exception):
    """Raised when reserve_next or get is called for (wallet, chain) with no row."""


class NonceWalletNotFoundError(Exception):
    """Raised when init_for_wallet references a wallet that doesn't exist (FK violation)."""


class NonceRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def init_for_wallet(
        self, wallet: str, chain: int, starting_nonce: int, force: bool = False
    ) -> Nonce:
        """Insert a nonces row with next_nonce=starting_nonce.

        Default (force=False): idempotent — if row exists, return the existing
        row UNCHANGED (do not overwrite).

        force=True: overwrite an existing row to the exact state a fresh init
        produces (next_nonce=starting_nonce, last_confirmed=None). Use to
        correct a mis-seeded nonce.
        """
        now = datetime.now(UTC)
        base_stmt = sqlite_insert(nonces).values(
            wallet=wallet,
            chain=chain,
            next_nonce=starting_nonce,
            last_confirmed=None,
            last_reconciled_at=now,
        )
        if force:
            stmt = base_stmt.on_conflict_do_update(
                index_elements=["wallet", "chain"],
                set_={
                    "next_nonce": starting_nonce,
                    "last_confirmed": None,
                    "last_reconciled_at": now,
                },
            )
        else:
            stmt = base_stmt.on_conflict_do_nothing()
        try:
            await self._session.execute(stmt)
        except IntegrityError as exc:
            # FK violation: wallet not found in wallets table.
            raise NonceWalletNotFoundError(wallet) from exc
        result = await self._session.execute(
            select(nonces).where(nonces.c.wallet == wallet, nonces.c.chain == chain)
        )
        row = result.first()
        assert row is not None
        return Nonce(
            wallet=row.wallet,
            chain=row.chain,
            next_nonce=row.next_nonce,
            last_confirmed=row.last_confirmed,
            last_reconciled_at=row.last_reconciled_at,
        )

    async def reserve_next(self, wallet: str, chain: int) -> int:
        """Atomically reserve and return the next nonce.

        Implements architecture.md § Signing flow step 6:
          BEGIN IMMEDIATE;
          SELECT next_nonce (= N);
          UPDATE next_nonce = N + 1;
          COMMIT;
        and returns N.

        Compatibility note: this two-step form (instead of a single
        `UPDATE...RETURNING`) targets SQLite 3.31 — the version shipped with
        Python 3.12 on glibc-2.31 hosts (Ubuntu 20.04 / dev box). The Docker
        runtime ships SQLite 3.40+ which supports RETURNING; both forms are
        functionally identical under BEGIN IMMEDIATE because the writer lock
        is held across both statements. The two-step is doctrine for
        cross-environment portability. See architecture.md § Signing flow.

        Concurrency: under the BEGIN IMMEDIATE writer lock (engine event
        listener in infra/db.py), concurrent reserve_next calls serialize
        and produce monotonic nonces.

        Raises NonceNotInitializedError if no row exists for (wallet, chain).
        """
        sel = await self._session.execute(
            select(nonces.c.next_nonce).where(nonces.c.wallet == wallet, nonces.c.chain == chain)
        )
        row = sel.first()
        if row is None:
            raise NonceNotInitializedError(f"no nonces row for wallet={wallet!r} chain={chain}")
        current: int = row.next_nonce
        await self._session.execute(
            update(nonces)
            .where(nonces.c.wallet == wallet, nonces.c.chain == chain)
            .values(next_nonce=current + 1)
        )
        return current

    async def release_if_unused(self, wallet: str, chain: int, reserved: int) -> bool:
        """Conditional decrement per architecture.md § Failure modes step 10.

        Verbatim:
          UPDATE nonces SET next_nonce = next_nonce - 1
            WHERE wallet = :w AND chain = :c AND next_nonce - 1 = :reserved

        Returns True if decremented (we were the most-recent reserver).
        Returns False if NOT decremented (someone else reserved after us;
        leave the gap — the nonce is operator-visible drift).
        """
        stmt = (
            update(nonces)
            .where(
                nonces.c.wallet == wallet,
                nonces.c.chain == chain,
                nonces.c.next_nonce - 1 == reserved,
            )
            .values(next_nonce=nonces.c.next_nonce - 1)
        )
        result = await self._session.execute(stmt)
        return result.rowcount == 1  # type: ignore[attr-defined, no-any-return]

    async def mark_confirmed(self, wallet: str, chain: int, confirmed_nonce: int) -> None:
        """Set last_confirmed = MAX(last_confirmed, confirmed_nonce).
        Called by the receipt-report path (api/transactions.py) when a client
        reports a confirmed broadcast outcome."""
        stmt = (
            update(nonces)
            .where(nonces.c.wallet == wallet, nonces.c.chain == chain)
            .values(
                last_confirmed=case(
                    (
                        nonces.c.last_confirmed.is_(None)
                        | (nonces.c.last_confirmed < confirmed_nonce),
                        confirmed_nonce,
                    ),
                    else_=nonces.c.last_confirmed,
                )
            )
        )
        await self._session.execute(stmt)

    async def get(self, wallet: str, chain: int, *, missing_ok: bool = False) -> Nonce | None:
        """Fetch the nonces row. Raises NonceNotInitializedError if missing
        unless missing_ok=True."""
        result = await self._session.execute(
            select(nonces).where(nonces.c.wallet == wallet, nonces.c.chain == chain)
        )
        row = result.first()
        if row is None:
            if missing_ok:
                return None
            raise NonceNotInitializedError(f"no nonces row for wallet={wallet!r} chain={chain}")
        return Nonce(
            wallet=row.wallet,
            chain=row.chain,
            next_nonce=row.next_nonce,
            last_confirmed=row.last_confirmed,
            last_reconciled_at=row.last_reconciled_at,
        )

    async def set_next_nonce(self, wallet: str, chain: int, value: int) -> None:
        """Directly set next_nonce to *value* and last_confirmed to value - 1.

        Admin-only use: called by POST /v1/admin/nonce-sync after bounds check.
        Does not validate that *value* > current next_nonce — the caller is
        responsible for the bounded-monotonic-advance guard.
        """
        await self._session.execute(
            update(nonces)
            .where(nonces.c.wallet == wallet, nonces.c.chain == chain)
            .values(next_nonce=value, last_confirmed=value - 1)
        )

    async def list_all(self) -> list[Nonce]:
        """List every nonces row. Used by app/nonce_reconcile.py."""
        result = await self._session.execute(select(nonces))
        return [
            Nonce(
                wallet=row.wallet,
                chain=row.chain,
                next_nonce=row.next_nonce,
                last_confirmed=row.last_confirmed,
                last_reconciled_at=row.last_reconciled_at,
            )
            for row in result
        ]
