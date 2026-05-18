"""Async repository for rate_buckets and wallet_buckets tables.

Implements the D14 rate-bucket substrate: per-caller-wallet-contract-method
call-count windows (hour/day) and per-wallet aggregate spend tracking.

Schema and semantics per decisions.md D14. Mirrors nonce_repo.py in its use
of module-level MetaData, SQLAlchemy core Table definitions, SELECT-then-
UPDATE atomicity under the engine-level BEGIN IMMEDIATE writer lock, and the
exported *_metadata name for test create_all calls.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, delete, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

# RateLimit and WalletConstraint are used at runtime in method bodies (rate.per_hour etc.).
from fwd.domain.policy import RateLimit, WalletConstraint  # noqa: TC001

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

rate_metadata = MetaData()

rate_buckets = Table(
    "rate_buckets",
    rate_metadata,
    Column("caller", String, nullable=False, primary_key=True),
    Column("wallet", String, nullable=False, primary_key=True),
    Column("contract", String, nullable=False, primary_key=True),
    Column("method", String, nullable=False, primary_key=True),
    Column("window_kind", String, nullable=False, primary_key=True),
    Column("window_start", DateTime(timezone=True), nullable=False, primary_key=True),
    Column("counter", Integer, nullable=False, default=0),
)

wallet_buckets = Table(
    "wallet_buckets",
    rate_metadata,
    Column("wallet", String, nullable=False, primary_key=True),
    Column("window_kind", String, nullable=False, primary_key=True),
    Column("window_start", DateTime(timezone=True), nullable=False, primary_key=True),
    Column("counter", Integer, nullable=False, default=0),
    Column("aggregate_value_wei", String, nullable=False, default="0"),
)

fsp_rate_buckets = Table(
    "fsp_rate_buckets",
    rate_metadata,
    Column("caller", String, nullable=False, primary_key=True),
    Column("wallet", String, nullable=False, primary_key=True),
    Column("message_type", String, nullable=False, primary_key=True),
    Column("window_kind", String, nullable=False, primary_key=True),
    Column("window_start", DateTime(timezone=True), nullable=False, primary_key=True),
    Column("counter", Integer, nullable=False, default=0),
)


class RateRepoError(Exception):
    """Raised on value-parsing errors in rate repo (e.g. non-decimal wei strings)."""


def window_start(kind: str, now: datetime) -> datetime:
    """Return the UTC-aligned window start for *kind* relative to *now*.

    *now* must be tz-aware UTC.
    'hour' -> truncate to the current hour (minute=second=microsecond=0).
    'day'  -> truncate to the current day (hour=minute=second=microsecond=0).
    Returns a tz-aware UTC datetime.
    """
    if kind == "hour":
        return now.replace(minute=0, second=0, microsecond=0)
    if kind == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"unknown window_kind: {kind!r}; expected 'hour' or 'day'")


def _parse_wei(value: str, label: str) -> int:
    """Parse *value* as a decimal integer; raise RateRepoError on failure."""
    try:
        return int(value)
    except (ValueError, TypeError) as exc:
        raise RateRepoError(f"{label} is not a valid decimal integer: {value!r}") from exc


class RateRepo:
    """Rate-bucket repository operating on a shared AsyncSession.

    All state-mutating methods operate under the engine-level BEGIN IMMEDIATE
    writer lock (set up in infra/db.py). The SELECT-then-UPDATE two-step
    (rather than UPDATE...RETURNING) preserves SQLite 3.31 compatibility per
    the nonce_repo doctrine.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Caller rate buckets
    # ------------------------------------------------------------------

    async def check_and_increment_caller(
        self,
        *,
        caller: str,
        wallet: str,
        contract: str,
        method: str,
        rate: RateLimit | None,
        now: datetime,
    ) -> bool:
        """Check caller rate limits and — if all pass — increment all windows.

        Returns True if allowed and counters were incremented; False if any
        window is at or over its cap (nothing is incremented on False —
        all-or-nothing semantics per D14).

        If *rate* is None, no limit applies: return True without DB access.
        """
        if rate is None:
            return True

        windows: list[tuple[str, int]] = []
        if rate.per_hour is not None:
            windows.append(("hour", rate.per_hour))
        if rate.per_day is not None:
            windows.append(("day", rate.per_day))

        # First pass: read all windows and check caps.
        for wk, cap in windows:
            ws = window_start(wk, now)
            row = await self._session.execute(
                select(rate_buckets.c.counter).where(
                    rate_buckets.c.caller == caller,
                    rate_buckets.c.wallet == wallet,
                    rate_buckets.c.contract == contract,
                    rate_buckets.c.method == method,
                    rate_buckets.c.window_kind == wk,
                    rate_buckets.c.window_start == ws,
                )
            )
            current = row.scalar()
            counter_val = current if current is not None else 0
            if counter_val >= cap:
                return False

        # Second pass: upsert-increment all windows.
        for wk, _cap in windows:
            ws = window_start(wk, now)
            stmt = (
                sqlite_insert(rate_buckets)
                .values(
                    caller=caller,
                    wallet=wallet,
                    contract=contract,
                    method=method,
                    window_kind=wk,
                    window_start=ws,
                    counter=1,
                )
                .on_conflict_do_update(
                    index_elements=[
                        rate_buckets.c.caller,
                        rate_buckets.c.wallet,
                        rate_buckets.c.contract,
                        rate_buckets.c.method,
                        rate_buckets.c.window_kind,
                        rate_buckets.c.window_start,
                    ],
                    set_={"counter": rate_buckets.c.counter + 1},
                )
            )
            await self._session.execute(stmt)

        return True

    async def release_caller(
        self,
        *,
        caller: str,
        wallet: str,
        contract: str,
        method: str,
        rate: RateLimit | None,
        now: datetime,
    ) -> None:
        """Conditionally decrement caller rate counters.

        Called on request failure after check_and_increment_caller succeeded,
        to undo the optimistic increment. Uses counter > 0 guard to prevent
        going negative. Ignores rowcount (best-effort decrement).

        No-op if *rate* is None.
        """
        if rate is None:
            return

        windows: list[str] = []
        if rate.per_hour is not None:
            windows.append("hour")
        if rate.per_day is not None:
            windows.append("day")

        for wk in windows:
            ws = window_start(wk, now)
            await self._session.execute(
                update(rate_buckets)
                .where(
                    rate_buckets.c.caller == caller,
                    rate_buckets.c.wallet == wallet,
                    rate_buckets.c.contract == contract,
                    rate_buckets.c.method == method,
                    rate_buckets.c.window_kind == wk,
                    rate_buckets.c.window_start == ws,
                    rate_buckets.c.counter > 0,
                )
                .values(counter=rate_buckets.c.counter - 1)
            )

    async def check_and_increment_fsp_caller(
        self,
        *,
        caller: str,
        wallet: str,
        message_type: str,
        rate: RateLimit | None,
        now: datetime,
    ) -> bool:
        """FSP analogue of check_and_increment_caller (fsp_rate_buckets).

        All-or-nothing across windows; rate is None -> True without DB.
        """
        if rate is None:
            return True

        windows: list[tuple[str, int]] = []
        if rate.per_hour is not None:
            windows.append(("hour", rate.per_hour))
        if rate.per_day is not None:
            windows.append(("day", rate.per_day))

        for wk, cap in windows:
            ws = window_start(wk, now)
            row = await self._session.execute(
                select(fsp_rate_buckets.c.counter).where(
                    fsp_rate_buckets.c.caller == caller,
                    fsp_rate_buckets.c.wallet == wallet,
                    fsp_rate_buckets.c.message_type == message_type,
                    fsp_rate_buckets.c.window_kind == wk,
                    fsp_rate_buckets.c.window_start == ws,
                )
            )
            current = row.scalar()
            counter_val = current if current is not None else 0
            if counter_val >= cap:
                return False

        for wk, _cap in windows:
            ws = window_start(wk, now)
            stmt = (
                sqlite_insert(fsp_rate_buckets)
                .values(
                    caller=caller,
                    wallet=wallet,
                    message_type=message_type,
                    window_kind=wk,
                    window_start=ws,
                    counter=1,
                )
                .on_conflict_do_update(
                    index_elements=[
                        fsp_rate_buckets.c.caller,
                        fsp_rate_buckets.c.wallet,
                        fsp_rate_buckets.c.message_type,
                        fsp_rate_buckets.c.window_kind,
                        fsp_rate_buckets.c.window_start,
                    ],
                    set_={"counter": fsp_rate_buckets.c.counter + 1},
                )
            )
            await self._session.execute(stmt)

        return True

    async def release_fsp_caller(
        self,
        *,
        caller: str,
        wallet: str,
        message_type: str,
        rate: RateLimit | None,
        now: datetime,
    ) -> None:
        """FSP analogue of release_caller. No-op if rate is None."""
        if rate is None:
            return

        windows: list[str] = []
        if rate.per_hour is not None:
            windows.append("hour")
        if rate.per_day is not None:
            windows.append("day")

        for wk in windows:
            ws = window_start(wk, now)
            await self._session.execute(
                update(fsp_rate_buckets)
                .where(
                    fsp_rate_buckets.c.caller == caller,
                    fsp_rate_buckets.c.wallet == wallet,
                    fsp_rate_buckets.c.message_type == message_type,
                    fsp_rate_buckets.c.window_kind == wk,
                    fsp_rate_buckets.c.window_start == ws,
                    fsp_rate_buckets.c.counter > 0,
                )
                .values(counter=fsp_rate_buckets.c.counter - 1)
            )

    # ------------------------------------------------------------------
    # Wallet buckets
    # ------------------------------------------------------------------

    async def check_and_increment_wallet(
        self,
        *,
        wallet: str,
        constraint: WalletConstraint | None,
        value_wei: int,
        now: datetime,
    ) -> bool:
        """Check wallet constraints and — if all pass — increment rate counters.

        Aggregate check: if max_aggregate_value_wei_per_day is set, the
        existing day aggregate + value_wei must not exceed the cap.

        Rate check: same all-or-nothing logic as check_and_increment_caller.

        NOTE: aggregate_value_wei is NOT incremented here. It is incremented
        post-broadcast-success by add_committed_value (per D14 asymmetry:
        only committed value counts toward the aggregate).

        Returns True if allowed; False if any limit is exceeded (nothing
        incremented on False).
        """
        if constraint is None:
            return True

        # Aggregate cap check (day window only).
        if constraint.max_aggregate_value_wei_per_day is not None:
            cap = _parse_wei(
                constraint.max_aggregate_value_wei_per_day,
                "max_aggregate_value_wei_per_day",
            )
            ws = window_start("day", now)
            row = await self._session.execute(
                select(wallet_buckets.c.aggregate_value_wei).where(
                    wallet_buckets.c.wallet == wallet,
                    wallet_buckets.c.window_kind == "day",
                    wallet_buckets.c.window_start == ws,
                )
            )
            raw = row.scalar()
            current_agg = _parse_wei(raw, "aggregate_value_wei") if raw is not None else 0
            if current_agg + value_wei > cap:
                return False

        # Rate cap check (all-or-nothing across windows).
        rate = constraint.rate
        if rate is not None:
            windows: list[tuple[str, int]] = []
            if rate.per_hour is not None:
                windows.append(("hour", rate.per_hour))
            if rate.per_day is not None:
                windows.append(("day", rate.per_day))

            for wk, cap in windows:
                ws = window_start(wk, now)
                row = await self._session.execute(
                    select(wallet_buckets.c.counter).where(
                        wallet_buckets.c.wallet == wallet,
                        wallet_buckets.c.window_kind == wk,
                        wallet_buckets.c.window_start == ws,
                    )
                )
                current = row.scalar()
                counter_val = current if current is not None else 0
                if counter_val >= cap:
                    return False

            # Increment rate counters (not aggregate).
            for wk, _cap in windows:
                ws = window_start(wk, now)
                stmt = (
                    sqlite_insert(wallet_buckets)
                    .values(
                        wallet=wallet,
                        window_kind=wk,
                        window_start=ws,
                        counter=1,
                        aggregate_value_wei="0",
                    )
                    .on_conflict_do_update(
                        index_elements=[
                            wallet_buckets.c.wallet,
                            wallet_buckets.c.window_kind,
                            wallet_buckets.c.window_start,
                        ],
                        set_={"counter": wallet_buckets.c.counter + 1},
                    )
                )
                await self._session.execute(stmt)

        return True

    async def release_wallet(
        self,
        *,
        wallet: str,
        constraint: WalletConstraint | None,
        now: datetime,
    ) -> None:
        """Conditionally decrement wallet rate counters (NOT aggregate).

        Called on request failure after check_and_increment_wallet succeeded.
        Aggregate is never decremented (only committed value counts).
        No-op if *constraint* is None or has no rate.
        """
        if constraint is None or constraint.rate is None:
            return

        rate = constraint.rate
        windows: list[str] = []
        if rate.per_hour is not None:
            windows.append("hour")
        if rate.per_day is not None:
            windows.append("day")

        for wk in windows:
            ws = window_start(wk, now)
            await self._session.execute(
                update(wallet_buckets)
                .where(
                    wallet_buckets.c.wallet == wallet,
                    wallet_buckets.c.window_kind == wk,
                    wallet_buckets.c.window_start == ws,
                    wallet_buckets.c.counter > 0,
                )
                .values(counter=wallet_buckets.c.counter - 1)
            )

    async def add_committed_value(
        self,
        *,
        wallet: str,
        value_wei: int,
        now: datetime,
    ) -> None:
        """Add *value_wei* to the day wallet bucket's aggregate_value_wei.

        Called post-broadcast-success (the request was committed to chain).
        Uses string bigint arithmetic to avoid overflow.
        """
        ws = window_start("day", now)
        row = await self._session.execute(
            select(wallet_buckets.c.aggregate_value_wei).where(
                wallet_buckets.c.wallet == wallet,
                wallet_buckets.c.window_kind == "day",
                wallet_buckets.c.window_start == ws,
            )
        )
        raw = row.scalar()
        existing = _parse_wei(raw, "aggregate_value_wei") if raw is not None else 0
        new_agg = str(existing + value_wei)
        stmt = (
            sqlite_insert(wallet_buckets)
            .values(
                wallet=wallet,
                window_kind="day",
                window_start=ws,
                counter=0,
                aggregate_value_wei=new_agg,
            )
            .on_conflict_do_update(
                index_elements=[
                    wallet_buckets.c.wallet,
                    wallet_buckets.c.window_kind,
                    wallet_buckets.c.window_start,
                ],
                set_={"aggregate_value_wei": new_agg},
            )
        )
        await self._session.execute(stmt)

    async def delete_stale(self, *, before: datetime) -> int:
        """Delete rows in all rate tables with window_start < *before*.

        Returns the total number of rows deleted across all three tables.
        Called at policy-load by the a6 integration ship.
        """
        result_rb = await self._session.execute(
            delete(rate_buckets).where(rate_buckets.c.window_start < before)
        )
        result_wb = await self._session.execute(
            delete(wallet_buckets).where(wallet_buckets.c.window_start < before)
        )
        result_fsp = await self._session.execute(
            delete(fsp_rate_buckets).where(fsp_rate_buckets.c.window_start < before)
        )
        return (result_rb.rowcount or 0) + (result_wb.rowcount or 0) + (result_fsp.rowcount or 0)  # type: ignore[attr-defined]
