"""Tests for RateRepo.delete_stale at-cutoff semantics.

Tests the delete_stale(before=cutoff) call directly, mirroring what
_startup_policy_load runs at boot (v0.5.0a7).

Per the spec note: testing the whole lifespan is heavy; a focused
delete_stale-at-cutoff test is sufficient. This is that focused test.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.infra.rate_repo import RateRepo, rate_buckets, rate_metadata, window_start


@pytest.fixture()
async def session(tmp_path):  # type: ignore[no-untyped-def]
    """Real tmp-sqlite with rate_buckets and wallet_buckets tables."""
    db = tmp_path / "test_delete_stale.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(rate_metadata.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


async def _insert_rate_bucket(
    session: AsyncSession,
    caller: str,
    window_kind: str,
    ws: datetime,
    counter: int = 1,
) -> None:
    """Insert a single rate_buckets row at the given window_start."""
    await session.execute(
        sqlite_insert(rate_buckets)
        .values(
            caller=caller,
            wallet="w",
            contract="0x" + "11" * 20,
            method="0xabcdef01",
            window_kind=window_kind,
            window_start=ws,
            counter=counter,
        )
        .on_conflict_do_nothing()
    )


@pytest.mark.asyncio
async def test_delete_stale_removes_old_rows_and_keeps_fresh(
    session: AsyncSession,
) -> None:
    """delete_stale(before=cutoff) removes rows with window_start < cutoff
    and leaves rows with window_start >= cutoff intact.
    """
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=2)

    # Stale row: window_start is 5 days ago.
    stale_ws = window_start("hour", now - timedelta(days=5))
    await _insert_rate_bucket(session, "caller-stale", "hour", stale_ws)

    # Fresh row: window_start is 1 day ago (within the 2-day window).
    fresh_ws = window_start("hour", now - timedelta(days=1))
    await _insert_rate_bucket(session, "caller-fresh", "hour", fresh_ws)

    await session.commit()

    # Run delete_stale with the same cutoff _startup_policy_load uses.
    deleted = await RateRepo(session).delete_stale(before=cutoff)
    assert deleted >= 1, f"Expected at least 1 deleted row, got {deleted}"

    # The fresh row must still be queryable.
    from sqlalchemy import select

    result = await session.execute(
        select(rate_buckets).where(rate_buckets.c.caller == "caller-fresh")
    )
    row = result.first()
    assert row is not None, "Fresh row was incorrectly deleted"

    # The stale row must be gone.
    result2 = await session.execute(
        select(rate_buckets).where(rate_buckets.c.caller == "caller-stale")
    )
    assert result2.first() is None, "Stale row was NOT deleted"


@pytest.mark.asyncio
async def test_delete_stale_returns_zero_on_empty_table(session: AsyncSession) -> None:
    """delete_stale on an empty table returns 0 without error."""
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=2)
    deleted = await RateRepo(session).delete_stale(before=cutoff)
    assert deleted == 0
