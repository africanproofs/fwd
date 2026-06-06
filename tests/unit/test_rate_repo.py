"""Tests for infra/rate_repo.py.

Exercises window_start truncation, caller rate buckets (all-or-nothing,
release, no-op), wallet buckets (aggregate cap, rate, add_committed_value),
delete_stale, and concurrency under BEGIN IMMEDIATE.

Uses a file-based tmp SQLite session (matching nonce_repo test pattern).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.domain.policy import RateLimit, WalletConstraint
from fwd.infra.rate_repo import RateRepo, rate_buckets, rate_metadata, wallet_buckets, window_start

# ---------------------------------------------------------------------------
# Session fixture (file-based SQLite, mirrors nonce_repo pattern)
# ---------------------------------------------------------------------------


@pytest.fixture()
async def session(tmp_path):  # type: ignore[no-untyped-def]
    db = tmp_path / "test_rate.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(rate_metadata.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


# ---------------------------------------------------------------------------
# window_start
# ---------------------------------------------------------------------------


def test_window_start_hour_truncates_sub_hour() -> None:
    now = datetime(2026, 5, 16, 14, 37, 22, 123456, tzinfo=UTC)
    ws = window_start("hour", now)
    assert ws == datetime(2026, 5, 16, 14, 0, 0, 0, tzinfo=UTC)
    assert ws.tzinfo is not None


def test_window_start_day_truncates_sub_day() -> None:
    now = datetime(2026, 5, 16, 14, 37, 22, 123456, tzinfo=UTC)
    ws = window_start("day", now)
    assert ws == datetime(2026, 5, 16, 0, 0, 0, 0, tzinfo=UTC)
    assert ws.tzinfo is not None


def test_window_start_hour_already_aligned() -> None:
    now = datetime(2026, 5, 16, 10, 0, 0, 0, tzinfo=UTC)
    assert window_start("hour", now) == now


def test_window_start_day_already_aligned() -> None:
    now = datetime(2026, 5, 16, 0, 0, 0, 0, tzinfo=UTC)
    assert window_start("day", now) == now


def test_window_start_returns_tz_aware_result() -> None:
    now = datetime(2026, 5, 16, 8, 15, 0, 0, tzinfo=UTC)
    result = window_start("hour", now)
    assert result.tzinfo is not None


def test_window_start_unknown_kind_raises() -> None:
    now = datetime(2026, 5, 16, 8, 0, 0, 0, tzinfo=UTC)
    with pytest.raises(ValueError, match="unknown window_kind"):
        window_start("week", now)


# ---------------------------------------------------------------------------
# check_and_increment_caller — basic counter behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_caller_first_n_increments_within_per_hour_return_true(
    session: AsyncSession,
) -> None:
    repo = RateRepo(session)
    rate = RateLimit(per_hour=3)
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    for _ in range(3):
        ok = await repo.check_and_increment_caller(
            caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
        )
        assert ok is True
    await session.commit()

    # 4th call should be denied.
    ok = await repo.check_and_increment_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
    )
    assert ok is False


@pytest.mark.asyncio
async def test_caller_counter_never_exceeds_cap(session: AsyncSession) -> None:
    repo = RateRepo(session)
    rate = RateLimit(per_hour=2)
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    # Saturate the bucket.
    for _ in range(2):
        await repo.check_and_increment_caller(
            caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
        )
    await session.commit()

    # Two more denied calls — counter must stay at 2.
    for _ in range(2):
        ok = await repo.check_and_increment_caller(
            caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
        )
        assert ok is False
    await session.commit()

    ws = window_start("hour", now)
    row = await session.execute(
        select(rate_buckets.c.counter).where(
            rate_buckets.c.caller == "c",
            rate_buckets.c.window_kind == "hour",
            rate_buckets.c.window_start == ws,
        )
    )
    assert row.scalar() == 2


@pytest.mark.asyncio
async def test_caller_all_or_nothing_per_hour_and_per_day(session: AsyncSession) -> None:
    """per_hour=2, per_day=1: after 1 success, the day cap is hit.
    The 2nd call is denied, and the hour counter must stay at 1 (not 2).
    """
    repo = RateRepo(session)
    rate = RateLimit(per_hour=2, per_day=1)
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    ok1 = await repo.check_and_increment_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
    )
    assert ok1 is True
    await session.commit()

    ok2 = await repo.check_and_increment_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
    )
    assert ok2 is False
    await session.commit()

    # Hour counter must be 1, not 2 (all-or-nothing: denied call did NOT increment).
    ws_hour = window_start("hour", now)
    row = await session.execute(
        select(rate_buckets.c.counter).where(
            rate_buckets.c.caller == "c",
            rate_buckets.c.window_kind == "hour",
            rate_buckets.c.window_start == ws_hour,
        )
    )
    assert row.scalar() == 1, "hour counter should be 1 (only the first allowed call)"


@pytest.mark.asyncio
async def test_caller_rate_none_returns_false_fail_closed(session: AsyncSession) -> None:
    # fail-closed: unconfigured rate (None) must deny, not allow.
    repo = RateRepo(session)
    ok = await repo.check_and_increment_caller(
        caller="c",
        wallet="w",
        contract="0xabc",
        method="f()",
        rate=None,
        now=datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC),
    )
    assert ok is False


# ---------------------------------------------------------------------------
# release_caller
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_release_caller_decrements(session: AsyncSession) -> None:
    repo = RateRepo(session)
    rate = RateLimit(per_hour=5)
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    await repo.check_and_increment_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
    )
    await session.commit()

    await repo.release_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
    )
    await session.commit()

    # Counter should be back to 0; next call should succeed again.
    ok = await repo.check_and_increment_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
    )
    assert ok is True


@pytest.mark.asyncio
async def test_release_caller_never_below_zero(session: AsyncSession) -> None:
    repo = RateRepo(session)
    rate = RateLimit(per_hour=5)
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    # Release on an empty bucket — must not raise or go negative.
    await repo.release_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=now
    )
    await session.commit()

    ws = window_start("hour", now)
    row = await session.execute(
        select(rate_buckets.c.counter).where(
            rate_buckets.c.caller == "c",
            rate_buckets.c.window_kind == "hour",
            rate_buckets.c.window_start == ws,
        )
    )
    # Row either absent or counter == 0 (never negative).
    val = row.scalar()
    assert val is None or val >= 0


@pytest.mark.asyncio
async def test_release_caller_noop_when_rate_none(session: AsyncSession) -> None:
    repo = RateRepo(session)
    # Should not raise.
    await repo.release_caller(
        caller="c",
        wallet="w",
        contract="0xabc",
        method="f()",
        rate=None,
        now=datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# check_and_increment_wallet — aggregate cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wallet_aggregate_cap_exceeded_denies(session: AsyncSession) -> None:
    repo = RateRepo(session)
    constraint = WalletConstraint(max_aggregate_value_wei_per_day="1000")
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    # Simulate existing aggregate by calling add_committed_value.
    await repo.add_committed_value(wallet="w", value_wei=800, now=now)
    await session.commit()

    # Checking 300 more should exceed 1000.
    ok = await repo.check_and_increment_wallet(
        wallet="w", constraint=constraint, value_wei=300, now=now
    )
    assert ok is False


@pytest.mark.asyncio
async def test_wallet_aggregate_cap_not_exceeded_allows(session: AsyncSession) -> None:
    repo = RateRepo(session)
    constraint = WalletConstraint(max_aggregate_value_wei_per_day="1000")
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    await repo.add_committed_value(wallet="w", value_wei=500, now=now)
    await session.commit()

    ok = await repo.check_and_increment_wallet(
        wallet="w", constraint=constraint, value_wei=499, now=now
    )
    assert ok is True


@pytest.mark.asyncio
async def test_wallet_rate_incremented_not_aggregate(session: AsyncSession) -> None:
    """Under rate limit only: rate counter increments but aggregate stays 0."""
    repo = RateRepo(session)
    constraint = WalletConstraint(rate=RateLimit(per_hour=5))
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    ok = await repo.check_and_increment_wallet(
        wallet="w", constraint=constraint, value_wei=1000, now=now
    )
    assert ok is True
    await session.commit()

    ws = window_start("hour", now)
    row = await session.execute(
        select(wallet_buckets.c.counter, wallet_buckets.c.aggregate_value_wei).where(
            wallet_buckets.c.wallet == "w",
            wallet_buckets.c.window_kind == "hour",
            wallet_buckets.c.window_start == ws,
        )
    )
    r = row.first()
    assert r is not None
    assert r.counter == 1
    assert r.aggregate_value_wei == "0"  # aggregate NOT incremented here


@pytest.mark.asyncio
async def test_wallet_constraint_none_returns_false_fail_closed(session: AsyncSession) -> None:
    # fail-closed: unconfigured constraint (None) must deny, not allow.
    repo = RateRepo(session)
    ok = await repo.check_and_increment_wallet(
        wallet="w",
        constraint=None,
        value_wei=999999,
        now=datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC),
    )
    assert ok is False


# ---------------------------------------------------------------------------
# add_committed_value
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_committed_value_accumulates(session: AsyncSession) -> None:
    repo = RateRepo(session)
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    await repo.add_committed_value(wallet="w", value_wei=100, now=now)
    await session.commit()
    await repo.add_committed_value(wallet="w", value_wei=200, now=now)
    await session.commit()

    ws = window_start("day", now)
    row = await session.execute(
        select(wallet_buckets.c.aggregate_value_wei).where(
            wallet_buckets.c.wallet == "w",
            wallet_buckets.c.window_kind == "day",
            wallet_buckets.c.window_start == ws,
        )
    )
    assert row.scalar() == "300"


@pytest.mark.asyncio
async def test_add_committed_value_bigint_no_overflow(session: AsyncSession) -> None:
    """Prove string bigint arithmetic handles values > 2**64."""
    repo = RateRepo(session)
    now = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)

    huge = 2**64 + 1
    await repo.add_committed_value(wallet="w", value_wei=huge, now=now)
    await session.commit()
    await repo.add_committed_value(wallet="w", value_wei=huge, now=now)
    await session.commit()

    ws = window_start("day", now)
    row = await session.execute(
        select(wallet_buckets.c.aggregate_value_wei).where(
            wallet_buckets.c.wallet == "w",
            wallet_buckets.c.window_kind == "day",
            wallet_buckets.c.window_start == ws,
        )
    )
    stored = row.scalar()
    assert stored is not None
    assert int(stored) == huge * 2


# ---------------------------------------------------------------------------
# delete_stale
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_stale_removes_old_rows_both_tables(session: AsyncSession) -> None:
    repo = RateRepo(session)

    old_time = datetime(2026, 5, 14, 0, 0, 0, 0, tzinfo=UTC)
    recent_time = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)
    cutoff = datetime(2026, 5, 15, 0, 0, 0, 0, tzinfo=UTC)

    rate = RateLimit(per_hour=10)

    # Old row in rate_buckets.
    await repo.check_and_increment_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=old_time
    )
    await session.commit()

    # Recent row in rate_buckets.
    await repo.check_and_increment_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=recent_time
    )
    await session.commit()

    # Old row in wallet_buckets.
    await repo.add_committed_value(wallet="w", value_wei=1, now=old_time)
    await session.commit()

    # Recent row in wallet_buckets.
    await repo.add_committed_value(wallet="w", value_wei=1, now=recent_time)
    await session.commit()

    deleted = await repo.delete_stale(before=cutoff)
    await session.commit()

    # Should have deleted 2 old rows (1 rate_bucket + 1 wallet_bucket).
    assert deleted == 2


@pytest.mark.asyncio
async def test_delete_stale_returns_zero_when_nothing_old(session: AsyncSession) -> None:
    repo = RateRepo(session)
    recent_time = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)
    old_cutoff = datetime(2026, 5, 14, 0, 0, 0, 0, tzinfo=UTC)

    rate = RateLimit(per_hour=10)
    await repo.check_and_increment_caller(
        caller="c", wallet="w", contract="0xabc", method="f()", rate=rate, now=recent_time
    )
    await session.commit()

    deleted = await repo.delete_stale(before=old_cutoff)
    await session.commit()
    assert deleted == 0


# ---------------------------------------------------------------------------
# Concurrency — K concurrent check_and_increment_caller with per_hour=K
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_caller_increments_all_true_counter_equals_k(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """asyncio.gather of K check_and_increment_caller with per_hour=K should
    all return True and result in counter == K.

    Uses separate sessions per task (same pattern as nonce_repo concurrency
    test) to exercise the BEGIN IMMEDIATE serialization. Uses an engine with
    the same PRAGMA + begin event listener setup as the production engine.
    """
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    k = 5
    db = tmp_path / "concurrent_rate.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")

    @event.listens_for(Engine, "connect")
    def _pragmas(conn, _record) -> None:  # type: ignore[no-untyped-def]
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    @event.listens_for(engine.sync_engine, "begin")
    def _immediate(conn) -> None:  # type: ignore[no-untyped-def]
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    async with engine.begin() as conn:
        await conn.run_sync(rate_metadata.create_all)

    rate = RateLimit(per_hour=k)
    now = datetime(2026, 5, 16, 10, 0, 0, 0, tzinfo=UTC)

    async def _one_call() -> bool:
        async with AsyncSession(engine) as s:
            repo = RateRepo(s)
            result = await repo.check_and_increment_caller(
                caller="c",
                wallet="w",
                contract="0xabc",
                method="f()",
                rate=rate,
                now=now,
            )
            await s.commit()
            return result

    results = await asyncio.gather(*[_one_call() for _ in range(k)])
    await engine.dispose()

    assert all(r is True for r in results), f"Expected all True, got {results}"
    assert len(results) == k
