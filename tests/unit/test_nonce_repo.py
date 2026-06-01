"""NonceRepo unit tests against a file-based SQLite (tmp_path).

Uses file-based SQLite (matching test_wallet_repo.py / test_transaction_repo.py
pattern) rather than in-memory to ensure WAL and FK pragma behaviour is
consistent.

The concurrent-reservation test (test_concurrent_reservations_are_monotonic_no_gaps)
is the v0.4.0a5 verification gate: it exercises the BEGIN IMMEDIATE
serialization on a freshly-created test engine.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.infra.nonce_repo import (
    Nonce,
    NonceNotInitializedError,
    NonceRepo,
    NonceWalletNotFoundError,
)
from fwd.infra.nonce_repo import metadata as nonces_metadata
from fwd.infra.wallet_repo import metadata as wallets_metadata
from fwd.infra.wallet_repo import wallets


@pytest.fixture()
async def session(tmp_path) -> AsyncSession:  # type: ignore[no-untyped-def]
    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(wallets_metadata.create_all)
        await conn.run_sync(nonces_metadata.create_all)
    async with AsyncSession(engine) as session:
        yield session
    await engine.dispose()


async def _seed_wallet(session: AsyncSession, name: str = "test-wallet") -> None:
    await session.execute(
        wallets.insert().values(
            name=name,
            address="0x" + "11" * 20,
            privkey_ciphertext="vault:v1:test",
            vault_master_key="fwd-master",
            policy_path="policies/test.yaml",
            created_at=datetime.now(UTC),
        )
    )
    await session.commit()


@pytest.mark.asyncio
async def test_init_for_wallet_inserts_row(session: AsyncSession) -> None:
    await _seed_wallet(session)
    repo = NonceRepo(session)
    n = await repo.init_for_wallet("test-wallet", 114, 5)
    await session.commit()
    assert isinstance(n, Nonce)
    assert n.wallet == "test-wallet"
    assert n.chain == 114
    assert n.next_nonce == 5
    assert n.last_confirmed is None


@pytest.mark.asyncio
async def test_init_for_wallet_is_idempotent(session: AsyncSession) -> None:
    await _seed_wallet(session)
    repo = NonceRepo(session)
    first = await repo.init_for_wallet("test-wallet", 114, 5)
    await session.commit()
    second = await repo.init_for_wallet("test-wallet", 114, 99)  # different starting_nonce
    await session.commit()
    assert first.next_nonce == 5
    assert second.next_nonce == 5  # original unchanged — idempotent


@pytest.mark.asyncio
async def test_reserve_next_returns_starting_value_then_increments(
    session: AsyncSession,
) -> None:
    await _seed_wallet(session)
    repo = NonceRepo(session)
    await repo.init_for_wallet("test-wallet", 114, 5)
    await session.commit()
    first = await repo.reserve_next("test-wallet", 114)
    await session.commit()
    second = await repo.reserve_next("test-wallet", 114)
    await session.commit()
    assert first == 5
    assert second == 6


@pytest.mark.asyncio
async def test_reserve_next_uninitialized_raises(session: AsyncSession) -> None:
    repo = NonceRepo(session)
    with pytest.raises(NonceNotInitializedError):
        await repo.reserve_next("no-such-wallet", 114)


@pytest.mark.asyncio
async def test_release_if_unused_decrements_when_no_one_else_reserved(
    session: AsyncSession,
) -> None:
    await _seed_wallet(session)
    repo = NonceRepo(session)
    await repo.init_for_wallet("test-wallet", 114, 10)
    await session.commit()
    reserved = await repo.reserve_next("test-wallet", 114)  # → 10; next_nonce becomes 11
    await session.commit()
    assert reserved == 10
    released = await repo.release_if_unused("test-wallet", 114, reserved)
    await session.commit()
    assert released is True
    # next_nonce should be back to 10; next reservation gets 10 again
    next_reserved = await repo.reserve_next("test-wallet", 114)
    await session.commit()
    assert next_reserved == 10


@pytest.mark.asyncio
async def test_release_if_unused_no_op_when_someone_else_reserved(
    session: AsyncSession,
) -> None:
    await _seed_wallet(session)
    repo = NonceRepo(session)
    await repo.init_for_wallet("test-wallet", 114, 10)
    await session.commit()
    first = await repo.reserve_next("test-wallet", 114)  # 10; next_nonce=11
    await session.commit()
    _second = await repo.reserve_next("test-wallet", 114)  # 11; next_nonce=12
    await session.commit()
    # Try to release first (10); next_nonce is now 12, so condition fails
    released = await repo.release_if_unused("test-wallet", 114, first)
    await session.commit()
    assert released is False
    # next_nonce stays at 12; gap at nonce 10 is accepted drift
    n = await repo.get("test-wallet", 114)
    assert n is not None
    assert n.next_nonce == 12


@pytest.mark.asyncio
async def test_mark_confirmed_takes_max(session: AsyncSession) -> None:
    await _seed_wallet(session)
    repo = NonceRepo(session)
    await repo.init_for_wallet("test-wallet", 114, 0)
    await session.commit()
    # Initial: last_confirmed is None
    n = await repo.get("test-wallet", 114)
    assert n is not None
    assert n.last_confirmed is None
    # mark(5) → sets to 5
    await repo.mark_confirmed("test-wallet", 114, 5)
    await session.commit()
    n = await repo.get("test-wallet", 114)
    assert n is not None
    assert n.last_confirmed == 5
    # mark(3) → stays at 5 (3 < 5)
    await repo.mark_confirmed("test-wallet", 114, 3)
    await session.commit()
    n = await repo.get("test-wallet", 114)
    assert n is not None
    assert n.last_confirmed == 5
    # mark(7) → updates to 7
    await repo.mark_confirmed("test-wallet", 114, 7)
    await session.commit()
    n = await repo.get("test-wallet", 114)
    assert n is not None
    assert n.last_confirmed == 7


@pytest.mark.asyncio
async def test_get_missing_raises(session: AsyncSession) -> None:
    repo = NonceRepo(session)
    with pytest.raises(NonceNotInitializedError):
        await repo.get("no-such-wallet", 114)


@pytest.mark.asyncio
async def test_get_missing_ok_returns_none(session: AsyncSession) -> None:
    repo = NonceRepo(session)
    result = await repo.get("no-such-wallet", 114, missing_ok=True)
    assert result is None


@pytest.mark.asyncio
async def test_list_all_returns_every_row(session: AsyncSession) -> None:
    for name in ("w1", "w2", "w3"):
        await _seed_wallet(session, name)
    repo = NonceRepo(session)
    await repo.init_for_wallet("w1", 114, 0)
    await repo.init_for_wallet("w2", 114, 5)
    await repo.init_for_wallet("w3", 114, 10)
    await session.commit()
    all_nonces = await repo.list_all()
    assert len(all_nonces) == 3
    names = {n.wallet for n in all_nonces}
    assert names == {"w1", "w2", "w3"}


@pytest.mark.asyncio
async def test_concurrent_reservations_are_monotonic_no_gaps(  # type: ignore[no-untyped-def]
    tmp_path,
) -> None:
    """asyncio.gather of 10 reserve_next calls returns {100, 101, ..., 109}.

    Validates BEGIN IMMEDIATE serialization. With default BEGIN DEFERRED,
    concurrent UPDATE...RETURNING statements on the same row produce races
    (multiple goroutines see the same next_nonce). BEGIN IMMEDIATE forces
    writers to serialize, guaranteeing monotonic nonces with no gaps.
    """
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")

    @event.listens_for(Engine, "connect")
    def _pragmas(conn, _record) -> None:  # type: ignore[no-untyped-def]
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    @event.listens_for(engine.sync_engine, "begin")
    def _immediate(conn) -> None:  # type: ignore[no-untyped-def]
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    async with engine.begin() as conn:
        await conn.run_sync(wallets_metadata.create_all)
        await conn.run_sync(nonces_metadata.create_all)

    # Seed wallet + nonces row.
    async with AsyncSession(engine) as session:
        await session.execute(
            wallets.insert().values(
                name="w",
                address="0x" + "11" * 20,
                privkey_ciphertext="vault:v1:x",
                vault_master_key="fwd-master",
                policy_path="p",
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()
        repo = NonceRepo(session)
        await repo.init_for_wallet("w", 114, 100)
        await session.commit()

    async def _one_reservation() -> int:
        async with AsyncSession(engine) as session:
            repo = NonceRepo(session)
            n = await repo.reserve_next("w", 114)
            await session.commit()
            return n

    reserved = await asyncio.gather(*[_one_reservation() for _ in range(10)])
    await engine.dispose()

    assert sorted(reserved) == list(range(100, 110)), (
        f"expected [100..109] but got {sorted(reserved)} — " f"BEGIN IMMEDIATE serialization failed"
    )
    assert len(set(reserved)) == 10, f"duplicate reservations: {reserved}"


# ---------------------------------------------------------------------------
# force=True overwrite tests (a50)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_init_for_wallet_force_overwrites_existing_row(session: AsyncSession) -> None:
    """force=True on an existing row resets next_nonce to starting_nonce and clears last_confirmed."""
    await _seed_wallet(session)
    repo = NonceRepo(session)
    # Create the initial row and advance the nonce so last_confirmed is also set.
    await repo.init_for_wallet("test-wallet", 114, 5)
    await session.commit()
    await repo.mark_confirmed("test-wallet", 114, 4)
    await session.commit()

    # Sanity: existing row has the old values.
    before = await repo.get("test-wallet", 114)
    assert before.next_nonce == 5
    assert before.last_confirmed == 4

    # Force overwrite to nonce 0.
    result = await repo.init_for_wallet("test-wallet", 114, 0, force=True)
    await session.commit()

    assert result.next_nonce == 0
    assert result.last_confirmed is None

    # Verify via a fresh read.
    after = await repo.get("test-wallet", 114)
    assert after.next_nonce == 0
    assert after.last_confirmed is None


@pytest.mark.asyncio
async def test_init_for_wallet_force_false_leaves_existing_unchanged(session: AsyncSession) -> None:
    """force=False (default) on an existing row returns the existing row unchanged."""
    await _seed_wallet(session)
    repo = NonceRepo(session)
    await repo.init_for_wallet("test-wallet", 114, 42)
    await session.commit()

    # Second call with a different starting_nonce and force=False — must be a no-op.
    result = await repo.init_for_wallet("test-wallet", 114, 99, force=False)
    await session.commit()

    assert result.next_nonce == 42  # unchanged


@pytest.mark.asyncio
async def test_init_for_wallet_missing_wallet_raises_nonce_wallet_not_found(  # type: ignore[no-untyped-def]
    tmp_path,
) -> None:
    """FK violation (wallet not in wallets table) raises NonceWalletNotFoundError even with force=True.

    Uses raw DDL with REFERENCES + PRAGMA foreign_keys=ON (the FK is in the alembic migration
    DDL, not in the SQLAlchemy Table metadata, so metadata.create_all does not create it).
    """
    from sqlalchemy import event, text
    from sqlalchemy.engine import Engine

    db = tmp_path / "fk_test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")

    @event.listens_for(Engine, "connect")
    def _pragmas(conn, _record) -> None:  # type: ignore[no-untyped-def]
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    async with engine.begin() as conn:
        # Create wallets table (no FK — just needs to exist for the nonces FK to reference it).
        await conn.execute(
            text(
                "CREATE TABLE wallets ("
                "  name TEXT PRIMARY KEY,"
                "  address TEXT NOT NULL,"
                "  privkey_ciphertext TEXT NOT NULL,"
                "  vault_master_key TEXT NOT NULL,"
                "  policy_path TEXT NOT NULL,"
                "  created_at DATETIME NOT NULL"
                ")"
            )
        )
        # Create nonces WITH the FK constraint (mirrors the alembic migration DDL).
        await conn.execute(
            text(
                "CREATE TABLE nonces ("
                "  wallet TEXT NOT NULL,"
                "  chain INTEGER NOT NULL,"
                "  next_nonce INTEGER NOT NULL,"
                "  last_confirmed INTEGER,"
                "  last_reconciled_at DATETIME NOT NULL,"
                "  PRIMARY KEY (wallet, chain),"
                "  FOREIGN KEY (wallet) REFERENCES wallets(name)"
                ")"
            )
        )

    async with AsyncSession(engine) as session:
        repo = NonceRepo(session)
        with pytest.raises(NonceWalletNotFoundError):
            await repo.init_for_wallet("ghost-wallet", 114, 0, force=True)

    await engine.dispose()
