"""WalletRepo unit tests against an in-memory SQLite (file-based via tmp dir
for the foreign-keys PRAGMA + WAL journal_mode to take effect).
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.infra.wallet_repo import (
    Wallet,
    WalletExistsError,
    WalletNotFoundError,
    WalletRepo,
    metadata,
)


@pytest.fixture()
async def session(tmp_path) -> AsyncSession:  # type: ignore[no-untyped-def]
    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    async with AsyncSession(engine) as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_then_get(session: AsyncSession) -> None:
    repo = WalletRepo(session)
    w = await repo.create(
        name="w1",
        address="0x" + "01" * 20,
        privkey_ciphertext="seal:v1:abc",
        vault_master_key="fwd-master",
        policy_path="p1",
    )
    await session.commit()
    assert isinstance(w, Wallet)
    assert w.name == "w1"
    got = await repo.get_by_name("w1")
    assert got is not None
    assert got.address == "0x" + "01" * 20


@pytest.mark.asyncio
async def test_create_duplicate_raises(session: AsyncSession) -> None:
    repo = WalletRepo(session)
    await repo.create(
        name="dup",
        address="0x" + "02" * 20,
        privkey_ciphertext="seal:v1:abc",
        vault_master_key="fwd-master",
        policy_path="p1",
    )
    await session.commit()
    with pytest.raises(WalletExistsError):
        await repo.create(
            name="dup",
            address="0x" + "03" * 20,
            privkey_ciphertext="seal:v1:def",
            vault_master_key="fwd-master",
            policy_path="p1",
        )


@pytest.mark.asyncio
async def test_get_missing_raises(session: AsyncSession) -> None:
    repo = WalletRepo(session)
    with pytest.raises(WalletNotFoundError):
        await repo.get_by_name("none")


@pytest.mark.asyncio
async def test_get_missing_ok(session: AsyncSession) -> None:
    repo = WalletRepo(session)
    got = await repo.get_by_name("none", missing_ok=True)
    assert got is None


@pytest.mark.asyncio
async def test_list_all_returns_all_wallets_ordered_by_created_at(
    session: AsyncSession,
) -> None:
    """Insert 3 wallets at distinct times; list_all returns all 3 in
    creation order (oldest first)."""
    import asyncio

    repo = WalletRepo(session)
    await repo.create(
        name="w-alpha",
        address="0x" + "0a" * 20,
        privkey_ciphertext="seal:v1:alpha",
        vault_master_key="fwd-master",
        policy_path="p1",
    )
    await session.commit()
    # Tiny sleep ensures distinct created_at timestamps (datetime.now(UTC)
    # has microsecond resolution; sqlite truncates).
    await asyncio.sleep(0.01)
    await repo.create(
        name="w-beta",
        address="0x" + "0b" * 20,
        privkey_ciphertext="seal:v1:beta",
        vault_master_key="fwd-master",
        policy_path="p2",
    )
    await session.commit()
    await asyncio.sleep(0.01)
    await repo.create(
        name="w-gamma",
        address="0x" + "0c" * 20,
        privkey_ciphertext="seal:v1:gamma",
        vault_master_key="fwd-master",
        policy_path="p3",
    )
    await session.commit()

    rows = await repo.list_all()
    assert [w.name for w in rows] == ["w-alpha", "w-beta", "w-gamma"]
    # All summary fields present and full ciphertext returned at repo layer
    # (the API layer is responsible for stripping ciphertext + vault_master_key
    # from the public response).
    for w in rows:
        assert w.privkey_ciphertext.startswith("seal:v1:")
        assert w.vault_master_key == "fwd-master"


@pytest.mark.asyncio
async def test_list_all_empty(session: AsyncSession) -> None:
    repo = WalletRepo(session)
    rows = await repo.list_all()
    assert rows == []
