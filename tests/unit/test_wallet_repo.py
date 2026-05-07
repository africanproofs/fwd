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
        privkey_ciphertext="vault:v1:abc",
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
        privkey_ciphertext="vault:v1:abc",
        vault_master_key="fwd-master",
        policy_path="p1",
    )
    await session.commit()
    with pytest.raises(WalletExistsError):
        await repo.create(
            name="dup",
            address="0x" + "03" * 20,
            privkey_ciphertext="vault:v1:def",
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
