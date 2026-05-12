"""TransactionRepo unit tests against a file-based SQLite (tmp_path).

Uses file-based SQLite (matching test_wallet_repo.py pattern) rather than
in-memory to ensure WAL and FK pragma behaviour is consistent.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.infra.caller_repo import metadata as callers_metadata
from fwd.infra.transaction_repo import (
    Transaction,
    TransactionExistsError,
    TransactionHash,
    TransactionNotFoundError,
    TransactionRepo,
)
from fwd.infra.transaction_repo import (
    metadata as tx_metadata,
)
from fwd.infra.wallet_repo import metadata as wallets_metadata


@pytest.fixture()
async def session(tmp_path) -> AsyncSession:  # type: ignore[no-untyped-def]
    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(wallets_metadata.create_all)
        await conn.run_sync(callers_metadata.create_all)
        await conn.run_sync(tx_metadata.create_all)
    async with AsyncSession(engine) as session:
        yield session
    await engine.dispose()


def _tx_kwargs(tx_id: str = "test-uuid-0001", **overrides: object) -> dict:
    base: dict = {
        "tx_id": tx_id,
        "wallet": "test-wallet",
        "chain": 114,
        "caller": "test-caller",
        "nonce": 0,
        "contract_address": "0x" + "11" * 20,
        "method_name": "0x",
        "value_wei": "0",
        "request_json": '{"test": true}',
        "signed_raw": "0xdeadbeef",
        "status": "submitted",
        "submitted_at": datetime.now(UTC),
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_create_inserts_row(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    tx = await repo.create(**_tx_kwargs("uuid-create-01"))
    await session.commit()
    assert isinstance(tx, Transaction)
    assert tx.tx_id == "uuid-create-01"
    assert tx.status == "submitted"
    assert tx.caller == "test-caller"
    assert tx.wallet == "test-wallet"


@pytest.mark.asyncio
async def test_create_duplicate_raises_exists_error(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    await repo.create(**_tx_kwargs("uuid-dup-01"))
    await session.commit()
    with pytest.raises(TransactionExistsError):
        await repo.create(**_tx_kwargs("uuid-dup-01"))


@pytest.mark.asyncio
async def test_get_by_id_returns_row(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    await repo.create(**_tx_kwargs("uuid-get-01"))
    await session.commit()
    tx = await repo.get_by_id("uuid-get-01")
    assert tx is not None
    assert tx.tx_id == "uuid-get-01"
    assert tx.chain == 114
    assert tx.nonce == 0


@pytest.mark.asyncio
async def test_get_by_id_missing_raises(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    with pytest.raises(TransactionNotFoundError):
        await repo.get_by_id("does-not-exist")


@pytest.mark.asyncio
async def test_get_by_id_missing_ok_returns_none(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    result = await repo.get_by_id("does-not-exist", missing_ok=True)
    assert result is None


@pytest.mark.asyncio
async def test_add_hash_inserts_row(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    await repo.create(**_tx_kwargs("uuid-hash-01"))
    await session.commit()
    th = await repo.add_hash("uuid-hash-01", "0x" + "ab" * 32, sequence_num=1)
    await session.commit()
    assert isinstance(th, TransactionHash)
    assert th.tx_id == "uuid-hash-01"
    assert th.sequence_num == 1
    assert th.hash_hex == "0x" + "ab" * 32


@pytest.mark.asyncio
async def test_list_hashes_returns_in_sequence_order(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    await repo.create(**_tx_kwargs("uuid-order-01"))
    await session.commit()
    # Insert in reverse order to verify ORDER BY sequence_num.
    await repo.add_hash("uuid-order-01", "0x" + "bb" * 32, sequence_num=2)
    await repo.add_hash("uuid-order-01", "0x" + "aa" * 32, sequence_num=1)
    await session.commit()
    hashes = await repo.list_hashes_by_tx("uuid-order-01")
    assert len(hashes) == 2
    assert hashes[0].sequence_num == 1
    assert hashes[1].sequence_num == 2
    assert hashes[0].hash_hex == "0x" + "aa" * 32
    assert hashes[1].hash_hex == "0x" + "bb" * 32


@pytest.mark.asyncio
async def test_update_status_changes_status_and_confirmed_at(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    await repo.create(**_tx_kwargs("uuid-update-01"))
    await session.commit()
    confirmed = datetime.now(UTC)
    await repo.update_status(
        "uuid-update-01",
        "mined",
        confirmed_at=confirmed,
        receipt_json='{"status":"0x1"}',
    )
    await session.commit()
    tx = await repo.get_by_id("uuid-update-01")
    assert tx.status == "mined"
    assert tx.confirmed_at is not None
    assert tx.receipt_json == '{"status":"0x1"}'


@pytest.mark.asyncio
async def test_list_by_status_returns_only_matching(session: AsyncSession) -> None:
    """Three txs with statuses [submitted, mined, submitted]; list_by_status
    returns the two submitted, ordered by created_at."""
    repo = TransactionRepo(session)
    await repo.create(**_tx_kwargs("uuid-status-01", status="submitted"))
    await session.commit()
    await repo.create(**_tx_kwargs("uuid-status-02", status="submitted"))
    await session.commit()
    await repo.create(**_tx_kwargs("uuid-status-03", status="submitted"))
    await session.commit()
    # Demote one to mined to confirm filter.
    await repo.update_status("uuid-status-02", "mined", confirmed_at=datetime.now(UTC))
    await session.commit()

    submitted = await repo.list_by_status("submitted")
    ids = [t.tx_id for t in submitted]
    assert set(ids) == {"uuid-status-01", "uuid-status-03"}

    mined = await repo.list_by_status("mined")
    assert [t.tx_id for t in mined] == ["uuid-status-02"]


@pytest.mark.asyncio
async def test_update_status_with_signed_raw_persists(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    await repo.create(**_tx_kwargs("uuid-signed-01"))
    await session.commit()
    await repo.update_status(
        "uuid-signed-01",
        "submitted",
        signed_raw="0x" + "ab" * 4,
    )
    await session.commit()
    tx = await repo.get_by_id("uuid-signed-01")
    assert tx.signed_raw == "0x" + "ab" * 4
    assert tx.status == "submitted"


@pytest.mark.asyncio
async def test_update_status_with_submitted_at_persists(session: AsyncSession) -> None:
    repo = TransactionRepo(session)
    await repo.create(**_tx_kwargs("uuid-resubmit-01"))
    await session.commit()
    new_submitted = datetime(2026, 5, 12, 10, 30, 45, tzinfo=UTC)
    await repo.update_status(
        "uuid-resubmit-01",
        "submitted",
        submitted_at=new_submitted,
    )
    await session.commit()
    tx = await repo.get_by_id("uuid-resubmit-01")
    # SQLite's DateTime column drops tzinfo on round-trip; compare naive.
    assert tx.submitted_at is not None
    assert tx.submitted_at.replace(tzinfo=None) == new_submitted.replace(tzinfo=None)
    assert tx.status == "submitted"
