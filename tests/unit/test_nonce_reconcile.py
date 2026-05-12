"""nonce_reconcile unit tests with mocked nonce_repo, wallet_repo, and rpc_mgr."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from fwd.app.nonce_reconcile import DriftReport, reconcile_all
from fwd.infra.nonce_repo import Nonce
from fwd.infra.wallet_repo import Wallet


def _nonce(wallet: str, chain: int, next_nonce: int) -> Nonce:
    return Nonce(
        wallet=wallet,
        chain=chain,
        next_nonce=next_nonce,
        last_confirmed=None,
        last_reconciled_at=datetime.now(UTC),
    )


def _wallet(name: str, address: str = "0x" + "11" * 20) -> Wallet:
    return Wallet(
        name=name,
        address=address,
        privkey_ciphertext="vault:v1:test",
        vault_master_key="fwd-master",
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
    )


def _make_mocks(
    nonces: list[Nonce],
    wallets: list[Wallet | None],
    chain_counts: list[int | Exception],
) -> tuple[MagicMock, MagicMock, MagicMock]:
    nonce_repo = MagicMock()
    nonce_repo.list_all = AsyncMock(return_value=nonces)

    wallet_repo = MagicMock()
    wallet_repo.get_by_name = AsyncMock(side_effect=wallets)

    rpc = MagicMock()
    rpc.transaction_count = AsyncMock(side_effect=chain_counts)

    rpc_mgr = MagicMock()
    rpc_mgr.for_chain = MagicMock(return_value=rpc)

    return nonce_repo, wallet_repo, rpc_mgr


@pytest.mark.asyncio
async def test_no_drift_returns_empty_list() -> None:
    nonce_repo, wallet_repo, rpc_mgr = _make_mocks(
        nonces=[_nonce("w", 114, 5)],
        wallets=[_wallet("w")],
        chain_counts=[5],  # DB (5) == chain (5)
    )
    reports = await reconcile_all(nonce_repo, wallet_repo, rpc_mgr)
    assert reports == []


@pytest.mark.asyncio
async def test_db_ahead_logged_as_warning() -> None:
    nonce_repo, wallet_repo, rpc_mgr = _make_mocks(
        nonces=[_nonce("w", 114, 10)],
        wallets=[_wallet("w")],
        chain_counts=[7],  # DB (10) > chain (7)
    )
    reports = await reconcile_all(nonce_repo, wallet_repo, rpc_mgr)
    assert len(reports) == 1
    r = reports[0]
    assert isinstance(r, DriftReport)
    assert r.drift == 3
    assert r.drift > 0
    assert r.db_next_nonce == 10
    assert r.chain_count == 7
    assert r.wallet == "w"
    assert r.chain == 114


@pytest.mark.asyncio
async def test_db_behind_logged_as_warning() -> None:
    nonce_repo, wallet_repo, rpc_mgr = _make_mocks(
        nonces=[_nonce("w", 114, 3)],
        wallets=[_wallet("w")],
        chain_counts=[8],  # DB (3) < chain (8) — external use of key
    )
    reports = await reconcile_all(nonce_repo, wallet_repo, rpc_mgr)
    assert len(reports) == 1
    r = reports[0]
    assert r.drift == -5
    assert r.drift < 0
    assert r.db_next_nonce == 3
    assert r.chain_count == 8


@pytest.mark.asyncio
async def test_rpc_failure_continues_to_next_row() -> None:
    """If RPC fails for the first wallet, reconcile continues with the second."""
    nonce_repo, wallet_repo, rpc_mgr = _make_mocks(
        nonces=[_nonce("w1", 114, 5), _nonce("w2", 114, 10)],
        wallets=[_wallet("w1", "0x" + "aa" * 20), _wallet("w2", "0x" + "bb" * 20)],
        chain_counts=[Exception("rpc down"), 10],  # first fails, second matches
    )
    reports = await reconcile_all(nonce_repo, wallet_repo, rpc_mgr)
    # w1 RPC failed (skipped), w2 has no drift
    assert reports == []
    rpc = rpc_mgr.for_chain.return_value
    assert rpc.transaction_count.await_count == 2


@pytest.mark.asyncio
async def test_orphan_nonce_logged() -> None:
    """Nonces row referencing a deleted wallet is logged and skipped; RPC not consulted."""
    nonce_repo, wallet_repo, rpc_mgr = _make_mocks(
        nonces=[_nonce("deleted-wallet", 114, 5)],
        wallets=[None],  # wallet_repo.get_by_name returns None
        chain_counts=[],
    )
    reports = await reconcile_all(nonce_repo, wallet_repo, rpc_mgr)
    assert reports == []
    rpc_mgr.for_chain.assert_not_called()
