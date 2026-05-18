"""receipt_watcher unit tests with mocked signer/rpc/tx_repo/nonce_repo.

Tests _process_tx (per-tx state machine) and the watch_receipts cancellation
contract directly. The full loop (watch_receipts -> _tick) is covered by
the lifespan integration; per-tick CM wiring is exercised in the
cancellation test by monkeypatching _tick to a no-op.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from fwd.app import receipt_watcher as receipt_watcher_module
from fwd.app.receipt_watcher import (
    WatcherConfig,
    _process_tx,
    _replace,
    watch_receipts,
)
from fwd.app.sign_and_send import _DEFAULT_TIP_WEI, _GAS_ESTIMATE_BUFFER
from fwd.domain.signer import SignedTransaction
from fwd.infra.rpc import RpcError, RpcUnavailable
from fwd.infra.sealed_master import SealError
from fwd.infra.transaction_repo import Transaction, TransactionHash


def _config(
    *,
    poll_interval_sec: float = 0.01,
    stuck_threshold_sec: float = 30.0,
    max_retries: int = 5,
    tip_multiplier: float = 1.125,
    enabled: bool = True,
) -> WatcherConfig:
    return WatcherConfig(
        poll_interval_sec=poll_interval_sec,
        stuck_threshold_sec=stuck_threshold_sec,
        max_retries=max_retries,
        tip_multiplier=tip_multiplier,
        enabled=enabled,
    )


def _tx(
    *,
    tx_id: str = "uuid-watcher-01",
    wallet: str = "w1",
    chain: int = 114,
    nonce: int = 5,
    submitted_at: datetime | None = None,
    request_json: str | None = None,
) -> Transaction:
    if submitted_at is None:
        submitted_at = datetime.now(UTC) - timedelta(seconds=60)
    if request_json is None:
        request_json = json.dumps(
            {
                "wallet": wallet,
                "chain": chain,
                "to": "0x" + "11" * 20,
                "value_wei": "0",
                "data": "0x",
                "gas": None,
            },
            sort_keys=True,
        )
    return Transaction(
        tx_id=tx_id,
        wallet=wallet,
        chain=chain,
        caller="c1",
        nonce=nonce,
        contract_address="0x" + "11" * 20,
        method_name="0x",
        value_wei="0",
        idempotency_key=None,
        request_json=request_json,
        signed_raw="0xdeadbeef",
        status="submitted",
        submitted_at=submitted_at,
        confirmed_at=None,
        receipt_json=None,
        created_at=datetime.now(UTC) - timedelta(seconds=120),
    )


def _hash(tx_id: str, seq: int, hash_hex: str | None = None) -> TransactionHash:
    return TransactionHash(
        tx_id=tx_id,
        sequence_num=seq,
        hash_hex=hash_hex or f"0x{seq:064x}",
        submitted_at=datetime.now(UTC) - timedelta(seconds=60),
    )


def _signer(
    signed_raw: bytes = b"\x02\x00\x01",
    address: str = "0x" + "aa" * 20,
) -> MagicMock:
    s = MagicMock()
    s.sign_transaction = AsyncMock(
        return_value=SignedTransaction(
            raw_transaction=signed_raw,
            hash=b"\x00" * 32,
            r=1,
            s=2,
            v=27,
        )
    )
    # Replacement path resolves the wallet name → checksum address before
    # estimate_gas (Reviewer correction during v0.4.0a6 review — eth_estimateGas
    # rejects non-address `from` fields).
    s.address = AsyncMock(return_value=address)
    return s


def _rpc(
    *,
    receipts: list[dict[str, Any] | None | Exception] | None = None,
    base_fee: int = 1_000_000_000,
    gas_estimate: int = 21000,
    send_hash: str = "0x" + "ab" * 32,
    fee_history_exc: Exception | None = None,
    estimate_exc: Exception | None = None,
    send_exc: Exception | None = None,
) -> MagicMock:
    rpc = MagicMock()
    if receipts is None:
        rpc.transaction_receipt = AsyncMock(return_value=None)
    else:
        rpc.transaction_receipt = AsyncMock(side_effect=receipts)
    if fee_history_exc is not None:
        rpc.fee_history = AsyncMock(side_effect=fee_history_exc)
    else:
        rpc.fee_history = AsyncMock(return_value={"baseFeePerGas": [hex(base_fee), hex(base_fee)]})
    if estimate_exc is not None:
        rpc.estimate_gas = AsyncMock(side_effect=estimate_exc)
    else:
        rpc.estimate_gas = AsyncMock(return_value=gas_estimate)
    if send_exc is not None:
        rpc.send_raw_transaction = AsyncMock(side_effect=send_exc)
    else:
        rpc.send_raw_transaction = AsyncMock(return_value=send_hash)
    return rpc


def _rpc_manager(rpc: MagicMock) -> MagicMock:
    mgr = MagicMock()
    mgr.for_chain = MagicMock(return_value=rpc)
    return mgr


def _tx_repo(hashes: list[TransactionHash]) -> MagicMock:
    repo = MagicMock()
    repo.list_hashes_by_tx = AsyncMock(return_value=hashes)
    repo.update_status = AsyncMock(return_value=None)
    repo.add_hash = AsyncMock(return_value=None)
    repo.list_by_status = AsyncMock(return_value=[])
    return repo


def _nonce_repo() -> MagicMock:
    repo = MagicMock()
    repo.mark_confirmed = AsyncMock(return_value=None)
    return repo


# ---------------------------------------------------------------------------
# Terminal-receipt transitions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_tx_mined_when_receipt_status_ok() -> None:
    tx = _tx(nonce=7)
    hashes = [_hash(tx.tx_id, 1)]
    receipt = {"status": "0x1", "blockNumber": "0x1abc", "transactionHash": hashes[0].hash_hex}
    signer = _signer()
    rpc = _rpc(receipts=[receipt])
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    nonce_repo = _nonce_repo()

    await _process_tx(tx, _config(), signer, rpc_mgr, tx_repo, nonce_repo)

    tx_repo.update_status.assert_awaited_once()
    args, kwargs = tx_repo.update_status.call_args
    assert args[0] == tx.tx_id
    assert args[1] == "mined"
    assert kwargs["confirmed_at"] is not None
    assert kwargs["receipt_json"] == json.dumps(receipt)
    nonce_repo.mark_confirmed.assert_awaited_once_with(tx.wallet, tx.chain, tx.nonce)
    tx_repo.add_hash.assert_not_awaited()
    signer.sign_transaction.assert_not_awaited()


@pytest.mark.asyncio
async def test_process_tx_failed_when_receipt_status_reverted() -> None:
    tx = _tx(nonce=8)
    hashes = [_hash(tx.tx_id, 1)]
    receipt = {"status": "0x0", "blockNumber": "0x1ace", "transactionHash": hashes[0].hash_hex}
    signer = _signer()
    rpc = _rpc(receipts=[receipt])
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    nonce_repo = _nonce_repo()

    await _process_tx(tx, _config(), signer, rpc_mgr, tx_repo, nonce_repo)

    tx_repo.update_status.assert_awaited_once()
    args, _ = tx_repo.update_status.call_args
    assert args[1] == "failed"
    nonce_repo.mark_confirmed.assert_not_awaited()
    tx_repo.add_hash.assert_not_awaited()


# ---------------------------------------------------------------------------
# Stuck detection / retry cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_tx_skips_if_not_stuck() -> None:
    tx = _tx(submitted_at=datetime.now(UTC) - timedelta(seconds=5))
    hashes = [_hash(tx.tx_id, 1)]
    rpc = _rpc(receipts=[None])
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer()
    nonce_repo = _nonce_repo()

    await _process_tx(tx, _config(stuck_threshold_sec=30.0), signer, rpc_mgr, tx_repo, nonce_repo)

    tx_repo.update_status.assert_not_awaited()
    tx_repo.add_hash.assert_not_awaited()
    signer.sign_transaction.assert_not_awaited()


@pytest.mark.asyncio
async def test_process_tx_handles_naive_submitted_at_from_db() -> None:
    """Regression: SQLite drops tzinfo on DateTime(timezone=True) round-trip.

    Production reads `tx.submitted_at` as a NAIVE datetime even though we
    wrote it as UTC-aware. The watcher's stuck-check subtraction
    `datetime.now(UTC) - tx.submitted_at` would raise TypeError unless the
    watcher normalizes naive → UTC-aware. This regression test simulates
    the post-round-trip state by constructing the Transaction with a naive
    submitted_at directly. Added during v0.4.0a6 Reviewer review after the
    bug was caught (Sonnet's unit tests passed because they bypassed the
    DB round-trip with aware datetimes).
    """
    # NAIVE — what SQLite hands back after round-trip.
    naive_submitted = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=60)
    assert naive_submitted.tzinfo is None, "test precondition: submitted_at must be naive"

    tx = _tx(submitted_at=naive_submitted)
    hashes = [_hash(tx.tx_id, 1)]
    rpc = _rpc(receipts=[None])
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer()
    nonce_repo = _nonce_repo()

    # Must NOT raise TypeError. Should detect as stuck (60s > 30s threshold)
    # and attempt replacement.
    await _process_tx(
        tx,
        _config(stuck_threshold_sec=30.0, max_retries=5),
        signer,
        rpc_mgr,
        tx_repo,
        nonce_repo,
    )

    signer.sign_transaction.assert_awaited_once()
    tx_repo.add_hash.assert_awaited_once()


@pytest.mark.asyncio
async def test_process_tx_replaces_when_stuck_under_cap() -> None:
    tx = _tx(submitted_at=datetime.now(UTC) - timedelta(seconds=60))
    hashes = [_hash(tx.tx_id, 1), _hash(tx.tx_id, 2)]
    rpc = _rpc(receipts=[None, None])
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer()
    nonce_repo = _nonce_repo()

    await _process_tx(
        tx, _config(stuck_threshold_sec=30.0, max_retries=5), signer, rpc_mgr, tx_repo, nonce_repo
    )

    signer.sign_transaction.assert_awaited_once()
    rpc.send_raw_transaction.assert_awaited_once()
    tx_repo.update_status.assert_awaited_once()
    args, kwargs = tx_repo.update_status.call_args
    assert args[1] == "submitted"
    assert kwargs["signed_raw"] is not None
    assert kwargs["submitted_at"] is not None
    tx_repo.add_hash.assert_awaited_once()
    add_args, add_kwargs = tx_repo.add_hash.call_args
    assert add_args[0] == tx.tx_id
    assert add_kwargs.get("sequence_num") == 3 or (len(add_args) >= 3 and add_args[2] == 3)


@pytest.mark.asyncio
async def test_process_tx_marks_failed_after_max_retries() -> None:
    tx = _tx(submitted_at=datetime.now(UTC) - timedelta(seconds=60))
    hashes = [_hash(tx.tx_id, i) for i in range(1, 6)]  # 5 hashes already
    rpc = _rpc(receipts=[None] * 5)
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer()
    nonce_repo = _nonce_repo()

    await _process_tx(
        tx, _config(stuck_threshold_sec=30.0, max_retries=5), signer, rpc_mgr, tx_repo, nonce_repo
    )

    tx_repo.update_status.assert_awaited_once()
    args, kwargs = tx_repo.update_status.call_args
    assert args[1] == "failed"
    assert kwargs["confirmed_at"] is not None
    signer.sign_transaction.assert_not_awaited()
    tx_repo.add_hash.assert_not_awaited()


# ---------------------------------------------------------------------------
# Replacement math
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replace_tip_bump_math() -> None:
    tx = _tx(submitted_at=datetime.now(UTC) - timedelta(seconds=60))
    hashes = [_hash(tx.tx_id, 1), _hash(tx.tx_id, 2)]
    base_fee = 5_000_000_000  # 5 gwei
    rpc = _rpc(receipts=[None, None], base_fee=base_fee)
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer()
    nonce_repo = _nonce_repo()

    await _process_tx(
        tx, _config(stuck_threshold_sec=30.0, max_retries=5), signer, rpc_mgr, tx_repo, nonce_repo
    )

    signer.sign_transaction.assert_awaited_once()
    sign_args, _ = signer.sign_transaction.call_args
    tx_dict = sign_args[1]
    new_seq = 3  # len(hashes)+1
    expected_tip = int(_DEFAULT_TIP_WEI * (1.125**new_seq))
    expected_max_fee = base_fee * 2 + expected_tip
    assert tx_dict["maxPriorityFeePerGas"] == expected_tip
    assert tx_dict["maxFeePerGas"] == expected_max_fee
    assert tx_dict["nonce"] == tx.nonce
    assert tx_dict["chainId"] == tx.chain
    assert tx_dict["type"] == 2


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_tx_rpc_failure_logs_and_returns() -> None:
    tx = _tx()
    hashes = [_hash(tx.tx_id, 1)]
    rpc = _rpc(receipts=[RpcUnavailable("node down")])
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer()
    nonce_repo = _nonce_repo()

    await _process_tx(tx, _config(), signer, rpc_mgr, tx_repo, nonce_repo)

    tx_repo.update_status.assert_not_awaited()
    tx_repo.add_hash.assert_not_awaited()
    signer.sign_transaction.assert_not_awaited()


@pytest.mark.asyncio
async def test_replace_vault_failure_logs_and_returns() -> None:
    tx = _tx()
    hashes = [_hash(tx.tx_id, 1)]
    rpc = _rpc(receipts=[None])
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer()
    signer.sign_transaction = AsyncMock(side_effect=SealError("sealed"))
    nonce_repo = _nonce_repo()

    await _process_tx(
        tx, _config(stuck_threshold_sec=30.0, max_retries=5), signer, rpc_mgr, tx_repo, nonce_repo
    )

    tx_repo.update_status.assert_not_awaited()
    tx_repo.add_hash.assert_not_awaited()
    rpc.send_raw_transaction.assert_not_awaited()


@pytest.mark.asyncio
async def test_replace_broadcast_failure_logs_and_returns() -> None:
    tx = _tx()
    hashes = [_hash(tx.tx_id, 1)]
    rpc = _rpc(receipts=[None], send_exc=RpcError("nonce too low"))
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer()
    nonce_repo = _nonce_repo()

    await _process_tx(
        tx, _config(stuck_threshold_sec=30.0, max_retries=5), signer, rpc_mgr, tx_repo, nonce_repo
    )

    signer.sign_transaction.assert_awaited_once()
    rpc.send_raw_transaction.assert_awaited_once()
    tx_repo.update_status.assert_not_awaited()
    tx_repo.add_hash.assert_not_awaited()


# ---------------------------------------------------------------------------
# Gas resolution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replace_uses_caller_provided_gas_if_present() -> None:
    request_json = json.dumps(
        {
            "wallet": "w1",
            "chain": 114,
            "to": "0x" + "11" * 20,
            "value_wei": "0",
            "data": "0x",
            "gas": 50_000,
        },
        sort_keys=True,
    )
    tx = _tx(request_json=request_json)
    hashes = [_hash(tx.tx_id, 1)]
    rpc = _rpc(receipts=[None])
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer()
    nonce_repo = _nonce_repo()

    await _process_tx(
        tx, _config(stuck_threshold_sec=30.0, max_retries=5), signer, rpc_mgr, tx_repo, nonce_repo
    )

    rpc.estimate_gas.assert_not_awaited()
    sign_args, _ = signer.sign_transaction.call_args
    tx_dict = sign_args[1]
    assert tx_dict["gas"] == 50_000


@pytest.mark.asyncio
async def test_replace_estimates_gas_if_not_provided() -> None:
    tx = _tx()  # default request_json has gas=None
    hashes = [_hash(tx.tx_id, 1)]
    rpc = _rpc(receipts=[None], gas_estimate=80_000)
    rpc_mgr = _rpc_manager(rpc)
    tx_repo = _tx_repo(hashes)
    signer = _signer(address="0x" + "cc" * 20)
    nonce_repo = _nonce_repo()

    await _process_tx(
        tx, _config(stuck_threshold_sec=30.0, max_retries=5), signer, rpc_mgr, tx_repo, nonce_repo
    )

    # signer.address is awaited once to resolve the wallet name for the
    # estimate_gas `from` field (Reviewer correction during v0.4.0a6 review).
    signer.address.assert_awaited_once_with(tx.wallet)
    rpc.estimate_gas.assert_awaited_once()
    estimate_args, _ = rpc.estimate_gas.call_args
    estimate_call_obj = estimate_args[0]
    assert (
        estimate_call_obj["from"] == "0x" + "cc" * 20
    ), "estimate_gas `from` must be the resolved 0x address, not the wallet name"
    sign_args, _ = signer.sign_transaction.call_args
    tx_dict = sign_args[1]
    assert tx_dict["gas"] == int(80_000 * _GAS_ESTIMATE_BUFFER)


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_watch_receipts_cancellation_propagates_cleanly(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """watch_receipts must re-raise CancelledError after cleanup, not swallow it."""
    tick_count = 0

    async def fake_tick(_config: WatcherConfig) -> None:
        nonlocal tick_count
        tick_count += 1
        await asyncio.sleep(0)

    monkeypatch.setattr(receipt_watcher_module, "_tick", fake_tick)

    task = asyncio.create_task(watch_receipts(_config(poll_interval_sec=0.01)))
    # Let the loop run for a couple of ticks.
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert tick_count >= 1


@pytest.mark.asyncio
async def test_replace_signature_via_replace_helper() -> None:
    """Direct unit test of _replace's signature shape -- exercises it without
    going through _process_tx, useful for catching arg-mismatch regressions."""
    tx = _tx()
    hashes = [_hash(tx.tx_id, 1)]
    rpc = _rpc()
    tx_repo = _tx_repo(hashes)
    signer = _signer()

    await _replace(tx, hashes, _config(), signer, rpc, tx_repo)

    signer.sign_transaction.assert_awaited_once()
    rpc.send_raw_transaction.assert_awaited_once()
    tx_repo.update_status.assert_awaited_once()
    tx_repo.add_hash.assert_awaited_once()
