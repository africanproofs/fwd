"""sign_and_send use case unit tests with mocked signer + rpc + tx_repo + nonce_repo."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from fwd.app.sign_and_send import (
    ChainNotAllowed,
    RpcUnreachable,
    SignAndSendRequest,
    VaultUnavailableError,
    WalletNotFound,
    sign_and_send,
)
from fwd.domain.signer import SignedTransaction
from fwd.infra.nonce_repo import NonceNotInitializedError
from fwd.infra.rpc import RpcUnavailable
from fwd.infra.vault_client import VaultError
from fwd.infra.wallet_repo import WalletNotFoundError


def _request(**kwargs: Any) -> SignAndSendRequest:
    defaults = {
        "wallet": "test-wallet",
        "caller": "test-caller",
        "chain": 114,
        "to": "0x" + "11" * 20,
        "value_wei": "0",
        "data": "0x",
        "gas": 21000,
    }
    defaults.update(kwargs)
    return SignAndSendRequest(**defaults)


def _signer(address: str = "0xabc", signed_raw: bytes = b"\x02\x00\x01") -> MagicMock:
    s = MagicMock()
    s.address = AsyncMock(return_value=address)
    s.sign_transaction = AsyncMock(
        return_value=SignedTransaction(
            raw_transaction=signed_raw,
            hash=b"\x00" * 32,
            r=1,
            s=2,
            v=27,
        )
    )
    return s


def _rpc(
    chain_id: int = 114,
    nonce: int = 0,
    base_fee: int = 1_000_000_000,
    gas_estimate: int = 21000,
    tx_hash: str = "0x" + "de" * 32,
) -> MagicMock:
    r = MagicMock()
    r.chain_id = chain_id
    r.verify_chain_id = AsyncMock(return_value=chain_id)
    r.transaction_count = AsyncMock(return_value=nonce)
    r.fee_history = AsyncMock(return_value={"baseFeePerGas": [hex(base_fee)] * 6})
    r.estimate_gas = AsyncMock(return_value=gas_estimate)
    r.send_raw_transaction = AsyncMock(return_value=tx_hash)
    return r


def _tx_repo() -> MagicMock:
    r = MagicMock()
    r.create = AsyncMock(return_value=MagicMock())
    r.add_hash = AsyncMock(return_value=MagicMock())
    return r


def _nonce_repo(nonce: int = 0) -> MagicMock:
    r = MagicMock()
    r.reserve_next = AsyncMock(return_value=nonce)
    r.release_if_unused = AsyncMock(return_value=True)
    r.init_for_wallet = AsyncMock(return_value=None)
    return r


@pytest.mark.asyncio
async def test_happy_path() -> None:
    request = _request()
    signer = _signer()
    rpc = _rpc(tx_hash="0x" + "ab" * 32)
    result = await sign_and_send(request, signer, rpc, _tx_repo(), _nonce_repo(nonce=42))
    assert result.hash == "0x" + "ab" * 32
    assert result.nonce == 42
    signer.address.assert_awaited_once_with("test-wallet")
    signer.sign_transaction.assert_awaited_once()
    rpc.send_raw_transaction.assert_awaited_once()


@pytest.mark.asyncio
async def test_chain_not_allowed_in_v030() -> None:
    request = _request(chain=14)  # Flare
    with pytest.raises(ChainNotAllowed):
        await sign_and_send(request, _signer(), _rpc(), _tx_repo(), _nonce_repo())


@pytest.mark.asyncio
async def test_wallet_not_found() -> None:
    signer = _signer()
    signer.address = AsyncMock(side_effect=WalletNotFoundError("no-such"))
    with pytest.raises(WalletNotFound):
        await sign_and_send(_request(), signer, _rpc(), _tx_repo(), _nonce_repo())


@pytest.mark.asyncio
async def test_rpc_unreachable_on_chain_id() -> None:
    rpc = _rpc()
    rpc.verify_chain_id = AsyncMock(side_effect=RpcUnavailable("conn refused"))
    with pytest.raises(RpcUnreachable):
        await sign_and_send(_request(), _signer(), rpc, _tx_repo(), _nonce_repo())


@pytest.mark.asyncio
async def test_rpc_unreachable_on_broadcast() -> None:
    rpc = _rpc()
    rpc.send_raw_transaction = AsyncMock(side_effect=RpcUnavailable("timeout"))
    with pytest.raises(RpcUnreachable):
        await sign_and_send(_request(), _signer(), rpc, _tx_repo(), _nonce_repo())


@pytest.mark.asyncio
async def test_vault_failure_during_sign() -> None:
    signer = _signer()
    signer.sign_transaction = AsyncMock(side_effect=VaultError("decrypt failed"))
    with pytest.raises(VaultUnavailableError):
        await sign_and_send(_request(), signer, _rpc(), _tx_repo(), _nonce_repo())


@pytest.mark.asyncio
async def test_estimate_gas_when_not_provided() -> None:
    request = _request(gas=None)
    rpc = _rpc(gas_estimate=50_000)
    signer = _signer()
    await sign_and_send(request, signer, rpc, _tx_repo(), _nonce_repo())
    rpc.estimate_gas.assert_awaited_once()
    # tx_dict passed to sign_transaction had gas = int(50_000 * 1.25) = 62_500
    args, _ = signer.sign_transaction.await_args
    _, tx_dict = args
    assert tx_dict["gas"] == 62_500


@pytest.mark.asyncio
async def test_explicit_gas_skips_estimate() -> None:
    request = _request(gas=200_000)
    rpc = _rpc()
    signer = _signer()
    await sign_and_send(request, signer, rpc, _tx_repo(), _nonce_repo())
    rpc.estimate_gas.assert_not_awaited()
    args, _ = signer.sign_transaction.await_args
    _, tx_dict = args
    assert tx_dict["gas"] == 200_000


@pytest.mark.asyncio
async def test_malformed_fee_history() -> None:
    rpc = _rpc()
    rpc.fee_history = AsyncMock(return_value={"baseFeePerGas": []})  # empty list
    with pytest.raises(RpcUnreachable, match="unexpected eth_feeHistory"):
        await sign_and_send(_request(), _signer(), rpc, _tx_repo(), _nonce_repo())


@pytest.mark.asyncio
async def test_tx_dict_shape() -> None:
    """The tx_dict passed to sign_transaction must be a valid EIP-1559 shape."""
    request = _request(value_wei="100", data="0xabcd")
    rpc = _rpc(base_fee=2_000_000_000)
    signer = _signer()
    await sign_and_send(request, signer, rpc, _tx_repo(), _nonce_repo(nonce=7))
    args, _ = signer.sign_transaction.await_args
    _, tx_dict = args
    assert tx_dict["type"] == 2
    assert tx_dict["chainId"] == 114
    assert tx_dict["nonce"] == 7
    assert tx_dict["to"] == request.to
    assert tx_dict["value"] == 100
    assert tx_dict["data"] == "0xabcd"
    # max_fee = 2e9 * 2 + 1e9 (tip) = 5e9
    assert tx_dict["maxFeePerGas"] == 5_000_000_000
    assert tx_dict["maxPriorityFeePerGas"] == 1_000_000_000


@pytest.mark.asyncio
async def test_sign_and_send_persists_transaction_row() -> None:
    """tx_repo.create is called once after broadcast with the right shape."""
    tx_repo = _tx_repo()
    request = _request(data="0xabcdef01aabbccdd")  # 8-byte data → method_name = "0xabcdef01"
    await sign_and_send(request, _signer(), _rpc(), tx_repo, _nonce_repo())

    tx_repo.create.assert_awaited_once()
    _, kwargs = tx_repo.create.call_args
    assert kwargs["status"] == "submitted"
    assert kwargs["caller"] == "test-caller"
    assert kwargs["method_name"] == "0xabcdef01"
    assert kwargs["signed_raw"] is not None
    assert kwargs["wallet"] == "test-wallet"
    assert kwargs["chain"] == 114

    tx_repo.add_hash.assert_awaited_once()
    _, hash_kwargs = tx_repo.add_hash.call_args
    assert hash_kwargs["sequence_num"] == 1


@pytest.mark.asyncio
async def test_sign_and_send_returns_tx_id_in_result() -> None:
    """result.tx_id is a valid UUIDv7 string."""
    result = await sign_and_send(_request(), _signer(), _rpc(), _tx_repo(), _nonce_repo())
    assert len(result.tx_id) == 36
    parsed = uuid.UUID(result.tx_id)
    assert parsed.version == 7


# --- v0.4.0a5: nonce_repo integration tests ---


@pytest.mark.asyncio
async def test_sign_and_send_uses_nonce_repo_not_rpc_for_nonce() -> None:
    """Happy path: nonce comes from nonce_repo, not rpc.transaction_count."""
    nonce_repo = _nonce_repo(nonce=5)
    rpc = _rpc()
    await sign_and_send(_request(), _signer(), rpc, _tx_repo(), nonce_repo)
    nonce_repo.reserve_next.assert_awaited_once_with("test-wallet", 114)
    rpc.transaction_count.assert_not_awaited()


@pytest.mark.asyncio
async def test_sign_and_send_init_path_when_nonce_uninitialized() -> None:
    """First reserve_next raises NonceNotInitializedError; use case seeds from RPC."""
    nonce_repo = _nonce_repo()
    nonce_repo.reserve_next = AsyncMock(side_effect=[NonceNotInitializedError("test-wallet"), 5])
    rpc = _rpc(nonce=5)
    await sign_and_send(_request(), _signer(), rpc, _tx_repo(), nonce_repo)
    rpc.transaction_count.assert_awaited_once_with("0xabc", block="pending")
    nonce_repo.init_for_wallet.assert_awaited_once_with("test-wallet", 114, 5)
    assert nonce_repo.reserve_next.await_count == 2


@pytest.mark.asyncio
async def test_sign_and_send_releases_nonce_on_vault_failure() -> None:
    """Vault failure during sign triggers safe-conditional nonce release."""
    nonce_repo = _nonce_repo(nonce=3)
    signer = _signer()
    signer.sign_transaction = AsyncMock(side_effect=VaultError("decrypt failed"))
    with pytest.raises(VaultUnavailableError):
        await sign_and_send(_request(), signer, _rpc(), _tx_repo(), nonce_repo)
    nonce_repo.release_if_unused.assert_awaited_once_with("test-wallet", 114, 3)


@pytest.mark.asyncio
async def test_sign_and_send_releases_nonce_on_fee_history_failure() -> None:
    """RPC fee_history failure triggers safe-conditional nonce release."""
    nonce_repo = _nonce_repo(nonce=7)
    rpc = _rpc()
    rpc.fee_history = AsyncMock(side_effect=RpcUnavailable("timeout"))
    with pytest.raises(RpcUnreachable):
        await sign_and_send(_request(), _signer(), rpc, _tx_repo(), nonce_repo)
    nonce_repo.release_if_unused.assert_awaited_once_with("test-wallet", 114, 7)


@pytest.mark.asyncio
async def test_sign_and_send_does_NOT_release_on_broadcast_failure() -> None:  # noqa: N802
    """Broadcast failure does NOT release — tx may have been seen by other nodes."""
    nonce_repo = _nonce_repo(nonce=9)
    rpc = _rpc()
    rpc.send_raw_transaction = AsyncMock(side_effect=RpcUnavailable("timeout"))
    with pytest.raises(RpcUnreachable):
        await sign_and_send(_request(), _signer(), rpc, _tx_repo(), nonce_repo)
    nonce_repo.release_if_unused.assert_not_awaited()
