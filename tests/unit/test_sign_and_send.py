"""sign_and_send use case unit tests with mocked signer + rpc."""
from __future__ import annotations

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
from fwd.infra.rpc import RpcUnavailable
from fwd.infra.vault_client import VaultError
from fwd.infra.wallet_repo import WalletNotFoundError


def _request(**kwargs: Any) -> SignAndSendRequest:
    defaults = {
        "wallet": "test-wallet",
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
    s.sign_transaction = AsyncMock(return_value=SignedTransaction(
        raw_transaction=signed_raw,
        hash=b"\x00" * 32,
        r=1, s=2, v=27,
    ))
    return s


def _rpc(chain_id: int = 114, nonce: int = 0, base_fee: int = 1_000_000_000,
         gas_estimate: int = 21000, tx_hash: str = "0x" + "de" * 32) -> MagicMock:
    r = MagicMock()
    r.chain_id = chain_id
    r.verify_chain_id = AsyncMock(return_value=chain_id)
    r.transaction_count = AsyncMock(return_value=nonce)
    r.fee_history = AsyncMock(return_value={"baseFeePerGas": [hex(base_fee)] * 6})
    r.estimate_gas = AsyncMock(return_value=gas_estimate)
    r.send_raw_transaction = AsyncMock(return_value=tx_hash)
    return r


@pytest.mark.asyncio
async def test_happy_path() -> None:
    request = _request()
    signer = _signer()
    rpc = _rpc(nonce=42, tx_hash="0x" + "ab" * 32)
    result = await sign_and_send(request, signer, rpc)
    assert result.hash == "0x" + "ab" * 32
    assert result.nonce == 42
    signer.address.assert_awaited_once_with("test-wallet")
    signer.sign_transaction.assert_awaited_once()
    rpc.send_raw_transaction.assert_awaited_once()


@pytest.mark.asyncio
async def test_chain_not_allowed_in_v030() -> None:
    request = _request(chain=14)  # Flare
    with pytest.raises(ChainNotAllowed):
        await sign_and_send(request, _signer(), _rpc())


@pytest.mark.asyncio
async def test_wallet_not_found() -> None:
    signer = _signer()
    signer.address = AsyncMock(side_effect=WalletNotFoundError("no-such"))
    with pytest.raises(WalletNotFound):
        await sign_and_send(_request(), signer, _rpc())


@pytest.mark.asyncio
async def test_rpc_unreachable_on_chain_id() -> None:
    rpc = _rpc()
    rpc.verify_chain_id = AsyncMock(side_effect=RpcUnavailable("conn refused"))
    with pytest.raises(RpcUnreachable):
        await sign_and_send(_request(), _signer(), rpc)


@pytest.mark.asyncio
async def test_rpc_unreachable_on_broadcast() -> None:
    rpc = _rpc()
    rpc.send_raw_transaction = AsyncMock(side_effect=RpcUnavailable("timeout"))
    with pytest.raises(RpcUnreachable):
        await sign_and_send(_request(), _signer(), rpc)


@pytest.mark.asyncio
async def test_vault_failure_during_sign() -> None:
    signer = _signer()
    signer.sign_transaction = AsyncMock(side_effect=VaultError("decrypt failed"))
    with pytest.raises(VaultUnavailableError):
        await sign_and_send(_request(), signer, _rpc())


@pytest.mark.asyncio
async def test_estimate_gas_when_not_provided() -> None:
    request = _request(gas=None)
    rpc = _rpc(gas_estimate=50_000)
    signer = _signer()
    await sign_and_send(request, signer, rpc)
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
    await sign_and_send(request, signer, rpc)
    rpc.estimate_gas.assert_not_awaited()
    args, _ = signer.sign_transaction.await_args
    _, tx_dict = args
    assert tx_dict["gas"] == 200_000


@pytest.mark.asyncio
async def test_malformed_fee_history() -> None:
    rpc = _rpc()
    rpc.fee_history = AsyncMock(return_value={"baseFeePerGas": []})  # empty list
    with pytest.raises(RpcUnreachable, match="unexpected eth_feeHistory"):
        await sign_and_send(_request(), _signer(), rpc)


@pytest.mark.asyncio
async def test_tx_dict_shape() -> None:
    """The tx_dict passed to sign_transaction must be a valid EIP-1559 shape."""
    request = _request(value_wei="100", data="0xabcd")
    rpc = _rpc(nonce=7, base_fee=2_000_000_000)
    signer = _signer()
    await sign_and_send(request, signer, rpc)
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
