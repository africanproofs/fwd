"""sign_and_send use case unit tests with mocked signer + rpc + tx_repo + nonce_repo.

v0.5.0a6: sign_and_send now requires caller, wallet, policy, registry,
rate_repo, audit_repo keyword args. The policy gate is stubbed via an
AllowDecision-returning mock so existing tests continue to exercise the
signer/RPC/nonce_repo failure paths in isolation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fwd.app.sign_and_send import (
    RpcUnreachable,
    SignAndSendRequest,
    TransactionRejected,
    VaultUnavailableError,
    WalletNotFound,
    sign_and_send,
)
from fwd.domain.intent import DecodedIntent
from fwd.domain.signer import SignedTransaction
from fwd.infra.nonce_repo import NonceNotInitializedError
from fwd.infra.rpc import RpcError, RpcUnavailable
from fwd.infra.sealed_master import SealError
from fwd.infra.wallet_repo import Wallet, WalletNotFoundError


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


# ---------------------------------------------------------------------------
# v0.5.0a6 — stubs for the new required keyword args.
# The policy gate is mocked at the module level so existing tests exercise
# the signer/RPC/nonce_repo paths without needing a real policy/registry.
# ---------------------------------------------------------------------------

_DECODED_INTENT = DecodedIntent(
    contract="0x" + "11" * 20,
    method_signature="transfer(address,uint256)",
    selector="0xa9059cbb",
    args={"to": "0x" + "33" * 20, "value": 0},
)


def _fake_caller() -> MagicMock:
    c = MagicMock()
    c.name = "test-caller"
    c.policy_path = "perm/test"
    return c


def _fake_wallet() -> Wallet:
    return Wallet(
        name="test-wallet",
        address="0x" + "aa" * 20,
        privkey_ciphertext="vault:v1:x",
        vault_master_key="fwd-master",
        policy_path="wc/test",
        created_at=datetime.now(UTC),
    )


def _fake_policy() -> MagicMock:
    p = MagicMock()
    return p


def _fake_registry() -> MagicMock:
    return MagicMock()


def _rate_repo_mock() -> MagicMock:
    r = MagicMock()
    r.add_committed_value = AsyncMock(return_value=None)
    r.release_caller = AsyncMock(return_value=None)
    r.release_wallet = AsyncMock(return_value=None)
    return r


def _audit_repo_mock() -> MagicMock:
    r = MagicMock()
    r.append = AsyncMock(return_value=MagicMock())
    # v0.5.2: the deny/error arms commit the forensic row before re-raising
    # (D16 / Core invariant #5 — survives the session_scope rollback).
    r.commit = AsyncMock(return_value=None)
    return r


def _policy_kwargs(**overrides: Any) -> dict[str, Any]:
    """Return default policy-gate keyword args for sign_and_send.

    Patches policy_gate.gate to return an AllowDecision so the existing
    tests can call sign_and_send without a real policy/registry/rate_repo.
    Overrides are passed through.
    """
    return {
        "caller": _fake_caller(),
        "wallet": _fake_wallet(),
        "policy": _fake_policy(),
        "registry": _fake_registry(),
        "rate_repo": _rate_repo_mock(),
        "audit_repo": _audit_repo_mock(),
        **overrides,
    }


def _allow_decision() -> MagicMock:
    from fwd.app.policy_engine import AllowDecision

    return AllowDecision(decoded=_DECODED_INTENT, matched_policy_path="perm/test")


@pytest.mark.asyncio
async def test_happy_path() -> None:
    request = _request()
    signer = _signer()
    rpc = _rpc(tx_hash="0x" + "ab" * 32)
    with patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())):
        result = await sign_and_send(
            request, signer, rpc, _tx_repo(), _nonce_repo(nonce=42), **_policy_kwargs()
        )
    assert result.hash == "0x" + "ab" * 32
    assert result.nonce == 42
    signer.address.assert_awaited_once_with("test-wallet")
    signer.sign_transaction.assert_awaited_once()
    rpc.send_raw_transaction.assert_awaited_once()


@pytest.mark.asyncio
async def test_wallet_not_found() -> None:
    signer = _signer()
    signer.address = AsyncMock(side_effect=WalletNotFoundError("no-such"))
    with (
        patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(WalletNotFound),
    ):
        await sign_and_send(
            _request(), signer, _rpc(), _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )


@pytest.mark.asyncio
async def test_rpc_unreachable_on_chain_id() -> None:
    rpc = _rpc()
    rpc.verify_chain_id = AsyncMock(side_effect=RpcUnavailable("conn refused"))
    with (
        patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(RpcUnreachable),
    ):
        await sign_and_send(
            _request(), _signer(), rpc, _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )


@pytest.mark.asyncio
async def test_rpc_unreachable_on_broadcast() -> None:
    rpc = _rpc()
    rpc.send_raw_transaction = AsyncMock(side_effect=RpcUnavailable("timeout"))
    with (
        patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(RpcUnreachable),
    ):
        await sign_and_send(
            _request(), _signer(), rpc, _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )


@pytest.mark.asyncio
async def test_vault_failure_during_sign() -> None:
    signer = _signer()
    signer.sign_transaction = AsyncMock(side_effect=SealError("decrypt failed"))
    with (
        patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(VaultUnavailableError),
    ):
        await sign_and_send(
            _request(), signer, _rpc(), _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )


@pytest.mark.asyncio
async def test_estimate_gas_when_not_provided() -> None:
    request = _request(gas=None)
    rpc = _rpc(gas_estimate=50_000)
    signer = _signer()
    with patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())):
        await sign_and_send(request, signer, rpc, _tx_repo(), _nonce_repo(), **_policy_kwargs())
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
    with patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())):
        await sign_and_send(request, signer, rpc, _tx_repo(), _nonce_repo(), **_policy_kwargs())
    rpc.estimate_gas.assert_not_awaited()
    args, _ = signer.sign_transaction.await_args
    _, tx_dict = args
    assert tx_dict["gas"] == 200_000


@pytest.mark.asyncio
async def test_malformed_fee_history() -> None:
    rpc = _rpc()
    rpc.fee_history = AsyncMock(return_value={"baseFeePerGas": []})  # empty list
    with (
        patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(RpcUnreachable, match="unexpected eth_feeHistory"),
    ):
        await sign_and_send(
            _request(), _signer(), rpc, _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )


@pytest.mark.asyncio
async def test_tx_dict_shape() -> None:
    """The tx_dict passed to sign_transaction must be a valid EIP-1559 shape."""
    request = _request(value_wei="100", data="0xabcd")
    rpc = _rpc(base_fee=2_000_000_000)
    signer = _signer()
    with patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())):
        await sign_and_send(
            request, signer, rpc, _tx_repo(), _nonce_repo(nonce=7), **_policy_kwargs()
        )
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
    with patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())):
        await sign_and_send(request, _signer(), _rpc(), tx_repo, _nonce_repo(), **_policy_kwargs())

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
    with patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())):
        result = await sign_and_send(
            _request(), _signer(), _rpc(), _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )
    assert len(result.tx_id) == 36
    parsed = uuid.UUID(result.tx_id)
    assert parsed.version == 7


# --- v0.4.0a5: nonce_repo integration tests ---


@pytest.mark.asyncio
async def test_sign_and_send_uses_nonce_repo_not_rpc_for_nonce() -> None:
    """Happy path: nonce comes from nonce_repo, not rpc.transaction_count."""
    nonce_repo = _nonce_repo(nonce=5)
    rpc = _rpc()
    with patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())):
        await sign_and_send(_request(), _signer(), rpc, _tx_repo(), nonce_repo, **_policy_kwargs())
    nonce_repo.reserve_next.assert_awaited_once_with("test-wallet", 114)
    rpc.transaction_count.assert_not_awaited()


@pytest.mark.asyncio
async def test_sign_and_send_init_path_when_nonce_uninitialized() -> None:
    """First reserve_next raises NonceNotInitializedError; use case seeds from RPC."""
    nonce_repo = _nonce_repo()
    nonce_repo.reserve_next = AsyncMock(side_effect=[NonceNotInitializedError("test-wallet"), 5])
    rpc = _rpc(nonce=5)
    with patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())):
        await sign_and_send(_request(), _signer(), rpc, _tx_repo(), nonce_repo, **_policy_kwargs())
    rpc.transaction_count.assert_awaited_once_with("0xabc", block="pending")
    nonce_repo.init_for_wallet.assert_awaited_once_with("test-wallet", 114, 5)
    assert nonce_repo.reserve_next.await_count == 2


@pytest.mark.asyncio
async def test_sign_and_send_releases_nonce_on_vault_failure() -> None:
    """Vault failure during sign triggers safe-conditional nonce release."""
    nonce_repo = _nonce_repo(nonce=3)
    signer = _signer()
    signer.sign_transaction = AsyncMock(side_effect=SealError("decrypt failed"))
    with (
        patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(VaultUnavailableError),
    ):
        await sign_and_send(_request(), signer, _rpc(), _tx_repo(), nonce_repo, **_policy_kwargs())
    nonce_repo.release_if_unused.assert_awaited_once_with("test-wallet", 114, 3)


@pytest.mark.asyncio
async def test_sign_and_send_releases_nonce_on_fee_history_failure() -> None:
    """RPC fee_history failure triggers safe-conditional nonce release."""
    nonce_repo = _nonce_repo(nonce=7)
    rpc = _rpc()
    rpc.fee_history = AsyncMock(side_effect=RpcUnavailable("timeout"))
    with (
        patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(RpcUnreachable),
    ):
        await sign_and_send(_request(), _signer(), rpc, _tx_repo(), nonce_repo, **_policy_kwargs())
    nonce_repo.release_if_unused.assert_awaited_once_with("test-wallet", 114, 7)


@pytest.mark.asyncio
async def test_sign_and_send_does_NOT_release_on_broadcast_failure() -> None:  # noqa: N802
    """Broadcast failure does NOT release — tx may have been seen by other nodes."""
    nonce_repo = _nonce_repo(nonce=9)
    rpc = _rpc()
    rpc.send_raw_transaction = AsyncMock(side_effect=RpcUnavailable("timeout"))
    with (
        patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(RpcUnreachable),
    ):
        await sign_and_send(_request(), _signer(), rpc, _tx_repo(), nonce_repo, **_policy_kwargs())
    nonce_repo.release_if_unused.assert_not_awaited()


@pytest.mark.asyncio
async def test_broadcast_rejected_releases_nonce_and_is_terminal() -> None:
    """A node-deterministic rejection (RpcError from eth_sendRawTransaction —
    e.g. -32000 insufficient funds) is TERMINAL, not retryable: the reserved
    nonce + rate are released (the tx is provably not in flight) and the
    caller gets TransactionRejected, NOT RpcUnreachable/502. This is the
    inverse pair of test_sign_and_send_does_NOT_release_on_broadcast_failure
    (RpcUnavailable retains). Regression for the v1.0.0 Coston2-rehearsal
    live-drill finding: a retained nonce here permanently wedges the wallet
    because startup reconcile only logs the drift, never heals it."""
    nonce_repo = _nonce_repo(nonce=9)
    rpc = _rpc()
    rpc.send_raw_transaction = AsyncMock(
        side_effect=RpcError("rpc 114 eth_sendRawTransaction: -32000 insufficient funds")
    )
    audit = _audit_repo_mock()
    with (
        patch("fwd.app.sign_and_send.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(TransactionRejected),
    ):
        await sign_and_send(
            _request(),
            _signer(),
            rpc,
            _tx_repo(),
            nonce_repo,
            **_policy_kwargs(audit_repo=audit),
        )
    nonce_repo.release_if_unused.assert_awaited_once_with("test-wallet", 114, 9)
    audit.commit.assert_awaited_once()


# --- legacy test for removed chain allowlist ---


@pytest.mark.asyncio
async def test_chain_not_allowed_removed_in_v050a6() -> None:
    """The v0.3.0 ALLOWED_CHAINS gate is removed; policy engine is now sole authZ.

    Previously Flare (chain_id=14) was rejected with ChainNotAllowed before reaching
    the policy engine. Now the chain gate is gone; rejection comes from the policy
    engine (via PolicyDenied) or from RpcUnreachable (unknown chain → _resolve_url
    raises). This test verifies ChainNotAllowed is no longer raised by sign_and_send
    for a chain that merely wasn't in the v0.3.0 allowlist.
    """
    from fwd.app.policy_gate import PolicyDenied

    request = _request(chain=14)  # Flare — was rejected by ALLOWED_CHAINS in v0.3.0
    # Policy gate rejects (no policy for Flare in the stub) — that's PolicyDenied, not ChainNotAllowed.
    # gate mock raises PolicyDenied to simulate a policy denial.
    with (
        patch(
            "fwd.app.sign_and_send.gate",
            new=AsyncMock(side_effect=PolicyDenied(step=1, reason="caller not in policy")),
        ),
        pytest.raises(PolicyDenied),
    ):
        await sign_and_send(
            request, _signer(), _rpc(), _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )
