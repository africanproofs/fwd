"""sign_transaction use case unit tests (v1.1.0a9 — zero-egress, sign-only).

All RPC-dependent tests removed (chain-id verify, broadcast success/failure,
estimate_gas, fee_history, TransactionRejected, RpcUnreachable). The absence
of an rpc object in the call signature is itself the proof that no broadcast
occurs.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_utils import to_checksum_address

from fwd.app.sign_transaction import (
    NonceNotInitialized,
    SignTransactionRequest,
    SignTransactionResult,
    TxParamsRejected,
    VaultUnavailableError,
    WalletNotFound,
    sign_transaction,
)
from fwd.domain.intent import DecodedIntent
from fwd.domain.signer import SignedTransaction
from fwd.infra.nonce_repo import NonceNotInitializedError
from fwd.infra.sealed_master import SealError
from fwd.infra.wallet_repo import Wallet, WalletNotFoundError


def _request(**kwargs: Any) -> SignTransactionRequest:
    defaults = {
        "wallet": "test-wallet",
        "caller": "test-caller",
        "chain": 114,
        "to": "0x" + "11" * 20,
        "value_wei": "0",
        "data": "0x",
        "gas": 21_000,
        "max_fee_per_gas": 3_000_000_000,
        "max_priority_fee_per_gas": 1_000_000_000,
    }
    defaults.update(kwargs)
    return SignTransactionRequest(**defaults)


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


def _tx_repo() -> MagicMock:
    r = MagicMock()
    r.create = AsyncMock(return_value=MagicMock())
    r.add_hash = AsyncMock(return_value=MagicMock())
    r.get_by_idempotency_key = AsyncMock(return_value=None)
    return r


def _nonce_repo(nonce: int = 0) -> MagicMock:
    r = MagicMock()
    r.reserve_next = AsyncMock(return_value=nonce)
    r.release_if_unused = AsyncMock(return_value=True)
    r.init_for_wallet = AsyncMock(return_value=None)
    return r


# ---------------------------------------------------------------------------
# Stubs for policy-gate keyword args.
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
    r.commit = AsyncMock(return_value=None)
    r.find_sign_transaction_seq = AsyncMock(return_value=None)
    return r


def _policy_kwargs(**overrides: Any) -> dict[str, Any]:
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


# ---------------------------------------------------------------------------
# Tests: sign-only happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sign_only_happy_path() -> None:
    """Happy path: result has a non-empty signed_raw_tx and hash; no RPC is involved."""
    request = _request()
    signer = _signer(signed_raw=b"\x02" + b"\x01" * 31)
    with patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())):
        result = await sign_transaction(
            request, signer, _tx_repo(), _nonce_repo(nonce=42), **_policy_kwargs()
        )
    assert isinstance(result, SignTransactionResult)
    assert result.signed_raw_tx.startswith("0x")
    assert len(result.signed_raw_tx) > 2
    assert result.hash.startswith("0x")
    assert result.nonce == 42
    # No RPC object exists — the absence of an rpc arg is the proof that no broadcast occurs.


@pytest.mark.asyncio
async def test_sign_only_tx_row_persisted_as_pending() -> None:
    """tx_repo.create is called once with status='pending' (not 'submitted')."""
    tx_repo = _tx_repo()
    request = _request(data="0xabcdef01aabbccdd")
    with patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())):
        await sign_transaction(request, _signer(), tx_repo, _nonce_repo(), **_policy_kwargs())

    tx_repo.create.assert_awaited_once()
    _, kwargs = tx_repo.create.call_args
    assert kwargs["status"] == "pending"
    assert kwargs["submitted_at"] is None
    assert kwargs["caller"] == "test-caller"
    assert kwargs["method_name"] == "0xabcdef01"
    assert kwargs["signed_raw"] is not None
    assert kwargs["wallet"] == "test-wallet"
    assert kwargs["chain"] == 114


# ---------------------------------------------------------------------------
# Tests: wallet-not-found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wallet_not_found() -> None:
    signer = _signer()
    signer.address = AsyncMock(side_effect=WalletNotFoundError("no-such"))
    with (
        patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(WalletNotFound),
    ):
        await sign_transaction(
            _request(), signer, _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )


# ---------------------------------------------------------------------------
# Tests: vault failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vault_failure_during_sign() -> None:
    signer = _signer()
    signer.sign_transaction = AsyncMock(side_effect=SealError("decrypt failed"))
    with (
        patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(VaultUnavailableError),
    ):
        await sign_transaction(
            _request(), signer, _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )


@pytest.mark.asyncio
async def test_vault_failure_releases_nonce() -> None:
    """Vault failure during sign triggers safe-conditional nonce release."""
    nonce_repo = _nonce_repo(nonce=3)
    signer = _signer()
    signer.sign_transaction = AsyncMock(side_effect=SealError("decrypt failed"))
    with (
        patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(VaultUnavailableError),
    ):
        await sign_transaction(_request(), signer, _tx_repo(), nonce_repo, **_policy_kwargs())
    nonce_repo.release_if_unused.assert_awaited_once_with("test-wallet", 114, 3)


# ---------------------------------------------------------------------------
# Tests: v1.1.0a12 live-drill fixes (checksum `to`; TypeError releases nonce)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_to_address_checksummed_before_sign() -> None:
    """Live-drill regression: a lowercase `to` must be EIP-55 checksummed before
    signing — eth_account raises TypeError on a non-checksummed address."""
    lower_to = "0x" + "ab" * 20  # valid hex, lowercase
    signer = _signer()
    with patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())):
        await sign_transaction(
            _request(to=lower_to), signer, _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )
    signer.sign_transaction.assert_awaited_once()
    tx_dict = signer.sign_transaction.call_args.args[1]
    assert tx_dict["to"] == to_checksum_address(lower_to)


@pytest.mark.asyncio
async def test_sign_typeerror_releases_nonce() -> None:
    """Live-drill class fix: eth_account raises TypeError (not ValueError) on a
    bad tx field; the pre-sign arm MUST catch it and release the reserved nonce,
    else a permanent nonce-wedge (Core #11 spirit; partners #14/#19)."""
    nonce_repo = _nonce_repo(nonce=5)
    signer = _signer()
    signer.sign_transaction = AsyncMock(side_effect=TypeError("invalid fields"))
    with (
        patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(TypeError),
    ):
        await sign_transaction(_request(), signer, _tx_repo(), nonce_repo, **_policy_kwargs())
    nonce_repo.release_if_unused.assert_awaited_once_with("test-wallet", 114, 5)


# ---------------------------------------------------------------------------
# Tests: nonce-not-initialized (NEW)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nonce_not_initialized_raises() -> None:
    """NonceNotInitializedError from reserve_next raises NonceNotInitialized (409)."""
    nonce_repo = _nonce_repo()
    nonce_repo.reserve_next = AsyncMock(side_effect=NonceNotInitializedError("test-wallet"))
    with (
        patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(NonceNotInitialized),
    ):
        await sign_transaction(
            _request(), _signer(), _tx_repo(), nonce_repo, **_policy_kwargs()
        )


# ---------------------------------------------------------------------------
# Tests: cap enforcement (NEW)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cap_gas_exceeded() -> None:
    """gas > FWD_MAX_GAS raises TxParamsRejected."""
    request = _request(gas=99_000_000)  # well above default 15_000_000
    audit = _audit_repo_mock()
    with (
        patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(TxParamsRejected, match="FWD_MAX_GAS"),
    ):
        await sign_transaction(
            request, _signer(), _tx_repo(), _nonce_repo(),
            **_policy_kwargs(audit_repo=audit),
        )
    audit.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_cap_max_fee_per_gas_exceeded() -> None:
    """max_fee_per_gas > FWD_MAX_FEE_PER_GAS raises TxParamsRejected."""
    request = _request(max_fee_per_gas=999_000_000_000_000)  # well above 500 gwei default
    audit = _audit_repo_mock()
    with (
        patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(TxParamsRejected, match="FWD_MAX_FEE_PER_GAS"),
    ):
        await sign_transaction(
            request, _signer(), _tx_repo(), _nonce_repo(),
            **_policy_kwargs(audit_repo=audit),
        )
    audit.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_cap_priority_exceeds_max_fee() -> None:
    """max_priority_fee_per_gas > max_fee_per_gas raises TxParamsRejected."""
    request = _request(max_fee_per_gas=1_000_000_000, max_priority_fee_per_gas=2_000_000_000)
    audit = _audit_repo_mock()
    with (
        patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())),
        pytest.raises(TxParamsRejected, match="max_priority_fee_per_gas"),
    ):
        await sign_transaction(
            request, _signer(), _tx_repo(), _nonce_repo(),
            **_policy_kwargs(audit_repo=audit),
        )
    audit.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# Tests: nonce reservation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_uses_nonce_repo_for_nonce() -> None:
    """Nonce comes from nonce_repo.reserve_next (no RPC transaction_count)."""
    nonce_repo = _nonce_repo(nonce=5)
    with patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())):
        result = await sign_transaction(
            _request(), _signer(), _tx_repo(), nonce_repo, **_policy_kwargs()
        )
    nonce_repo.reserve_next.assert_awaited_once_with("test-wallet", 114)
    assert result.nonce == 5


# ---------------------------------------------------------------------------
# Tests: idempotency replay
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_idempotency_replay() -> None:
    """Idempotency replay returns cached tx_id without re-evaluating policy."""
    existing_tx = MagicMock()
    existing_tx.tx_id = "existing-tx-id"
    existing_tx.nonce = 7
    existing_tx.signed_raw = "0xdeadbeef"

    tx_repo = _tx_repo()
    tx_repo.get_by_idempotency_key = AsyncMock(return_value=existing_tx)
    tx_repo.list_hashes_by_tx = AsyncMock(return_value=[])
    audit = _audit_repo_mock()
    audit.find_sign_transaction_seq = AsyncMock(return_value=None)

    request = _request(idempotency_key="test-key")
    with patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())) as mock_gate:
        result = await sign_transaction(
            request, _signer(), tx_repo, _nonce_repo(),
            **_policy_kwargs(audit_repo=audit),
        )
    mock_gate.assert_not_awaited()
    assert result.tx_id == "existing-tx-id"
    assert result.nonce == 7
    assert result.signed_raw_tx == "0xdeadbeef"


# ---------------------------------------------------------------------------
# Tests: tx_dict shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tx_dict_shape() -> None:
    """The tx_dict passed to sign_transaction must be a valid EIP-1559 shape."""
    request = _request(
        value_wei="100",
        data="0xabcd",
        gas=42_000,
        max_fee_per_gas=5_000_000_000,
        max_priority_fee_per_gas=2_000_000_000,
    )
    signer = _signer()
    with patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())):
        await sign_transaction(
            request, signer, _tx_repo(), _nonce_repo(nonce=7), **_policy_kwargs()
        )
    args, _ = signer.sign_transaction.await_args
    _, tx_dict = args
    assert tx_dict["type"] == 2
    assert tx_dict["chainId"] == 114
    assert tx_dict["nonce"] == 7
    assert tx_dict["to"] == request.to
    assert tx_dict["value"] == 100
    assert tx_dict["data"] == "0xabcd"
    assert tx_dict["gas"] == 42_000
    assert tx_dict["maxFeePerGas"] == 5_000_000_000
    assert tx_dict["maxPriorityFeePerGas"] == 2_000_000_000


# ---------------------------------------------------------------------------
# Tests: result shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_result_has_valid_uuidv7_tx_id() -> None:
    """result.tx_id is a valid UUIDv7 string."""
    with patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())):
        result = await sign_transaction(
            _request(), _signer(), _tx_repo(), _nonce_repo(), **_policy_kwargs()
        )
    assert len(result.tx_id) == 36
    parsed = uuid.UUID(result.tx_id)
    assert parsed.version == 7


# ---------------------------------------------------------------------------
# Tests: concurrent nonce monotonicity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sequential_nonce_monotonicity() -> None:
    """Consecutive reserve_next calls yield strictly increasing nonces."""
    nonces = [0, 1, 2]
    nonce_repo = _nonce_repo()
    nonce_repo.reserve_next = AsyncMock(side_effect=nonces)

    results = []
    for _ in nonces:
        with patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=_allow_decision())):
            r = await sign_transaction(
                _request(), _signer(), _tx_repo(), nonce_repo, **_policy_kwargs()
            )
        results.append(r.nonce)

    assert results == [0, 1, 2]
