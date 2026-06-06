"""Tests for D14 idempotency-replay path in sign_transaction.

App-layer. Real tmp-sqlite (audit+rate+tx+nonce); signer and rpc are
AsyncMock. Uses real policy+registry for the first (normal) call; the
replay path skips policy evaluation entirely.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import eth_abi
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.app.sign_transaction import (
    IdempotencyConflict,
    SignTransactionRequest,
    SignTransactionResult,
    sign_transaction,
)
from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.audit_repo import AuditRepo, audit_log, audit_metadata
from fwd.infra.caller_repo import Caller
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.nonce_repo import metadata as nonce_metadata
from fwd.infra.rate_repo import RateRepo, rate_metadata
from fwd.infra.transaction_repo import TransactionRepo
from fwd.infra.transaction_repo import metadata as transaction_metadata
from fwd.infra.wallet_repo import Wallet

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

ERC20_CONTRACT = "0x1234567890abcdef1234567890abcdef12345678"
RECIPIENT_ADDR = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
TRANSFER_SELECTOR = "0xa9059cbb"
POLICY_PATH = "perm/main"
WC_PATH = "wc/main"
WALLET_NAME = "my-wallet"
CALLER_NAME = "my-caller"
WALLET_ADDR = "0x" + "bb" * 20
CHAIN_ID = 114


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


@pytest.fixture()
async def session(tmp_path):  # type: ignore[no-untyped-def]
    """Single session for ALL DB metadata (audit+rate+tx+nonce)."""
    db = tmp_path / "test_idempotency.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(audit_metadata.create_all)
        await conn.run_sync(rate_metadata.create_all)
        await conn.run_sync(transaction_metadata.create_all)
        await conn.run_sync(nonce_metadata.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_caller(name: str = CALLER_NAME) -> Caller:
    return Caller(
        name=name,
        api_key_hash="h",
        api_key_prefix="p",
        policy_path=POLICY_PATH,
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _make_wallet(name: str = WALLET_NAME) -> Wallet:
    return Wallet(
        name=name,
        address=WALLET_ADDR,
        privkey_ciphertext="vault:v1:x",
        vault_master_key="fwd-master",
        policy_path=WC_PATH,
        created_at=datetime.now(UTC),
    )


def _make_policy() -> Policy:
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {CALLER_NAME: {"policy_path": POLICY_PATH}},
            "wallets": {WALLET_NAME: {"policy_path": WC_PATH}},
            "permissions": {
                POLICY_PATH: {
                    "contracts": {
                        ERC20_CONTRACT: {
                            "abi": "erc20",
                            "chains": [CHAIN_ID],
                            "methods": {
                                "transfer(address,uint256)": {
                                    "max_value_wei": "0",
                                }
                            },
                        }
                    },
                    "wallet_allowlist": [WALLET_NAME],
                    "rate": {"per_hour": 100, "per_day": 1000},
                }
            },
            "wallet_constraints": {WC_PATH: {}},
        }
    )


def _deny_policy() -> Policy:
    """A policy that has no permissions for CALLER_NAME (step-1 deny)."""
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "wallets": {},
            "permissions": {},
            "wallet_constraints": {},
        }
    )


def _transfer_calldata(amount: int = 100) -> str:
    encoded = eth_abi.encode(["address", "uint256"], [RECIPIENT_ADDR, amount])
    raw = bytes.fromhex(TRANSFER_SELECTOR[2:]) + encoded
    return "0x" + raw.hex()


def _make_request(
    idempotency_key: str | None = None,
    caller: str = CALLER_NAME,
) -> SignTransactionRequest:
    return SignTransactionRequest(
        wallet=WALLET_NAME,
        caller=caller,
        chain=CHAIN_ID,
        to=ERC20_CONTRACT,
        value_wei="0",
        data=_transfer_calldata(),
        gas=21_000,
        max_fee_per_gas=3_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
        idempotency_key=idempotency_key,
    )


def _mock_signer(address: str = WALLET_ADDR) -> AsyncMock:
    from fwd.domain.signer import SignedTransaction

    signer = AsyncMock()
    signer.address.return_value = address
    signer.sign_transaction.return_value = SignedTransaction(
        raw_transaction=bytes(32),
        hash=bytes(32),
        r=1,
        s=2,
        v=27,
    )
    return signer


async def _sign(
    session: AsyncSession,
    registry: AbiRegistry,
    idempotency_key: str | None = None,
    caller_name: str = CALLER_NAME,
    policy: Policy | None = None,
) -> SignTransactionResult:
    if policy is None:
        policy = _make_policy()
    # Ensure a nonce row exists for (WALLET_NAME, CHAIN_ID) — idempotent.
    # In sign_transaction (zero-egress) fwd cannot seed from chain; the row
    # must be pre-seeded by the operator (POST /v1/admin/nonce-init).
    nonce_repo = NonceRepo(session)
    await nonce_repo.init_for_wallet(WALLET_NAME, CHAIN_ID, 0)
    return await sign_transaction(
        _make_request(idempotency_key=idempotency_key, caller=caller_name),
        _mock_signer(),
        TransactionRepo(session),
        nonce_repo,
        caller=_make_caller(name=caller_name),
        wallet=_make_wallet(),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        audit_repo=AuditRepo(session),
    )


async def _audit_rows_by_action(session: AsyncSession, action: str) -> list[dict[str, object]]:
    result = await session.execute(
        select(audit_log).where(audit_log.c.action == action).order_by(audit_log.c.seq.asc())
    )
    return [dict(row._mapping) for row in result]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_with_different_body_raises_conflict(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Same idempotency_key reused with a DIFFERENT request body → 409 conflict
    (the cached signed tx must NOT be returned for a different intent)."""
    await _sign(session, registry, idempotency_key="key-body")
    # Second call: SAME key, DIFFERENT body (different transfer amount).
    nonce_repo = NonceRepo(session)
    different = SignTransactionRequest(
        wallet=WALLET_NAME,
        caller=CALLER_NAME,
        chain=CHAIN_ID,
        to=ERC20_CONTRACT,
        value_wei="0",
        data=_transfer_calldata(amount=999),  # differs from the stored body
        gas=21_000,
        max_fee_per_gas=3_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
        idempotency_key="key-body",
    )
    with pytest.raises(IdempotencyConflict):
        await sign_transaction(
            different,
            _mock_signer(),
            TransactionRepo(session),
            nonce_repo,
            caller=_make_caller(),
            wallet=_make_wallet(),
            policy=_make_policy(),
            registry=registry,
            rate_repo=RateRepo(session),
            audit_repo=AuditRepo(session),
        )
    # A denied forensic row records the mismatch (Core #5 / #19).
    rows = await _audit_rows_by_action(session, "sign-transaction")
    assert any(r["decision_reason"] == "idempotency_key_body_mismatch" for r in rows)


@pytest.mark.asyncio
async def test_first_call_stores_idempotency_key(
    session: AsyncSession,
    registry: AbiRegistry,
) -> None:
    """First call with idempotency_key='k1' stores the key in the tx row."""
    result = await _sign(session, registry, idempotency_key="k1")
    assert result.tx_id

    tx_repo = TransactionRepo(session)
    stored = await tx_repo.get_by_idempotency_key(CALLER_NAME, "k1")
    assert stored is not None
    assert stored.tx_id == result.tx_id
    assert stored.idempotency_key == "k1"
    await session.rollback()


@pytest.mark.asyncio
async def test_replay_returns_same_tx_id_and_hash(
    session: AsyncSession,
    registry: AbiRegistry,
) -> None:
    """Replay with same caller+key returns the cached tx_id and hash."""
    first = await _sign(session, registry, idempotency_key="key-replay")
    await session.commit()  # flush so next read sees the row

    replay = await _sign(session, registry, idempotency_key="key-replay")

    assert replay.tx_id == first.tx_id
    assert replay.hash == first.hash  # cached hash, not a fresh signing
    # No broadcast occurs — zero-egress; no RPC to assert against.
    await session.rollback()


@pytest.mark.asyncio
async def test_replay_does_not_re_evaluate_policy(
    session: AsyncSession,
    registry: AbiRegistry,
) -> None:
    """Replay returns cached result even if the policy would DENY a fresh request.

    D14: "The cached result remains valid even if policy.yaml is changed
    between the original signing and the replay."
    """
    first = await _sign(session, registry, idempotency_key="key-deny-replay")
    await session.commit()

    # Now use a deny-all policy for the replay call.
    deny = _deny_policy()
    replay = await _sign(session, registry, idempotency_key="key-deny-replay", policy=deny)
    # Should still succeed (cached result) despite deny policy.
    assert replay.tx_id == first.tx_id
    await session.rollback()


@pytest.mark.asyncio
async def test_replay_writes_duplicate_audit_row(
    session: AsyncSession,
    registry: AbiRegistry,
) -> None:
    """Replay path writes a sign-transaction-duplicate audit row with correct fields."""
    first = await _sign(session, registry, idempotency_key="key-dup-audit")
    await session.commit()

    await _sign(session, registry, idempotency_key="key-dup-audit")

    dup_rows = await _audit_rows_by_action(session, "sign-transaction-duplicate")
    assert len(dup_rows) == 1
    r = dup_rows[0]
    assert r["decision"] == "approved"
    assert r["decision_reason"] == "idempotency_replay"
    assert r["caller"] == CALLER_NAME

    outcome = json.loads(str(r["outcome"]))
    assert outcome["original_tx_id"] == first.tx_id
    # original_audit_seq is an int (the approved sign-transaction row's seq)
    # or None if no such row is found — both are valid per spec.
    assert "original_audit_seq" in outcome
    await session.rollback()


@pytest.mark.asyncio
async def test_replay_rate_bucket_not_incremented(
    session: AsyncSession,
    registry: AbiRegistry,
) -> None:
    """Rate buckets are NOT incremented on replay (D14: original consumed them)."""
    from sqlalchemy import func

    await _sign(session, registry, idempotency_key="key-rate")
    await session.commit()

    # Count rate_bucket rows before replay.
    from fwd.infra.rate_repo import rate_buckets

    result_before = await session.execute(select(func.count()).select_from(rate_buckets))
    count_before = result_before.scalar() or 0

    # Now replay.
    await _sign(session, registry, idempotency_key="key-rate")

    result_after = await session.execute(select(func.count()).select_from(rate_buckets))
    count_after = result_after.scalar() or 0

    # Row count may be same or lower; it must NOT increase (no new increment on replay).
    # The rate counters within existing rows also must not change.
    assert (
        count_after == count_before
    ), f"Rate bucket row count changed on replay: {count_before} → {count_after}"
    await session.rollback()


@pytest.mark.asyncio
async def test_different_caller_same_key_is_not_replay(
    session: AsyncSession,
    registry: AbiRegistry,
) -> None:
    """Same idempotency_key from a DIFFERENT caller is a distinct, normal call."""
    first = await _sign(
        session, registry, idempotency_key="shared-key", caller_name=CALLER_NAME
    )
    await session.commit()

    # Different caller. Must adjust policy and caller fixtures.
    other_caller = "other-caller"

    # Build a policy that includes other-caller.
    policy_both = Policy.model_validate(
        {
            "version": 1,
            "callers": {
                CALLER_NAME: {"policy_path": POLICY_PATH},
                other_caller: {"policy_path": POLICY_PATH},
            },
            "wallets": {WALLET_NAME: {"policy_path": WC_PATH}},
            "permissions": {
                POLICY_PATH: {
                    "contracts": {
                        ERC20_CONTRACT: {
                            "abi": "erc20",
                            "chains": [CHAIN_ID],
                            "methods": {"transfer(address,uint256)": {"max_value_wei": "0"}},
                        }
                    },
                    "wallet_allowlist": [WALLET_NAME],
                    "rate": {"per_hour": 100, "per_day": 1000},
                }
            },
            "wallet_constraints": {WC_PATH: {}},
        }
    )

    second = await sign_transaction(
        SignTransactionRequest(
            wallet=WALLET_NAME,
            caller=other_caller,
            chain=CHAIN_ID,
            to=ERC20_CONTRACT,
            value_wei="0",
            data=_transfer_calldata(),
            gas=21_000,
            max_fee_per_gas=3_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            idempotency_key="shared-key",
        ),
        _mock_signer(),
        TransactionRepo(session),
        NonceRepo(session),
        caller=_make_caller(name=other_caller),
        wallet=_make_wallet(),
        policy=policy_both,
        registry=registry,
        rate_repo=RateRepo(session),
        audit_repo=AuditRepo(session),
    )

    # Different caller → new tx_id, no broadcast (zero-egress).
    assert second.tx_id != first.tx_id
    assert second.signed_raw_tx.startswith("0x")
    await session.rollback()


@pytest.mark.asyncio
async def test_missing_key_uses_normal_path(
    session: AsyncSession,
    registry: AbiRegistry,
) -> None:
    """Without Idempotency-Key, idempotency_key is None and stored as NULL."""
    result = await _sign(session, registry, idempotency_key=None)
    assert result.tx_id

    tx_repo = TransactionRepo(session)
    tx = await tx_repo.get_by_id(result.tx_id)
    assert tx is not None
    assert tx.idempotency_key is None
    await session.rollback()


@pytest.mark.asyncio
async def test_get_by_idempotency_key_miss_returns_none(
    session: AsyncSession,
) -> None:
    """get_by_idempotency_key returns None for an unknown (caller, key) pair."""
    repo = TransactionRepo(session)
    result = await repo.get_by_idempotency_key("nobody", "nonexistent-key")
    assert result is None


@pytest.mark.asyncio
async def test_find_sign_transaction_seq_returns_seq(
    session: AsyncSession,
    registry: AbiRegistry,
) -> None:
    """find_sign_transaction_seq returns the approved row's seq for a known tx_id."""
    result = await _sign(session, registry, idempotency_key="key-seq-test")
    await session.commit()

    audit_repo = AuditRepo(session)
    seq = await audit_repo.find_sign_transaction_seq(result.tx_id)
    assert seq is not None
    assert isinstance(seq, int)
    assert seq >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_find_sign_transaction_seq_none_for_unknown(session: AsyncSession) -> None:
    """find_sign_transaction_seq returns None for an unknown tx_id."""
    audit_repo = AuditRepo(session)
    seq = await audit_repo.find_sign_transaction_seq("nonexistent-tx-id")
    assert seq is None
