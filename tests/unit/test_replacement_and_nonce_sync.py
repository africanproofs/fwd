"""Tests for v1.1.0a13: sign-replacement, nonce-sync, nonce/holes, attempt recording.

Coverage:
- Migration schema: transaction_attempts table + reserved_at column exist in create_all.
- sign_transaction records attempt 1 + reserved_at.
- POST /v1/transactions/{tx_id}/sign-replacement: happy bump, bump-too-low,
  cap-exhausted, wrong-state (pending→409), cross-caller→404, sign failure.
- POST /v1/admin/nonce-sync: in-sync no-op, bounded advance, out-of-bounds→409,
  rewind→409, missing row→404, admin-auth required.
- GET /v1/admin/nonce/holes: stale pending surfaces; fresh pending does not;
  submitted tx does not.

asyncio_mode = "auto" (set in pyproject.toml).
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.api.admin_auth import require_admin
from fwd.api.caller_auth import require_caller
from fwd.api.nonce import router as nonce_router
from fwd.api.transactions import router as transactions_router
from fwd.app.dependencies import (
    AdminScope,
    ReplacementScope,
    ReportScope,
    get_admin_scope,
    get_replacement_scope,
    get_report_scope,
    get_transaction_repo,
)
from fwd.infra.audit_repo import AuditRepo, audit_log, audit_metadata
from fwd.infra.caller_repo import Caller
from fwd.infra.nonce_repo import NonceRepo, nonces
from fwd.infra.nonce_repo import metadata as nonce_metadata
from fwd.infra.rate_repo import RateRepo, rate_metadata
from fwd.infra.transaction_repo import (
    TransactionAttemptRepo,
    TransactionRepo,
    transaction_attempts,
    transactions,
)
from fwd.infra.transaction_repo import (
    metadata as transaction_metadata,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WALLET = "test-wallet"
CHAIN = 114
CALLER_A = "caller-a"
CALLER_B = "caller-b"
TX_HASH_1 = "0x" + "ab" * 32
TX_HASH_2 = "0x" + "cd" * 32


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_caller(name: str = CALLER_A) -> Caller:
    return Caller(
        name=name,
        api_key_hash="h",
        api_key_prefix="p",
        policy_path=f"policies/{name}.yaml",
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _fake_admin_scope(session: AsyncSession) -> AdminScope:
    from fwd.infra.transaction_repo import TransactionRepo

    return AdminScope(
        signer=MagicMock(),
        caller_repo=MagicMock(),
        audit_repo=AuditRepo(session),
        nonce_repo=NonceRepo(session),
        tx_repo=TransactionRepo(session),
    )


# ---------------------------------------------------------------------------
# DB fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
async def db_session(tmp_path):  # type: ignore[no-untyped-def]
    """Yield a session with transactions + transaction_attempts + nonces + audit tables."""
    db = tmp_path / "test_a13.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(transaction_metadata.create_all)
        await conn.run_sync(nonce_metadata.create_all)
        await conn.run_sync(audit_metadata.create_all)
        await conn.run_sync(rate_metadata.create_all)
    async with AsyncSession(engine) as session:
        yield session
    await engine.dispose()


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


async def _seed_tx(
    session: AsyncSession,
    *,
    tx_id: str,
    caller: str = CALLER_A,
    status: str = "pending",
    nonce: int = 5,
    reserved_at: datetime | None = None,
    contract_address: str | None = None,
    value_wei: str = "0",
    request_json: str | None = None,
) -> None:
    addr = contract_address or ("0x" + "11" * 20)
    rj = request_json or json.dumps(
        {
            "wallet": WALLET,
            "chain": CHAIN,
            "to": addr,
            "value_wei": value_wei,
            "data": "0x",
            "gas": 21000,
            "max_fee_per_gas": 1_000_000_000,
            "max_priority_fee_per_gas": 500_000_000,
        }
    )
    await session.execute(
        transactions.insert().values(
            tx_id=tx_id,
            wallet=WALLET,
            chain=CHAIN,
            caller=caller,
            nonce=nonce,
            contract_address=addr,
            method_name="0x",
            value_wei=value_wei,
            idempotency_key=None,
            request_json=rj,
            signed_raw="0xdeadbeef",
            status=status,
            submitted_at=None,
            confirmed_at=None,
            receipt_json=None,
            created_at=datetime.now(UTC),
            reserved_at=reserved_at,
        )
    )
    await session.commit()


async def _seed_tx_hash(
    session: AsyncSession,
    *,
    tx_id: str,
    hash_hex: str = TX_HASH_1,
    sequence_num: int = 1,
) -> None:
    from fwd.infra.transaction_repo import transaction_hashes

    await session.execute(
        transaction_hashes.insert().values(
            tx_id=tx_id,
            sequence_num=sequence_num,
            hash_hex=hash_hex,
            submitted_at=datetime.now(UTC),
        )
    )
    await session.commit()


async def _seed_attempt(
    session: AsyncSession,
    *,
    tx_id: str,
    sequence_num: int = 1,
    gas: int = 21_000,
    max_fee_per_gas: int = 1_000_000_000,
    max_priority_fee_per_gas: int = 500_000_000,
    signed_raw: str = "0xsigned1",
    hash: str = TX_HASH_1,
) -> None:
    await session.execute(
        transaction_attempts.insert().values(
            tx_id=tx_id,
            sequence_num=sequence_num,
            gas=gas,
            max_fee_per_gas=max_fee_per_gas,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            signed_raw=signed_raw,
            hash=hash,
            created_at=datetime.now(UTC),
        )
    )
    await session.commit()


async def _seed_nonce(
    session: AsyncSession,
    *,
    wallet: str = WALLET,
    chain: int = CHAIN,
    next_nonce: int = 6,
    last_confirmed: int | None = None,
) -> None:
    await session.execute(
        nonces.insert().values(
            wallet=wallet,
            chain=chain,
            next_nonce=next_nonce,
            last_confirmed=last_confirmed,
            last_reconciled_at=datetime.now(UTC),
        )
    )
    await session.commit()


# ---------------------------------------------------------------------------
# Scope CM stubs for dependency injection
# ---------------------------------------------------------------------------


class _RealReplacementScopeCM:
    """Async CM wrapping a ReplacementScope backed by a fixture session + mock signer."""

    def __init__(self, session: AsyncSession, signer: Any | None = None) -> None:
        self._session = session
        self._signer = signer or MagicMock()

    async def __aenter__(self) -> ReplacementScope:
        return ReplacementScope(
            signer=self._signer,
            tx_repo=TransactionRepo(self._session),
            attempt_repo=TransactionAttemptRepo(self._session),
            nonce_repo=NonceRepo(self._session),
            audit_repo=AuditRepo(self._session),
        )

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is None:
            await self._session.commit()
        else:
            await self._session.rollback()


class _RealReportScopeCM:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def __aenter__(self) -> ReportScope:
        return ReportScope(
            tx_repo=TransactionRepo(self._session),
            nonce_repo=NonceRepo(self._session),
            audit_repo=AuditRepo(self._session),
            rate_repo=RateRepo(self._session),
        )

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is None:
            await self._session.commit()
        else:
            await self._session.rollback()


class _RealAdminScopeCM:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def __aenter__(self) -> AdminScope:
        return _fake_admin_scope(self._session)

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is None:
            await self._session.commit()
        else:
            await self._session.rollback()


class _RealTransactionRepoCM:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def __aenter__(self) -> TransactionRepo:
        return TransactionRepo(self._session)

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is None:
            await self._session.commit()
        else:
            await self._session.rollback()


# ---------------------------------------------------------------------------
# Client factories
# ---------------------------------------------------------------------------


def _make_replacement_client(
    caller: Caller,
    scope_cm: _RealReplacementScopeCM,
) -> TestClient:
    app = FastAPI()
    app.include_router(transactions_router)
    app.dependency_overrides[require_caller] = lambda: caller
    app.dependency_overrides[get_replacement_scope] = lambda: scope_cm
    return TestClient(app, raise_server_exceptions=False)


def _make_report_client(
    caller: Caller,
    report_cm: _RealReportScopeCM,
) -> TestClient:
    app = FastAPI()
    app.include_router(transactions_router)
    app.dependency_overrides[require_caller] = lambda: caller
    app.dependency_overrides[get_report_scope] = lambda: report_cm
    return TestClient(app, raise_server_exceptions=False)


def _make_nonce_client(
    admin_scope_cm: _RealAdminScopeCM,
    tx_repo_cm: _RealTransactionRepoCM | None = None,
) -> TestClient:
    app = FastAPI()
    app.include_router(nonce_router)
    app.dependency_overrides[require_admin] = lambda: None  # bypass auth
    app.dependency_overrides[get_admin_scope] = lambda: admin_scope_cm
    if tx_repo_cm is not None:
        app.dependency_overrides[get_transaction_repo] = lambda: tx_repo_cm
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------


async def _audit_rows(session: AsyncSession) -> list[dict[str, Any]]:
    result = await session.execute(select(audit_log).order_by(audit_log.c.seq.asc()))
    return [dict(row._mapping) for row in result]


async def _tx_row(session: AsyncSession, tx_id: str) -> dict[str, Any] | None:
    result = await session.execute(select(transactions).where(transactions.c.tx_id == tx_id))
    row = result.first()
    return dict(row._mapping) if row is not None else None


async def _attempt_rows(session: AsyncSession, tx_id: str) -> list[dict[str, Any]]:
    result = await session.execute(
        select(transaction_attempts)
        .where(transaction_attempts.c.tx_id == tx_id)
        .order_by(transaction_attempts.c.sequence_num)
    )
    return [dict(row._mapping) for row in result]


async def _nonce_row(
    session: AsyncSession, wallet: str = WALLET, chain: int = CHAIN
) -> dict[str, Any] | None:
    result = await session.execute(
        select(nonces).where(nonces.c.wallet == wallet, nonces.c.chain == chain)
    )
    row = result.first()
    return dict(row._mapping) if row is not None else None


# ===========================================================================
# A. Migration / schema presence
# ===========================================================================


@pytest.mark.asyncio
async def test_transaction_attempts_table_exists(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """create_all from transaction_metadata includes transaction_attempts."""
    db = tmp_path / "schema_test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(transaction_metadata.create_all)

        def _get_tables(conn_sync: Any) -> list[str]:
            insp = inspect(conn_sync)
            return insp.get_table_names()

        tables = await conn.run_sync(_get_tables)

    await engine.dispose()
    assert "transaction_attempts" in tables
    assert "transactions" in tables


@pytest.mark.asyncio
async def test_reserved_at_column_exists(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """transactions table has reserved_at column after create_all."""
    db = tmp_path / "schema_col_test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(transaction_metadata.create_all)

        def _get_columns(conn_sync: Any) -> list[str]:
            insp = inspect(conn_sync)
            return [c["name"] for c in insp.get_columns("transactions")]

        cols = await conn.run_sync(_get_columns)

    await engine.dispose()
    assert "reserved_at" in cols


# ===========================================================================
# B. sign_transaction attempt recording (unit layer, mocked repos)
# ===========================================================================


@pytest.mark.asyncio
async def test_sign_transaction_records_attempt_1_and_reserved_at() -> None:
    """Normal sign_transaction sets reserved_at + writes attempt seq=1 (mocked repos)."""
    from unittest.mock import patch

    from fwd.app.policy_engine import AllowDecision
    from fwd.app.sign_transaction import SignTransactionRequest, sign_transaction
    from fwd.domain.intent import DecodedIntent
    from fwd.domain.signer import SignedTransaction
    from fwd.infra.wallet_repo import Wallet

    tx_repo = MagicMock()
    tx_repo.get_by_idempotency_key = AsyncMock(return_value=None)
    tx_repo.create = AsyncMock(return_value=MagicMock())
    tx_repo.add_hash = AsyncMock(return_value=MagicMock())
    tx_repo.has_stale_reservation = AsyncMock(return_value=False)

    nonce_repo = MagicMock()
    nonce_repo.reserve_next = AsyncMock(return_value=7)
    nonce_repo.release_if_unused = AsyncMock(return_value=True)

    attempt_repo = MagicMock()
    attempt_repo.add_attempt = AsyncMock(return_value=MagicMock())

    audit_repo = MagicMock()
    audit_repo.append = AsyncMock(return_value=MagicMock())
    audit_repo.commit = AsyncMock(return_value=None)
    audit_repo.find_sign_transaction_seq = AsyncMock(return_value=None)

    rate_repo = MagicMock()
    rate_repo.add_committed_value = AsyncMock(return_value=None)

    wallet_obj = Wallet(
        name=WALLET,
        address="0x" + "aa" * 20,
        privkey_ciphertext="x",
        vault_master_key="vkey",
        policy_path="policies/w.yaml",
        created_at=datetime.now(UTC),
    )

    signer = MagicMock()
    signer.address = AsyncMock(return_value="0x" + "aa" * 20)
    signer.sign_transaction = AsyncMock(
        return_value=SignedTransaction(
            raw_transaction=bytes(range(32)),
            hash=bytes(range(32)),
            r=1,
            s=2,
            v=27,
        )
    )

    decoded = DecodedIntent(
        contract="0x" + "11" * 20,
        method_signature="transfer(address,uint256)",
        selector="0xa9059cbb",
        args={},
    )
    allow = AllowDecision(decoded=decoded, matched_policy_path="perm/test")

    request = SignTransactionRequest(
        wallet=WALLET,
        caller=CALLER_A,
        chain=CHAIN,
        to="0x" + "11" * 20,
        value_wei="0",
        data="0x",
        gas=21_000,
        max_fee_per_gas=1_000_000_000,
        max_priority_fee_per_gas=500_000_000,
    )
    caller = _make_caller(CALLER_A)

    with patch("fwd.app.sign_transaction.gate", new=AsyncMock(return_value=allow)):
        await sign_transaction(
            request,
            signer,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet_obj,
            policy=MagicMock(),
            registry=MagicMock(),
            rate_repo=rate_repo,
            audit_repo=audit_repo,
            attempt_repo=attempt_repo,
        )

    # Verify attempt_repo.add_attempt was called with seq=1.
    attempt_repo.add_attempt.assert_awaited_once()
    _, kwargs = attempt_repo.add_attempt.call_args
    assert kwargs["sequence_num"] == 1
    assert kwargs["gas"] == 21_000
    assert kwargs["max_fee_per_gas"] == 1_000_000_000
    assert kwargs["max_priority_fee_per_gas"] == 500_000_000

    # Verify tx_repo.create was called with reserved_at.
    tx_repo.create.assert_awaited_once()
    _, create_kwargs = tx_repo.create.call_args
    assert create_kwargs["reserved_at"] is not None


# ===========================================================================
# C. sign-replacement endpoint
# ===========================================================================


@pytest.mark.asyncio
async def test_sign_replacement_happy_path(db_session: AsyncSession) -> None:
    """submitted tx + valid bump → 200, tx stays `submitted`, new attempt recorded, same nonce."""
    tx_id = "018f0001-a13-0001-0000-000000000001"
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=5)
    await _seed_tx_hash(db_session, tx_id=tx_id, hash_hex=TX_HASH_1, sequence_num=1)
    prev_priority = 500_000_000
    await _seed_attempt(
        db_session,
        tx_id=tx_id,
        sequence_num=1,
        gas=21_000,
        max_fee_per_gas=1_000_000_000,
        max_priority_fee_per_gas=prev_priority,
    )

    new_raw = b"\x02\xaa\xbb"
    new_hash_bytes = bytes(range(32))
    from fwd.domain.signer import SignedTransaction

    mock_signer = MagicMock()
    mock_signer.sign_transaction = AsyncMock(
        return_value=SignedTransaction(
            raw_transaction=new_raw,
            hash=new_hash_bytes,
            r=1,
            s=2,
            v=27,
        )
    )

    caller = _make_caller(CALLER_A)
    scope_cm = _RealReplacementScopeCM(db_session, signer=mock_signer)
    client = _make_replacement_client(caller, scope_cm)

    min_priority = math.ceil(prev_priority * 1.125)
    r = client.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={
            "gas": 21_000,
            "max_fee_per_gas": 2_000_000_000,
            "max_priority_fee_per_gas": min_priority,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tx_id"] == tx_id
    assert body["nonce"] == 5
    assert body["attempt"] == 2

    # Check DB state.
    db_session.expire_all()
    tx_row = await _tx_row(db_session, tx_id)
    assert tx_row is not None
    assert tx_row["status"] == "submitted"

    attempts = await _attempt_rows(db_session, tx_id)
    assert len(attempts) == 2
    assert attempts[1]["sequence_num"] == 2
    assert attempts[1]["gas"] == 21_000
    assert attempts[1]["max_priority_fee_per_gas"] == min_priority

    # Audit row: approved tx-replacement.
    rows = await _audit_rows(db_session)
    assert any(row["action"] == "tx-replacement" and row["decision"] == "approved" for row in rows)
    approved_row = next(
        r for r in rows if r["action"] == "tx-replacement" and r["decision"] == "approved"
    )
    outcome = json.loads(approved_row["outcome"])  # type: ignore[arg-type]
    assert outcome["prev_seq"] == 1
    assert outcome["new_seq"] == 2
    assert outcome["nonce"] == 5


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_request_json",
    [
        "{not valid json",  # malformed → json.loads raises
        '{"wallet": "w", "chain": 14}',  # valid JSON but no "data" key
        '{"data": null}',  # data present but null
    ],
)
async def test_sign_replacement_corrupted_intent_fails_closed(
    db_session: AsyncSession, bad_request_json: str
) -> None:
    """A submitted tx whose stored request_json cannot yield calldata → 409 (refuse to
    replace with a DIFFERENT intent); the signer is never called (no empty-calldata tx)."""
    tx_id = "018f0001-a13-0009-0000-000000000009"
    await _seed_tx(
        db_session, tx_id=tx_id, status="submitted", nonce=7, request_json=bad_request_json
    )

    mock_signer = MagicMock()
    mock_signer.sign_transaction = AsyncMock()

    caller = _make_caller(CALLER_A)
    scope_cm = _RealReplacementScopeCM(db_session, signer=mock_signer)
    client = _make_replacement_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={
            "gas": 21_000,
            "max_fee_per_gas": 2_000_000_000,
            "max_priority_fee_per_gas": 600_000_000,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"] == "replacement_intent_unrecoverable"
    mock_signer.sign_transaction.assert_not_called()


@pytest.mark.asyncio
async def test_sign_replacement_same_nonce(db_session: AsyncSession) -> None:
    """Replacement MUST use the same nonce as the original tx."""
    tx_id = "018f0001-a13-same-nonce-000000000001"
    nonce = 99
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=nonce)
    await _seed_tx_hash(db_session, tx_id=tx_id)
    await _seed_attempt(db_session, tx_id=tx_id, max_priority_fee_per_gas=500_000_000)

    captured: dict[str, Any] = {}

    from fwd.domain.signer import SignedTransaction

    mock_signer = MagicMock()

    async def _sign(wallet: str, tx_dict: dict[str, Any]) -> SignedTransaction:
        captured["nonce"] = tx_dict["nonce"]
        captured["to"] = tx_dict["to"]
        return SignedTransaction(raw_transaction=b"\x02", hash=bytes(32), r=1, s=2, v=27)

    mock_signer.sign_transaction = _sign

    caller = _make_caller()
    scope_cm = _RealReplacementScopeCM(db_session, signer=mock_signer)
    client = _make_replacement_client(caller, scope_cm)

    min_priority = math.ceil(500_000_000 * 1.125)
    r = client.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={
            "gas": 21_000,
            "max_fee_per_gas": 2_000_000_000,
            "max_priority_fee_per_gas": min_priority,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200
    # The tx_dict passed to signer must have the SAME nonce.
    assert captured["nonce"] == nonce
    # to must be checksummed.
    from eth_utils import to_checksum_address

    assert captured["to"] == to_checksum_address("0x" + "11" * 20)


@pytest.mark.asyncio
async def test_sign_replacement_bump_too_low_returns_400(db_session: AsyncSession) -> None:
    """Priority fee below ceil(prev * 1.125) → 400 + denied audit row."""
    tx_id = "018f0001-a13-bump-low-00000000001"
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=5)
    await _seed_tx_hash(db_session, tx_id=tx_id)
    prev_priority = 1_000_000_000
    await _seed_attempt(db_session, tx_id=tx_id, max_priority_fee_per_gas=prev_priority)

    caller = _make_caller()
    scope_cm = _RealReplacementScopeCM(db_session)
    client = _make_replacement_client(caller, scope_cm)

    too_low = prev_priority  # same as prev, not bumped
    r = client.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={"gas": 21_000, "max_fee_per_gas": 2_000_000_000, "max_priority_fee_per_gas": too_low},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "replacement_bump_too_low"

    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0]["action"] == "tx-replacement"
    assert rows[0]["decision"] == "denied"
    assert rows[0]["decision_reason"] == "replacement_bump_too_low"


@pytest.mark.asyncio
async def test_sign_replacement_cap_exhausted_at_5(db_session: AsyncSession) -> None:
    """After 5 attempts, sign-replacement returns 409 replacement_cap_exhausted."""
    tx_id = "018f0001-a13-cap-exhausted-00000000001"
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=5)
    await _seed_tx_hash(db_session, tx_id=tx_id)

    # Seed 5 attempts with fees well under the default 500 gwei cap.
    base_priority = 100_000_000  # 0.1 gwei — stays small even after 5x 1.125 bumps
    for i in range(1, 6):
        await _seed_attempt(
            db_session,
            tx_id=tx_id,
            sequence_num=i,
            max_priority_fee_per_gas=base_priority,
            max_fee_per_gas=200_000_000,
            signed_raw=f"0xsigned{i}",
            hash="0x" + format(i, "064x"),
        )
        base_priority = math.ceil(base_priority * 1.125)

    caller = _make_caller()
    scope_cm = _RealReplacementScopeCM(db_session)
    client = _make_replacement_client(caller, scope_cm)

    # Use valid bump fees (above prev, under global cap).
    r = client.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={
            "gas": 21_000,
            "max_fee_per_gas": 300_000_000,
            "max_priority_fee_per_gas": base_priority,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "replacement_cap_exhausted"

    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert any(
        row["action"] == "tx-replacement"
        and row["decision"] == "denied"
        and row["decision_reason"] == "replacement_cap_exhausted"
        for row in rows
    )


@pytest.mark.asyncio
async def test_sign_replacement_wrong_state_pending_returns_409(
    db_session: AsyncSession,
) -> None:
    """pending tx (never broadcast) → 409 illegal_transition."""
    tx_id = "018f0001-a13-wrong-state-0000000001"
    await _seed_tx(db_session, tx_id=tx_id, status="pending", nonce=5)
    await _seed_tx_hash(db_session, tx_id=tx_id)

    caller = _make_caller()
    scope_cm = _RealReplacementScopeCM(db_session)
    client = _make_replacement_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={
            "gas": 21_000,
            "max_fee_per_gas": 2_000_000_000,
            "max_priority_fee_per_gas": 1_000_000_000,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "illegal_transition"

    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert any(row["action"] == "tx-replacement" and row["decision"] == "denied" for row in rows)


@pytest.mark.asyncio
async def test_sign_replacement_cross_caller_returns_404(db_session: AsyncSession) -> None:
    """Caller B on caller A's tx → 404 (no audit row)."""
    tx_id = "018f0001-a13-cross-caller-0000000001"
    await _seed_tx(db_session, tx_id=tx_id, caller=CALLER_A, status="submitted", nonce=5)
    await _seed_tx_hash(db_session, tx_id=tx_id)

    caller_b = _make_caller(CALLER_B)
    scope_cm = _RealReplacementScopeCM(db_session)
    client = _make_replacement_client(caller_b, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={
            "gas": 21_000,
            "max_fee_per_gas": 2_000_000_000,
            "max_priority_fee_per_gas": 1_000_000_000,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "transaction_not_found"


@pytest.mark.asyncio
async def test_sign_replacement_sign_failure_does_not_release_nonce(
    db_session: AsyncSession,
) -> None:
    """Sign failure path: 503 + error audit row; original attempt reservation intact."""
    tx_id = "018f0001-a13-sign-fail-000000000001"
    nonce = 7
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=nonce)
    await _seed_tx_hash(db_session, tx_id=tx_id)
    await _seed_attempt(db_session, tx_id=tx_id, max_priority_fee_per_gas=500_000_000)
    await _seed_nonce(db_session, next_nonce=nonce + 1)

    mock_signer = MagicMock()
    mock_signer.sign_transaction = AsyncMock(side_effect=ValueError("signing failed"))

    caller = _make_caller()
    scope_cm = _RealReplacementScopeCM(db_session, signer=mock_signer)
    client = _make_replacement_client(caller, scope_cm)

    min_priority = math.ceil(500_000_000 * 1.125)
    r = client.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={
            "gas": 21_000,
            "max_fee_per_gas": 2_000_000_000,
            "max_priority_fee_per_gas": min_priority,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 503

    db_session.expire_all()

    # Nonce NOT released.
    nonce_row = await _nonce_row(db_session)
    assert nonce_row is not None
    assert nonce_row["next_nonce"] == nonce + 1

    # Error audit row committed.
    rows = await _audit_rows(db_session)
    assert any(row["action"] == "tx-replacement" and row["decision"] == "error" for row in rows)


@pytest.mark.asyncio
async def test_receipt_after_replacement(db_session: AsyncSession) -> None:
    """After sign-replacement, the replacement hash is accepted by /receipt and
    the nonce is confirmed (gap-closer for the replacement lifecycle bug)."""
    from fwd.domain.signer import SignedTransaction

    tx_id = "018f0001-a19-receipt-after-repl-0001"
    nonce = 5
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=nonce)
    await _seed_tx_hash(db_session, tx_id=tx_id, hash_hex=TX_HASH_1, sequence_num=1)
    prev_priority = 500_000_000
    await _seed_attempt(
        db_session,
        tx_id=tx_id,
        sequence_num=1,
        gas=21_000,
        max_fee_per_gas=1_000_000_000,
        max_priority_fee_per_gas=prev_priority,
    )
    # Seed the nonce row so mark_confirmed has a row to update.
    await _seed_nonce(db_session, next_nonce=nonce + 1, last_confirmed=None)

    # The replacement signer returns a known hash.
    replacement_hash_bytes = bytes(range(32))
    replacement_hash_hex = "0x" + replacement_hash_bytes.hex()
    new_raw = b"\x02\xcc\xdd"
    mock_signer = MagicMock()
    mock_signer.sign_transaction = AsyncMock(
        return_value=SignedTransaction(
            raw_transaction=new_raw,
            hash=replacement_hash_bytes,
            r=1,
            s=2,
            v=27,
        )
    )

    caller = _make_caller(CALLER_A)
    scope_cm = _RealReplacementScopeCM(db_session, signer=mock_signer)
    replacement_client = _make_replacement_client(caller, scope_cm)

    min_priority = math.ceil(prev_priority * 1.125)
    r = replacement_client.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={
            "gas": 21_000,
            "max_fee_per_gas": 2_000_000_000,
            "max_priority_fee_per_gas": min_priority,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200, r.text

    # TX must still be submitted after replacement.
    db_session.expire_all()
    tx_row = await _tx_row(db_session, tx_id)
    assert tx_row is not None
    assert tx_row["status"] == "submitted"

    # Now report the receipt using the replacement's hash.
    report_cm = _RealReportScopeCM(db_session)
    report_client = _make_report_client(caller, report_cm)

    r2 = report_client.post(
        f"/v1/transactions/{tx_id}/receipt",
        json={
            "tx_hash": replacement_hash_hex,
            "outcome": "mined_success",
            "block_number": 12345,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r2.status_code == 200, r2.text

    db_session.expire_all()
    tx_row2 = await _tx_row(db_session, tx_id)
    assert tx_row2 is not None
    assert tx_row2["status"] == "mined"

    # mark_confirmed ran: last_confirmed == nonce.
    nonce_row = await _nonce_row(db_session)
    assert nonce_row is not None
    assert nonce_row["last_confirmed"] == nonce


@pytest.mark.asyncio
async def test_multi_replacement_reaches_cap(db_session: AsyncSession) -> None:
    """Four consecutive replacements all return 200 and leave the tx submitted;
    a 5th (6th attempt total) returns 409 replacement_cap_exhausted.

    Prior to the fix the 2nd call would 409 illegal_transition because
    the 1st moved the tx to 'replaced'.
    """
    from fwd.domain.signer import SignedTransaction

    tx_id = "018f0001-a19-multi-repl-cap-00001"
    nonce = 5
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=nonce)
    await _seed_tx_hash(db_session, tx_id=tx_id, hash_hex=TX_HASH_1, sequence_num=1)
    init_priority = 100_000_000
    init_fee = 200_000_000
    await _seed_attempt(
        db_session,
        tx_id=tx_id,
        sequence_num=1,
        gas=21_000,
        max_fee_per_gas=init_fee,
        max_priority_fee_per_gas=init_priority,
    )

    caller = _make_caller(CALLER_A)

    prev_priority = init_priority
    prev_fee = init_fee

    for i in range(4):
        new_priority = math.ceil(prev_priority * 1.125)
        new_fee = prev_fee + 50_000_000  # comfortably rising, stays well under caps

        mock_signer = MagicMock()
        mock_signer.sign_transaction = AsyncMock(
            return_value=SignedTransaction(
                raw_transaction=b"\x02" + bytes([i]),
                hash=bytes([i]) * 32,
                r=1,
                s=2,
                v=27,
            )
        )
        scope_cm = _RealReplacementScopeCM(db_session, signer=mock_signer)
        client = _make_replacement_client(caller, scope_cm)

        r = client.post(
            f"/v1/transactions/{tx_id}/sign-replacement",
            json={
                "gas": 21_000,
                "max_fee_per_gas": new_fee,
                "max_priority_fee_per_gas": new_priority,
            },
            headers={"Authorization": "Bearer fwd_live_x"},
        )
        assert r.status_code == 200, f"call {i + 1}: {r.text}"

        db_session.expire_all()
        tx_row = await _tx_row(db_session, tx_id)
        assert tx_row is not None
        assert (
            tx_row["status"] == "submitted"
        ), f"call {i + 1}: expected submitted, got {tx_row['status']}"

        prev_priority = new_priority
        prev_fee = new_fee

    # After 4 replacements there are 5 attempts total (seq 1..5).
    attempts = await _attempt_rows(db_session, tx_id)
    assert len(attempts) == 5

    # A 5th replacement call (6th attempt) must be rejected.
    fifth_priority = math.ceil(prev_priority * 1.125)
    fifth_fee = prev_fee + 50_000_000

    scope_cm_final = _RealReplacementScopeCM(db_session)
    client_final = _make_replacement_client(caller, scope_cm_final)
    r_cap = client_final.post(
        f"/v1/transactions/{tx_id}/sign-replacement",
        json={
            "gas": 21_000,
            "max_fee_per_gas": fifth_fee,
            "max_priority_fee_per_gas": fifth_priority,
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r_cap.status_code == 409, r_cap.text
    assert r_cap.json()["detail"]["error"] == "replacement_cap_exhausted"


# ===========================================================================
# D. nonce-sync endpoint
# ===========================================================================


@pytest.mark.asyncio
async def test_nonce_sync_in_sync_no_op(db_session: AsyncSession) -> None:
    """on_chain_count == next_nonce → 200 in_sync, no change."""
    await _seed_nonce(db_session, next_nonce=10)

    admin_scope_cm = _RealAdminScopeCM(db_session)
    client = _make_nonce_client(admin_scope_cm)

    r = client.post(
        "/v1/admin/nonce-sync",
        json={"wallet": WALLET, "chain": CHAIN, "on_chain_count": 10},
        headers={"Authorization": "Bearer x"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "in_sync"
    assert body["from_nonce"] == 10
    assert body["to_nonce"] == 10

    db_session.expire_all()
    nonce_row = await _nonce_row(db_session)
    assert nonce_row is not None
    assert nonce_row["next_nonce"] == 10  # unchanged


@pytest.mark.asyncio
async def test_nonce_sync_bounded_advance_heals_gap(db_session: AsyncSession) -> None:
    """on_chain_count = cur + 3 (within bound) → 200 advanced, next_nonce updated."""
    await _seed_nonce(db_session, next_nonce=5)

    admin_scope_cm = _RealAdminScopeCM(db_session)
    client = _make_nonce_client(admin_scope_cm)

    r = client.post(
        "/v1/admin/nonce-sync",
        json={"wallet": WALLET, "chain": CHAIN, "on_chain_count": 8},
        headers={"Authorization": "Bearer x"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "advanced"
    assert body["from_nonce"] == 5
    assert body["to_nonce"] == 8

    db_session.expire_all()
    nonce_row = await _nonce_row(db_session)
    assert nonce_row is not None
    assert nonce_row["next_nonce"] == 8
    assert nonce_row["last_confirmed"] == 7  # value - 1


@pytest.mark.asyncio
async def test_nonce_sync_rewind_returns_409(db_session: AsyncSession) -> None:
    """on_chain_count < cur → 409 nonce_sync_out_of_bounds."""
    await _seed_nonce(db_session, next_nonce=10)

    admin_scope_cm = _RealAdminScopeCM(db_session)
    client = _make_nonce_client(admin_scope_cm)

    r = client.post(
        "/v1/admin/nonce-sync",
        json={"wallet": WALLET, "chain": CHAIN, "on_chain_count": 5},
        headers={"Authorization": "Bearer x"},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "nonce_sync_out_of_bounds"

    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert any(row["action"] == "nonce-sync" and row["decision"] == "denied" for row in rows)


@pytest.mark.asyncio
async def test_nonce_sync_out_of_bounds_jump_returns_409(db_session: AsyncSession) -> None:
    """on_chain_count > cur + max_advance (64) → 409."""
    await _seed_nonce(db_session, next_nonce=10)

    admin_scope_cm = _RealAdminScopeCM(db_session)
    client = _make_nonce_client(admin_scope_cm)

    r = client.post(
        "/v1/admin/nonce-sync",
        json={"wallet": WALLET, "chain": CHAIN, "on_chain_count": 10 + 65},
        headers={"Authorization": "Bearer x"},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "nonce_sync_out_of_bounds"


@pytest.mark.asyncio
async def test_nonce_sync_missing_row_returns_404(db_session: AsyncSession) -> None:
    """No nonces row → 404 nonce_not_initialized."""
    admin_scope_cm = _RealAdminScopeCM(db_session)
    client = _make_nonce_client(admin_scope_cm)

    r = client.post(
        "/v1/admin/nonce-sync",
        json={"wallet": "nonexistent", "chain": CHAIN, "on_chain_count": 5},
        headers={"Authorization": "Bearer x"},
    )
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "nonce_not_initialized"

    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert any(row["action"] == "nonce-sync" and row["decision"] == "denied" for row in rows)


@pytest.mark.asyncio
async def test_nonce_sync_requires_admin_auth(db_session: AsyncSession) -> None:
    """Without overriding admin auth, no admin key configured → 503."""
    from fwd import settings as settings_mod

    settings_mod.get_settings.cache_clear()

    app = FastAPI()
    app.include_router(nonce_router)
    admin_scope_cm = _RealAdminScopeCM(db_session)
    app.dependency_overrides[get_admin_scope] = lambda: admin_scope_cm

    import os

    old_key = os.environ.get("FWD_ADMIN_KEY")
    os.environ["FWD_ADMIN_KEY"] = ""
    settings_mod.get_settings.cache_clear()
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.post(
                "/v1/admin/nonce-sync",
                json={"wallet": WALLET, "chain": CHAIN, "on_chain_count": 5},
            )
        # No admin key configured → 503
        assert r.status_code == 503
    finally:
        if old_key is None:
            os.environ.pop("FWD_ADMIN_KEY", None)
        else:
            os.environ["FWD_ADMIN_KEY"] = old_key
        settings_mod.get_settings.cache_clear()


# ===========================================================================
# E. nonce/holes endpoint
# ===========================================================================


@pytest.mark.asyncio
async def test_nonce_holes_stale_pending_surfaces(db_session: AsyncSession) -> None:
    """A pending tx with reserved_at older than lease_sec is returned."""
    from fwd import settings as settings_mod

    settings_mod.get_settings.cache_clear()

    tx_id = "018f0001-a13-holes-stale-00000000001"
    stale_time = datetime.now(UTC) - timedelta(seconds=901)  # > 900s default
    await _seed_tx(db_session, tx_id=tx_id, status="pending", nonce=3, reserved_at=stale_time)

    tx_repo_cm = _RealTransactionRepoCM(db_session)

    app = FastAPI()
    app.include_router(nonce_router)
    app.dependency_overrides[require_admin] = lambda: None
    app.dependency_overrides[get_transaction_repo] = lambda: tx_repo_cm

    with TestClient(app, raise_server_exceptions=False) as client:
        r = client.get(
            "/v1/admin/nonce/holes",
            headers={"Authorization": "Bearer x"},
        )
    assert r.status_code == 200
    holes = r.json()
    assert len(holes) == 1
    assert holes[0]["tx_id"] == tx_id
    assert holes[0]["nonce"] == 3
    assert holes[0]["wallet"] == WALLET
    assert holes[0]["caller"] == CALLER_A


@pytest.mark.asyncio
async def test_nonce_holes_fresh_pending_not_surfaced(db_session: AsyncSession) -> None:
    """A pending tx with recent reserved_at is NOT returned (within lease window)."""
    from fwd import settings as settings_mod

    settings_mod.get_settings.cache_clear()

    tx_id = "018f0001-a13-holes-fresh-00000000001"
    fresh_time = datetime.now(UTC) - timedelta(seconds=60)  # well within 900s
    await _seed_tx(db_session, tx_id=tx_id, status="pending", nonce=4, reserved_at=fresh_time)

    tx_repo_cm = _RealTransactionRepoCM(db_session)

    app = FastAPI()
    app.include_router(nonce_router)
    app.dependency_overrides[require_admin] = lambda: None
    app.dependency_overrides[get_transaction_repo] = lambda: tx_repo_cm

    with TestClient(app, raise_server_exceptions=False) as client:
        r = client.get(
            "/v1/admin/nonce/holes",
            headers={"Authorization": "Bearer x"},
        )
    assert r.status_code == 200
    holes = r.json()
    assert len(holes) == 0


@pytest.mark.asyncio
async def test_nonce_holes_submitted_tx_not_surfaced(db_session: AsyncSession) -> None:
    """A submitted tx (broadcast) with stale reserved_at is NOT in holes (wrong status)."""
    from fwd import settings as settings_mod

    settings_mod.get_settings.cache_clear()

    tx_id = "018f0001-a13-holes-submitted-0000001"
    stale_time = datetime.now(UTC) - timedelta(seconds=901)
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=5, reserved_at=stale_time)

    tx_repo_cm = _RealTransactionRepoCM(db_session)

    app = FastAPI()
    app.include_router(nonce_router)
    app.dependency_overrides[require_admin] = lambda: None
    app.dependency_overrides[get_transaction_repo] = lambda: tx_repo_cm

    with TestClient(app, raise_server_exceptions=False) as client:
        r = client.get(
            "/v1/admin/nonce/holes",
            headers={"Authorization": "Bearer x"},
        )
    assert r.status_code == 200
    holes = r.json()
    assert len(holes) == 0
