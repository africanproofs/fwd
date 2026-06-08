"""Tests for POST /v1/transactions/{tx_id}/broadcast-result and .../receipt.

Uses a real tmp-sqlite so state + audit rows can be read back after each
request. The ReportScope is backed by the real session (no Vault needed —
these paths never sign).

asyncio_mode = "auto" (set in pyproject.toml).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.api.caller_auth import require_caller
from fwd.api.transactions import router
from fwd.app.dependencies import ReportScope, get_report_scope
from fwd.infra.audit_repo import AuditRepo, audit_log, audit_metadata
from fwd.infra.caller_repo import Caller
from fwd.infra.nonce_repo import NonceRepo, nonces
from fwd.infra.nonce_repo import metadata as nonce_metadata
from fwd.infra.rate_repo import RateRepo, rate_metadata
from fwd.infra.transaction_repo import TransactionRepo, transaction_hashes, transactions
from fwd.infra.transaction_repo import metadata as transaction_metadata

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WALLET = "test-wallet"
CHAIN = 114
CALLER_A = "caller-a"
CALLER_B = "caller-b"
TX_HASH = "0x" + "ab" * 32  # valid 66-char hash
BAD_HASH = "0x" + "cd" * 32


# ---------------------------------------------------------------------------
# Caller factory
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


# ---------------------------------------------------------------------------
# DB fixture — creates all needed tables in a tmp SQLite
# ---------------------------------------------------------------------------


@pytest.fixture()
async def db_session(tmp_path):  # type: ignore[no-untyped-def]
    """Yield an AsyncSession with transaction + nonce + audit tables."""
    db = tmp_path / "test_report.db"
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
    nonce: int = 0,
) -> None:
    """Insert a transactions row directly."""
    now = datetime.now(UTC)
    await session.execute(
        transactions.insert().values(
            tx_id=tx_id,
            wallet=WALLET,
            chain=CHAIN,
            caller=caller,
            nonce=nonce,
            contract_address="0x" + "11" * 20,
            method_name="transfer(address,uint256)",
            value_wei="0",
            idempotency_key=None,
            request_json="{}",
            signed_raw="0xdeadbeef",
            status=status,
            submitted_at=None,
            confirmed_at=None,
            receipt_json=None,
            created_at=now,
        )
    )
    await session.commit()


async def _seed_hash(
    session: AsyncSession,
    *,
    tx_id: str,
    hash_hex: str = TX_HASH,
    sequence_num: int = 1,
) -> None:
    """Insert a transaction_hashes row directly."""
    await session.execute(
        transaction_hashes.insert().values(
            tx_id=tx_id,
            sequence_num=sequence_num,
            hash_hex=hash_hex,
            submitted_at=datetime.now(UTC),
        )
    )
    await session.commit()


async def _seed_nonce(
    session: AsyncSession,
    *,
    wallet: str = WALLET,
    chain: int = CHAIN,
    next_nonce: int = 1,
    last_confirmed: int | None = None,
) -> None:
    """Insert a nonces row directly."""
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
# Real ReportScope context manager backed by the fixture session
# ---------------------------------------------------------------------------


class _RealReportScopeCM:
    """Async CM that yields a ReportScope backed by the fixture session.

    Commits on clean exit (mirrors ReportScopeCM behaviour). Does not open
    a second session — uses the already-open fixture session so the test
    can read state back from the same session after the handler returns.
    """

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


# ---------------------------------------------------------------------------
# TestClient factory
# ---------------------------------------------------------------------------


def _make_client(
    caller: Caller,
    scope_cm: _RealReportScopeCM,
) -> TestClient:
    """TestClient with require_caller + get_report_scope both overridden."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_caller] = lambda: caller
    app.dependency_overrides[get_report_scope] = lambda: scope_cm
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Audit log reader
# ---------------------------------------------------------------------------


async def _audit_rows(session: AsyncSession) -> list[dict[str, object]]:
    result = await session.execute(select(audit_log).order_by(audit_log.c.seq.asc()))
    return [dict(row._mapping) for row in result]


async def _tx_row(session: AsyncSession, tx_id: str) -> dict[str, object] | None:
    result = await session.execute(select(transactions).where(transactions.c.tx_id == tx_id))
    row = result.first()
    return dict(row._mapping) if row is not None else None


async def _nonce_row(
    session: AsyncSession, wallet: str = WALLET, chain: int = CHAIN
) -> dict[str, object] | None:
    result = await session.execute(
        select(nonces).where(nonces.c.wallet == wallet, nonces.c.chain == chain)
    )
    row = result.first()
    return dict(row._mapping) if row is not None else None


# ===========================================================================
# broadcast-result tests
# ===========================================================================


@pytest.mark.asyncio
async def test_broadcast_result_accepted_pending_to_submitted(
    db_session: AsyncSession,
) -> None:
    """accepted: pending→submitted, submitted_at set, audit row approved."""
    tx_id = "018f0001-0000-7000-8000-000000000001"
    await _seed_tx(db_session, tx_id=tx_id, status="pending")
    await _seed_hash(db_session, tx_id=tx_id)

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/broadcast-result",
        json={"tx_hash": TX_HASH, "outcome": "accepted"},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["tx_id"] == tx_id
    assert body["status"] == "submitted"

    # Verify DB state
    db_session.expire_all()
    row = await _tx_row(db_session, tx_id)
    assert row is not None
    assert row["status"] == "submitted"
    assert row["submitted_at"] is not None

    # Verify audit row
    rows = await _audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0]["action"] == "tx-broadcast-result"
    assert rows[0]["decision"] == "approved"
    assert rows[0]["decision_reason"] == "broadcast_accepted"


@pytest.mark.asyncio
async def test_broadcast_result_rejected_releaseable_tail_nonce(
    db_session: AsyncSession,
) -> None:
    """rejected_releaseable on tail nonce: status→failed, next_nonce decremented."""
    tx_id = "018f0001-0000-7000-8000-000000000002"
    nonce = 5
    await _seed_tx(db_session, tx_id=tx_id, status="pending", nonce=nonce)
    await _seed_hash(db_session, tx_id=tx_id)
    await _seed_nonce(db_session, next_nonce=nonce + 1)  # tail: next_nonce - 1 == nonce

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/broadcast-result",
        json={"tx_hash": TX_HASH, "outcome": "rejected_releaseable", "error_class": "RpcError"},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "failed"

    db_session.expire_all()
    tx_row = await _tx_row(db_session, tx_id)
    assert tx_row is not None
    assert tx_row["status"] == "failed"

    nonce_row = await _nonce_row(db_session)
    assert nonce_row is not None
    assert nonce_row["next_nonce"] == nonce  # decremented from nonce+1 → nonce

    rows = await _audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0]["decision_reason"] == "broadcast_rejected_releaseable"
    outcome = json.loads(rows[0]["outcome"])  # type: ignore[arg-type]
    assert outcome["released"] is True


@pytest.mark.asyncio
async def test_broadcast_result_rejected_nonce_too_low_no_release(
    db_session: AsyncSession,
) -> None:
    """rejected_nonce_too_low: status→failed, nonce NOT released."""
    tx_id = "018f0001-0000-7000-8000-000000000003"
    nonce = 3
    await _seed_tx(db_session, tx_id=tx_id, status="pending", nonce=nonce)
    await _seed_hash(db_session, tx_id=tx_id)
    await _seed_nonce(db_session, next_nonce=nonce + 1)

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/broadcast-result",
        json={
            "tx_hash": TX_HASH,
            "outcome": "rejected_nonce_too_low",
            "error_class": "NonceTooLow",
        },
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "failed"

    db_session.expire_all()
    nonce_row = await _nonce_row(db_session)
    assert nonce_row is not None
    assert nonce_row["next_nonce"] == nonce + 1  # NOT decremented

    rows = await _audit_rows(db_session)
    assert rows[0]["decision_reason"] == "broadcast_rejected_nonce_too_low"
    outcome = json.loads(rows[0]["outcome"])  # type: ignore[arg-type]
    assert "chain ahead of fwd" in outcome["hint"]


# ===========================================================================
# receipt tests
# ===========================================================================


@pytest.mark.asyncio
async def test_receipt_mined_success_submitted_to_mined(
    db_session: AsyncSession,
) -> None:
    """mined_success: submitted→mined, last_confirmed advanced."""
    tx_id = "018f0001-0000-7000-8000-000000000004"
    nonce = 7
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=nonce)
    await _seed_hash(db_session, tx_id=tx_id)
    await _seed_nonce(db_session, next_nonce=nonce + 1, last_confirmed=None)

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/receipt",
        json={"tx_hash": TX_HASH, "outcome": "mined_success", "block_number": 12345},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "mined"

    db_session.expire_all()
    tx_row = await _tx_row(db_session, tx_id)
    assert tx_row is not None
    assert tx_row["status"] == "mined"
    assert tx_row["confirmed_at"] is not None
    receipt = json.loads(tx_row["receipt_json"])  # type: ignore[arg-type]
    assert receipt["status"] == 1
    assert receipt["block_number"] == 12345

    nonce_row = await _nonce_row(db_session)
    assert nonce_row is not None
    assert nonce_row["last_confirmed"] == nonce

    rows = await _audit_rows(db_session)
    assert rows[0]["action"] == "tx-receipt"
    assert rows[0]["decision_reason"] == "receipt_mined_success"


@pytest.mark.asyncio
async def test_receipt_mined_reverted_submitted_to_reverted(
    db_session: AsyncSession,
) -> None:
    """mined_reverted: submitted→reverted, last_confirmed still advanced (nonce consumed)."""
    tx_id = "018f0001-0000-7000-8000-000000000005"
    nonce = 9
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=nonce)
    await _seed_hash(db_session, tx_id=tx_id)
    await _seed_nonce(db_session, next_nonce=nonce + 1, last_confirmed=None)

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/receipt",
        json={"tx_hash": TX_HASH, "outcome": "mined_reverted", "block_number": 99999},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "reverted"

    db_session.expire_all()
    tx_row = await _tx_row(db_session, tx_id)
    assert tx_row is not None
    assert tx_row["status"] == "reverted"
    receipt = json.loads(tx_row["receipt_json"])  # type: ignore[arg-type]
    assert receipt["status"] == 0

    nonce_row = await _nonce_row(db_session)
    assert nonce_row is not None
    assert nonce_row["last_confirmed"] == nonce  # advanced even for revert

    rows = await _audit_rows(db_session)
    assert rows[0]["decision_reason"] == "receipt_mined_reverted"


# ===========================================================================
# Trust-boundary tests
# ===========================================================================


@pytest.mark.asyncio
async def test_caller_ownership_other_caller_gets_404(db_session: AsyncSession) -> None:
    """Caller B reporting on caller A's tx → 404 (no audit row)."""
    tx_id = "018f0001-0000-7000-8000-000000000006"
    await _seed_tx(db_session, tx_id=tx_id, caller=CALLER_A, status="pending")
    await _seed_hash(db_session, tx_id=tx_id)

    caller_b = _make_caller(CALLER_B)
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller_b, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/broadcast-result",
        json={"tx_hash": TX_HASH, "outcome": "accepted"},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "transaction_not_found"

    # No audit row — 404 is a non-event
    rows = await _audit_rows(db_session)
    assert len(rows) == 0


@pytest.mark.asyncio
async def test_tx_hash_mismatch_returns_409_with_denied_audit_row(
    db_session: AsyncSession,
) -> None:
    """tx_hash not in fwd's known hashes → 409 tx_hash_mismatch + denied audit row."""
    tx_id = "018f0001-0000-7000-8000-000000000007"
    await _seed_tx(db_session, tx_id=tx_id, status="pending")
    await _seed_hash(db_session, tx_id=tx_id, hash_hex=TX_HASH)

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/broadcast-result",
        json={"tx_hash": BAD_HASH, "outcome": "accepted"},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "tx_hash_mismatch"

    # Forensic audit row must survive (Core #5/#19)
    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0]["action"] == "tx-broadcast-result"
    assert rows[0]["decision"] == "denied"
    assert rows[0]["decision_reason"] == "tx_hash_mismatch"


@pytest.mark.asyncio
async def test_illegal_transition_broadcast_result_on_submitted_tx(
    db_session: AsyncSession,
) -> None:
    """broadcast-result on already-submitted tx → 409 illegal_transition + denied audit row."""
    tx_id = "018f0001-0000-7000-8000-000000000008"
    await _seed_tx(db_session, tx_id=tx_id, status="submitted")
    await _seed_hash(db_session, tx_id=tx_id)

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/broadcast-result",
        json={"tx_hash": TX_HASH, "outcome": "accepted"},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "illegal_transition"

    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0]["decision"] == "denied"
    assert "illegal_transition:submitted->accepted" in str(rows[0]["decision_reason"])


@pytest.mark.asyncio
async def test_illegal_transition_receipt_on_pending_tx(db_session: AsyncSession) -> None:
    """receipt on pending tx (not submitted) → 409 illegal_transition."""
    tx_id = "018f0001-0000-7000-8000-000000000009"
    await _seed_tx(db_session, tx_id=tx_id, status="pending")
    await _seed_hash(db_session, tx_id=tx_id)

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/receipt",
        json={"tx_hash": TX_HASH, "outcome": "mined_success", "block_number": 1},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "illegal_transition"

    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0]["decision"] == "denied"
    assert "illegal_transition:pending->mined_success" in str(rows[0]["decision_reason"])


# ===========================================================================
# Approved-path audit row existence tests
# ===========================================================================


@pytest.mark.asyncio
async def test_approved_broadcast_result_writes_tx_broadcast_result_audit_row(
    db_session: AsyncSession,
) -> None:
    """Approved broadcast-result writes a 'tx-broadcast-result' audit row."""
    tx_id = "018f0001-0000-7000-8000-00000000000a"
    await _seed_tx(db_session, tx_id=tx_id, status="pending")
    await _seed_hash(db_session, tx_id=tx_id)

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/broadcast-result",
        json={"tx_hash": TX_HASH, "outcome": "accepted"},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200

    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0]["action"] == "tx-broadcast-result"
    assert rows[0]["decision"] == "approved"
    assert rows[0]["caller"] == CALLER_A


@pytest.mark.asyncio
async def test_approved_receipt_writes_tx_receipt_audit_row(
    db_session: AsyncSession,
) -> None:
    """Approved receipt writes a 'tx-receipt' audit row."""
    tx_id = "018f0001-0000-7000-8000-00000000000b"
    nonce = 2
    await _seed_tx(db_session, tx_id=tx_id, status="submitted", nonce=nonce)
    await _seed_hash(db_session, tx_id=tx_id)
    await _seed_nonce(db_session, next_nonce=nonce + 1)

    caller = _make_caller()
    scope_cm = _RealReportScopeCM(db_session)
    client = _make_client(caller, scope_cm)

    r = client.post(
        f"/v1/transactions/{tx_id}/receipt",
        json={"tx_hash": TX_HASH, "outcome": "mined_success", "block_number": 500},
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200

    db_session.expire_all()
    rows = await _audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0]["action"] == "tx-receipt"
    assert rows[0]["decision"] == "approved"
    assert rows[0]["caller"] == CALLER_A
