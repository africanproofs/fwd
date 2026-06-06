"""POST /v1/admin/nonce-init endpoint tests.

Mirrors the harness in test_callers_endpoint.py:
- FastAPI TestClient with dependency_overrides[get_admin_scope].
- Real tmp-sqlite for the wallets + nonces + audit_log tables (audit row
  assertions use a DB-backed AdminScope so the rows can be read back).
- Mock-based AdminScope for pure auth / status-code tests (no DB needed).

asyncio_mode = "auto" (set in pyproject.toml).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd import settings as settings_mod
from fwd.api.nonce import router
from fwd.app.dependencies import AdminScope, get_admin_scope
from fwd.infra.audit_repo import AuditRepo, audit_log, audit_metadata
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.nonce_repo import metadata as nonces_metadata
from fwd.infra.transaction_repo import TransactionRepo
from fwd.infra.transaction_repo import metadata as tx_metadata
from fwd.infra.wallet_repo import metadata as wallets_metadata
from fwd.infra.wallet_repo import wallets

if TYPE_CHECKING:
    import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_admin_scope(
    nonce_repo: MagicMock | None = None,
    audit_repo: MagicMock | None = None,
    tx_repo: MagicMock | None = None,
) -> AdminScope:
    """Build a mock AdminScope (no Vault, no DB)."""
    signer = MagicMock()
    caller_repo = MagicMock()
    _audit_repo = audit_repo or MagicMock()
    if audit_repo is None:
        _audit_repo.append = AsyncMock(return_value=None)
        _audit_repo.commit = AsyncMock(return_value=None)
    _nonce_repo = nonce_repo or MagicMock()
    _tx_repo = tx_repo or MagicMock()
    return AdminScope(
        signer=signer,
        caller_repo=caller_repo,
        audit_repo=_audit_repo,
        nonce_repo=_nonce_repo,
        tx_repo=_tx_repo,
    )


class _FakeAdminScopeCM:
    """Async CM that yields a configurable fake AdminScope (no Vault/DB)."""

    def __init__(self, scope: AdminScope) -> None:
        self._scope = scope

    async def __aenter__(self) -> AdminScope:
        return self._scope

    async def __aexit__(self, *args: object) -> None:
        pass


def _make_mock_client(
    monkeypatch: pytest.MonkeyPatch,
    nonce_repo: MagicMock | None = None,
    audit_repo: MagicMock | None = None,
) -> TestClient:
    """Build a TestClient with a fake AdminScope (mock-based, no real DB)."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    scope = _fake_admin_scope(nonce_repo=nonce_repo, audit_repo=audit_repo)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_admin_scope] = lambda: _FakeAdminScopeCM(scope)
    return TestClient(app, raise_server_exceptions=False)


_ADMIN_HDR = {"Authorization": "Bearer admin-secret"}


# ---------------------------------------------------------------------------
# Helpers for real-DB tests (audit row assertions)
# ---------------------------------------------------------------------------


async def _make_real_db_session(tmp_path: object) -> AsyncSession:  # type: ignore[return]
    """Create a tmp-sqlite engine with wallets + nonces + audit_log + transactions tables."""
    db = tmp_path  # type: ignore[attr-defined]
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}/test_nonce_init.db")
    async with engine.begin() as conn:
        await conn.run_sync(wallets_metadata.create_all)
        await conn.run_sync(nonces_metadata.create_all)
        await conn.run_sync(audit_metadata.create_all)
        # transactions table required for count_in_flight (nonce-init force guard).
        await conn.run_sync(tx_metadata.create_all)
    return AsyncSession(engine)


async def _seed_wallet(session: AsyncSession, name: str = "alice") -> None:
    await session.execute(
        wallets.insert().values(
            name=name,
            address="0x" + "aa" * 20,
            privkey_ciphertext="seal:v1:test",
            vault_master_key="fwd-master",
            policy_path="policies/test.yaml",
            created_at=datetime.now(UTC),
        )
    )
    await session.commit()


async def _all_audit_rows(session: AsyncSession) -> list[dict[str, object]]:
    result = await session.execute(select(audit_log).order_by(audit_log.c.seq.asc()))
    return [dict(row._mapping) for row in result]


class _RealAdminScopeCM:
    """Async CM that yields an AdminScope backed by a real tmp-sqlite session.

    Mimics AdminScopeCM without touching Vault — exposes the session for
    post-request inspection of nonces + audit rows.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._scope: AdminScope | None = None

    async def __aenter__(self) -> AdminScope:
        nonce_repo = NonceRepo(self._session)
        audit_repo = AuditRepo(self._session)
        tx_repo = TransactionRepo(self._session)
        signer = MagicMock()
        caller_repo = MagicMock()
        self._scope = AdminScope(
            signer=signer,
            caller_repo=caller_repo,
            audit_repo=audit_repo,
            nonce_repo=nonce_repo,
            tx_repo=tx_repo,
        )
        return self._scope

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is None:
            await self._session.commit()


# ---------------------------------------------------------------------------
# Auth tests (mock-based, pure status-code)
# ---------------------------------------------------------------------------


def test_nonce_init_no_auth_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    nonce_repo = MagicMock()
    nonce_repo.get = AsyncMock(return_value=None)
    client = _make_mock_client(monkeypatch, nonce_repo=nonce_repo)
    r = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "alice", "chain": 114, "starting_nonce": 0},
    )
    assert r.status_code == 401


def test_nonce_init_wrong_token_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    nonce_repo = MagicMock()
    nonce_repo.get = AsyncMock(return_value=None)
    client = _make_mock_client(monkeypatch, nonce_repo=nonce_repo)
    r = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "alice", "chain": 114, "starting_nonce": 0},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Wallet-not-found (404) — mock-based
# ---------------------------------------------------------------------------


def test_nonce_init_wallet_not_found_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    from fwd.infra.nonce_repo import NonceWalletNotFoundError

    nonce_repo = MagicMock()
    nonce_repo.get = AsyncMock(return_value=None)
    nonce_repo.init_for_wallet = AsyncMock(side_effect=NonceWalletNotFoundError("ghost"))

    audit_repo = MagicMock()
    audit_repo.append = AsyncMock(return_value=None)
    audit_repo.commit = AsyncMock(return_value=None)

    client = _make_mock_client(monkeypatch, nonce_repo=nonce_repo, audit_repo=audit_repo)
    r = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "ghost", "chain": 114, "starting_nonce": 0},
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "wallet_not_found"


# ---------------------------------------------------------------------------
# Real-DB tests (happy path + idempotent guard + audit rows)
# ---------------------------------------------------------------------------


async def test_nonce_init_happy_path_201(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: create a wallet, POST nonce-init → 201; row exists with next_nonce=0."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    session = await _make_real_db_session(tmp_path)
    await _seed_wallet(session, "alice")

    cm = _RealAdminScopeCM(session)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_admin_scope] = lambda: cm

    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "alice", "chain": 114, "starting_nonce": 0},
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["wallet"] == "alice"
    assert body["chain"] == 114
    assert body["next_nonce"] == 0

    # Verify the nonces row was created.
    nonce = await NonceRepo(session).get("alice", 114, missing_ok=True)
    assert nonce is not None
    assert nonce.next_nonce == 0

    await session.close()


async def test_nonce_init_idempotent_guard_409(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Second call for the same (wallet, chain) → 409; stored next_nonce unchanged."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    session = await _make_real_db_session(tmp_path)
    await _seed_wallet(session, "bob")

    # Seed the nonce directly so the first call sees an existing row.
    await NonceRepo(session).init_for_wallet("bob", 114, 7)
    await session.commit()

    cm = _RealAdminScopeCM(session)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_admin_scope] = lambda: cm

    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "bob", "chain": 114, "starting_nonce": 99},
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"] == "nonce_already_initialized"

    # next_nonce must remain 7 (the original seed).
    nonce = await NonceRepo(session).get("bob", 114, missing_ok=True)
    assert nonce is not None
    assert nonce.next_nonce == 7

    await session.close()


async def test_nonce_init_audit_rows(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After happy path: approved audit row. After 409: denied/already_initialized row."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    session = await _make_real_db_session(tmp_path)
    await _seed_wallet(session, "carol")

    cm = _RealAdminScopeCM(session)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_admin_scope] = lambda: cm

    client = TestClient(app, raise_server_exceptions=False)

    # First call → approved.
    r1 = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "carol", "chain": 114, "starting_nonce": 0},
        headers=_ADMIN_HDR,
    )
    assert r1.status_code == 201, r1.text

    # Second call → denied (already_initialized).
    r2 = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "carol", "chain": 114, "starting_nonce": 5},
        headers=_ADMIN_HDR,
    )
    assert r2.status_code == 409, r2.text

    rows = await _all_audit_rows(session)
    # At least two rows: one approved, one denied.
    assert len(rows) >= 2

    approved_rows = [r for r in rows if r["decision"] == "approved" and r["action"] == "nonce-init"]
    denied_rows = [r for r in rows if r["decision"] == "denied" and r["action"] == "nonce-init"]

    assert len(approved_rows) >= 1, "Expected at least one approved nonce-init audit row"
    assert len(denied_rows) >= 1, "Expected at least one denied nonce-init audit row"
    assert denied_rows[0]["decision_reason"] == "already_initialized"

    await session.close()


# ---------------------------------------------------------------------------
# force=True overwrite tests (a50)
# ---------------------------------------------------------------------------


async def test_nonce_init_force_overwrites_existing_201(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """force=true on an existing (wallet, chain) → 201; row reflects new value; approved audit row
    with decision_reason=force_overwrite and from/to outcome."""
    import json

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    session = await _make_real_db_session(tmp_path)
    await _seed_wallet(session, "dave")

    # Pre-seed the nonce at 50.
    await NonceRepo(session).init_for_wallet("dave", 114, 50)
    await session.commit()

    cm = _RealAdminScopeCM(session)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_admin_scope] = lambda: cm

    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "dave", "chain": 114, "starting_nonce": 10, "force": True},
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["next_nonce"] == 10

    # Verify the DB row was overwritten.
    nonce = await NonceRepo(session).get("dave", 114, missing_ok=True)
    assert nonce is not None
    assert nonce.next_nonce == 10
    assert nonce.last_confirmed is None

    # Verify the audit row.
    rows = await _all_audit_rows(session)
    force_rows = [
        row for row in rows
        if row["action"] == "nonce-init"
        and row["decision"] == "approved"
        and row["decision_reason"] == "force_overwrite"
    ]
    assert len(force_rows) == 1, f"expected exactly one force_overwrite audit row, got {force_rows}"
    outcome = json.loads(force_rows[0]["outcome"])  # type: ignore[arg-type]
    assert outcome["from"] == 50
    assert outcome["to"] == 10

    await session.close()


async def test_nonce_init_non_force_on_existing_still_409(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """force=false (omitted) on an existing (wallet, chain) still → 409."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    session = await _make_real_db_session(tmp_path)
    await _seed_wallet(session, "eve")

    await NonceRepo(session).init_for_wallet("eve", 114, 3)
    await session.commit()

    cm = _RealAdminScopeCM(session)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_admin_scope] = lambda: cm

    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "eve", "chain": 114, "starting_nonce": 99},  # no force field
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"] == "nonce_already_initialized"

    # next_nonce must remain unchanged.
    nonce = await NonceRepo(session).get("eve", 114, missing_ok=True)
    assert nonce is not None
    assert nonce.next_nonce == 3

    await session.close()


async def test_nonce_init_force_on_non_existing_creates_201(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """force=true on a non-existing (wallet, chain) creates the row → 201."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    session = await _make_real_db_session(tmp_path)
    await _seed_wallet(session, "frank")

    cm = _RealAdminScopeCM(session)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_admin_scope] = lambda: cm

    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(
        "/v1/admin/nonce-init",
        json={"wallet": "frank", "chain": 114, "starting_nonce": 7, "force": True},
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["next_nonce"] == 7

    # Verify the row exists.
    nonce = await NonceRepo(session).get("frank", 114, missing_ok=True)
    assert nonce is not None
    assert nonce.next_nonce == 7

    await session.close()


# ---------------------------------------------------------------------------
# GET /v1/admin/nonce/{wallet}/{chain} tests (capability 1)
# ---------------------------------------------------------------------------


async def test_nonce_get_200_for_initialized_row(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /v1/admin/nonce/{wallet}/{chain} returns 200 with next_nonce + last_confirmed."""
    from fwd.app.dependencies import get_nonce_repo

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    session = await _make_real_db_session(tmp_path)
    await _seed_wallet(session, "grace")

    # Seed a nonce row.
    await NonceRepo(session).init_for_wallet("grace", 14, 5)
    await session.commit()

    class _NonceCM:
        async def __aenter__(self) -> NonceRepo:
            return NonceRepo(session)

        async def __aexit__(self, *args: object) -> None:
            pass

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[get_nonce_repo] = lambda: _NonceCM()

    client = TestClient(test_app, raise_server_exceptions=False)
    r = client.get("/v1/admin/nonce/grace/14", headers=_ADMIN_HDR)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["wallet"] == "grace"
    assert body["chain"] == 14
    assert body["next_nonce"] == 5
    assert body["last_confirmed"] is None

    await session.close()


def test_nonce_get_404_for_absent_row(monkeypatch: pytest.MonkeyPatch) -> None:
    """GET /v1/admin/nonce/{wallet}/{chain} returns 404 nonce_not_initialized for an absent row."""
    from fwd.app.dependencies import get_nonce_repo

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    nonce_repo = MagicMock()
    nonce_repo.get = AsyncMock(return_value=None)

    class _NonceCM:
        async def __aenter__(self) -> MagicMock:
            return nonce_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[get_nonce_repo] = lambda: _NonceCM()

    client = TestClient(test_app, raise_server_exceptions=False)
    r = client.get("/v1/admin/nonce/ghost/114", headers=_ADMIN_HDR)
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "nonce_not_initialized"
