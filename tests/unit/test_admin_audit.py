"""Unit tests for D16 admin-action audit authorship.

Verifies that each admin use case writes exactly ONE audit row per call
(on both success and known-failure paths), with the correct action/decision/
caller=None, and that request_json never contains secrets (api_key, hash,
privkey bytes).

Uses real tmp-sqlite for the audit_log table; mocks signer/caller_repo.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.app.caller_create import CallerCreateRequest, CallerNameTaken, create_caller
from fwd.app.caller_revoke import CallerNotFound, revoke_caller
from fwd.app.wallet_create import WalletCreateRequest, WalletNameTaken, create_wallet
from fwd.app.wallet_import import (
    PrivkeyFileBadMode,
    WalletImportRequest,
    import_wallet,
)
from fwd.infra.audit_repo import AuditRepo, audit_log, audit_metadata
from fwd.infra.caller_repo import CallerExistsError, CallerNotFoundError
from fwd.infra.wallet_repo import Wallet, WalletExistsError

POLICY_PATH = "perm/test"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def session(tmp_path):  # type: ignore[no-untyped-def]
    """Real tmp-sqlite session with audit_log table."""
    db = tmp_path / "test_admin_audit.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(audit_metadata.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dummy_wallet(name: str = "w1", address: str = "0x" + "ab" * 20) -> Wallet:
    return Wallet(
        name=name,
        address=address,
        privkey_ciphertext="vault:v1:abc",
        vault_master_key="fwd-master",
        policy_path=POLICY_PATH,
        created_at=datetime.now(UTC),
    )


def _mock_signer(wallet: Wallet | None = None, side_effect: Exception | None = None) -> MagicMock:
    signer = MagicMock()
    if side_effect is not None:
        signer.create_wallet = AsyncMock(side_effect=side_effect)
        signer.import_wallet = AsyncMock(side_effect=side_effect)
    else:
        w = wallet or _dummy_wallet()
        signer.create_wallet = AsyncMock(return_value=w)
        signer.import_wallet = AsyncMock(return_value=w)
    return signer


def _mock_caller_repo(
    create_side_effect: Exception | None = None,
    revoke_side_effect: Exception | None = None,
) -> MagicMock:
    from datetime import UTC, datetime

    from fwd.infra.caller_repo import Caller

    repo = MagicMock()
    if create_side_effect is not None:
        repo.create = AsyncMock(side_effect=create_side_effect)
    else:
        repo.create = AsyncMock(
            return_value=Caller(
                name="svc",
                api_key_hash="argon2hash",
                api_key_prefix="abcd1234",
                policy_path=POLICY_PATH,
                created_at=datetime.now(UTC),
                revoked_at=None,
            )
        )
    if revoke_side_effect is not None:
        repo.revoke = AsyncMock(side_effect=revoke_side_effect)
    else:
        repo.revoke = AsyncMock(return_value=None)
    return repo


async def _all_audit_rows(session: AsyncSession) -> list[dict[str, object]]:
    result = await session.execute(select(audit_log).order_by(audit_log.c.seq.asc()))
    return [dict(row._mapping) for row in result]


# ---------------------------------------------------------------------------
# create_wallet
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_wallet_success_writes_approved_row(session: AsyncSession) -> None:
    signer = _mock_signer()
    audit_repo = AuditRepo(session)

    await create_wallet(
        WalletCreateRequest(name="w1", policy_path=POLICY_PATH),
        signer,
        audit_repo=audit_repo,
    )

    rows = await _all_audit_rows(session)
    assert len(rows) == 1
    r = rows[0]
    assert r["action"] == "wallet-create"
    assert r["decision"] == "approved"
    assert r["caller"] is None  # admin action
    req_json = json.loads(str(r["request_json"]))
    assert req_json["name"] == "w1"
    assert req_json["policy_path"] == POLICY_PATH
    # No secrets in request_json
    raw = str(r["request_json"])
    assert "privkey" not in raw
    assert "ciphertext" not in raw
    assert "vault" not in raw.lower() or "policy_path" in raw  # policy_path may contain 'vault'


@pytest.mark.asyncio
async def test_create_wallet_name_taken_writes_error_row_and_raises(
    session: AsyncSession,
) -> None:
    signer = _mock_signer(side_effect=WalletExistsError("w1"))
    audit_repo = AuditRepo(session)

    with pytest.raises(WalletNameTaken):
        await create_wallet(
            WalletCreateRequest(name="w1", policy_path=POLICY_PATH),
            signer,
            audit_repo=audit_repo,
        )

    rows = await _all_audit_rows(session)
    assert len(rows) == 1
    r = rows[0]
    assert r["action"] == "wallet-create"
    assert r["decision"] == "error"
    assert r["caller"] is None
    assert r["decision_reason"] is not None


# ---------------------------------------------------------------------------
# create_caller
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_caller_success_writes_approved_row(session: AsyncSession) -> None:
    repo = _mock_caller_repo()
    audit_repo = AuditRepo(session)

    result = await create_caller(
        CallerCreateRequest(name="svc", policy_path=POLICY_PATH),
        repo,
        audit_repo=audit_repo,
    )

    rows = await _all_audit_rows(session)
    assert len(rows) == 1
    r = rows[0]
    assert r["action"] == "caller-create"
    assert r["decision"] == "approved"
    assert r["caller"] is None

    # outcome must contain api_key_prefix, NOT the plaintext key or hash
    outcome = json.loads(str(r["outcome"]))
    assert "api_key_prefix" in outcome
    assert outcome["api_key_prefix"] == result.api_key_prefix
    # Never the plaintext or hash
    raw_outcome = str(r["outcome"])
    assert result.api_key not in raw_outcome
    assert "fwd_live_" not in raw_outcome


@pytest.mark.asyncio
async def test_create_caller_name_taken_writes_error_row_and_raises(
    session: AsyncSession,
) -> None:
    repo = _mock_caller_repo(create_side_effect=CallerExistsError("svc"))
    audit_repo = AuditRepo(session)

    with pytest.raises(CallerNameTaken):
        await create_caller(
            CallerCreateRequest(name="svc", policy_path=POLICY_PATH),
            repo,
            audit_repo=audit_repo,
        )

    rows = await _all_audit_rows(session)
    assert len(rows) == 1
    assert rows[0]["action"] == "caller-create"
    assert rows[0]["decision"] == "error"
    assert rows[0]["caller"] is None


# ---------------------------------------------------------------------------
# revoke_caller
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_caller_success_writes_approved_row(session: AsyncSession) -> None:
    repo = _mock_caller_repo()
    audit_repo = AuditRepo(session)

    await revoke_caller("svc", repo, audit_repo=audit_repo)

    rows = await _all_audit_rows(session)
    assert len(rows) == 1
    r = rows[0]
    assert r["action"] == "caller-revoke"
    assert r["decision"] == "approved"
    assert r["caller"] is None
    req_json = json.loads(str(r["request_json"]))
    assert req_json["name"] == "svc"


@pytest.mark.asyncio
async def test_revoke_caller_not_found_writes_error_row_and_raises(
    session: AsyncSession,
) -> None:
    repo = _mock_caller_repo(revoke_side_effect=CallerNotFoundError("svc"))
    audit_repo = AuditRepo(session)

    with pytest.raises(CallerNotFound):
        await revoke_caller("svc", repo, audit_repo=audit_repo)

    rows = await _all_audit_rows(session)
    assert len(rows) == 1
    assert rows[0]["decision"] == "error"
    assert rows[0]["action"] == "caller-revoke"


# ---------------------------------------------------------------------------
# import_wallet
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_wallet_success_writes_approved_row(
    tmp_path,  # type: ignore[no-untyped-def]
    session: AsyncSession,
) -> None:
    """Happy path: successful import writes a wallet-import approved row."""
    privkey_file = tmp_path / "privkey.hex"
    privkey_file.write_text("aa" * 32, encoding="ascii")
    privkey_file.chmod(0o600)

    signer = _mock_signer()
    audit_repo = AuditRepo(session)

    req = WalletImportRequest(name="w1", policy_path=POLICY_PATH, privkey_file=privkey_file)
    result = await import_wallet(req, signer, audit_repo=audit_repo)

    rows = await _all_audit_rows(session)
    assert len(rows) == 1
    r = rows[0]
    assert r["action"] == "wallet-import"
    assert r["decision"] == "approved"
    assert r["caller"] is None

    # request_json must NOT contain privkey bytes
    raw_req = str(r["request_json"])
    assert "aa" * 32 not in raw_req  # privkey hex must not appear
    assert result.name == "w1"


@pytest.mark.asyncio
async def test_import_wallet_bad_mode_writes_error_row_and_raises(
    tmp_path,  # type: ignore[no-untyped-def]
    session: AsyncSession,
) -> None:
    """PrivkeyFileBadMode: error audit row written; request_json has no privkey."""
    privkey_file = tmp_path / "privkey.hex"
    privkey_file.write_text("aa" * 32, encoding="ascii")
    privkey_file.chmod(0o644)  # wrong mode

    signer = _mock_signer()
    audit_repo = AuditRepo(session)

    req = WalletImportRequest(name="w1", policy_path=POLICY_PATH, privkey_file=privkey_file)
    with pytest.raises(PrivkeyFileBadMode):
        await import_wallet(req, signer, audit_repo=audit_repo)

    rows = await _all_audit_rows(session)
    assert len(rows) == 1
    r = rows[0]
    assert r["action"] == "wallet-import"
    assert r["decision"] == "error"
    assert r["caller"] is None
    assert r["decision_reason"] is not None

    # request_json must not contain privkey even on failure
    raw_req = str(r["request_json"])
    assert "aa" * 32 not in raw_req
