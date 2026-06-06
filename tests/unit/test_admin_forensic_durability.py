"""Core invariant #19 forensic-durability regression guards.

Verifies that audit_repo.commit() is called on the error paths of
wallet_create, caller_create, and caller_revoke. Each test FAILS if
commit() is removed from the error path, enforcing Core invariant #19:
'Forensic audit rows survive the failure they record.'

Pattern: mock audit_repo with commit=AsyncMock, trigger the error path,
assert commit.assert_called_once() — one durable commit per refusal.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from fwd.app.caller_create import CallerCreateRequest, CallerNameTaken, create_caller
from fwd.app.caller_revoke import CallerAlreadyRevoked, CallerNotFound, revoke_caller
from fwd.app.wallet_create import VaultUnavailableError, WalletCreateRequest, WalletNameTaken, create_wallet
from fwd.infra.caller_repo import Caller, CallerAlreadyRevokedError, CallerExistsError, CallerNotFoundError
from fwd.infra.sealed_master import SealError
from fwd.infra.wallet_repo import Wallet, WalletExistsError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_audit_repo() -> MagicMock:
    """Minimal mock AuditRepo: append and commit are AsyncMock."""
    repo = MagicMock()
    repo.append = AsyncMock(return_value=None)
    repo.commit = AsyncMock(return_value=None)
    return repo


def _dummy_wallet() -> Wallet:
    return Wallet(
        name="w1",
        address="0x" + "ab" * 20,
        privkey_ciphertext="seal:v1:abc",
        vault_master_key="fwd-master",
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
    )


def _dummy_caller(name: str = "test") -> Caller:
    return Caller(
        name=name,
        api_key_hash="argon2hash",
        api_key_prefix="abcd1234",
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


# ---------------------------------------------------------------------------
# wallet_create — WalletExistsError path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wallet_create_audit_commit_on_exists_error() -> None:
    """Core #19: audit row must be durably committed when wallet name is taken."""
    signer = MagicMock()
    signer.create_wallet = AsyncMock(side_effect=WalletExistsError("dup"))
    audit = _mock_audit_repo()

    with pytest.raises(WalletNameTaken):
        await create_wallet(
            WalletCreateRequest(name="dup", policy_path="policies/dup.yaml"),
            signer,
            audit_repo=audit,
        )

    # Core #19: forensic row must be durably committed on the error path.
    audit.commit.assert_called_once()


@pytest.mark.asyncio
async def test_wallet_create_audit_commit_on_seal_error() -> None:
    """Core #19: audit row must be durably committed when the sealed master fails."""
    signer = MagicMock()
    signer.create_wallet = AsyncMock(side_effect=SealError("key file missing"))
    audit = _mock_audit_repo()

    with pytest.raises(VaultUnavailableError):
        await create_wallet(
            WalletCreateRequest(name="w-seal", policy_path="policies/w.yaml"),
            signer,
            audit_repo=audit,
        )

    # Core #19: forensic row must be durably committed on the seal-error path.
    audit.commit.assert_called_once()


@pytest.mark.asyncio
async def test_wallet_create_no_commit_on_happy_path() -> None:
    """Happy path: commit is NOT called explicitly (AdminScopeCM owns it)."""
    signer = MagicMock()
    signer.create_wallet = AsyncMock(return_value=_dummy_wallet())
    audit = _mock_audit_repo()

    result = await create_wallet(
        WalletCreateRequest(name="w1", policy_path="policies/w.yaml"),
        signer,
        audit_repo=audit,
    )

    assert result.name == "w1"
    # Happy path: no explicit commit — AdminScopeCM.__aexit__ commits.
    audit.commit.assert_not_called()


# ---------------------------------------------------------------------------
# caller_create — CallerExistsError path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_caller_create_audit_commit_on_name_taken() -> None:
    """Core #19: audit row must be durably committed when caller name is taken."""
    repo = MagicMock()
    repo.create = AsyncMock(side_effect=CallerExistsError("dup"))
    audit = _mock_audit_repo()

    with pytest.raises(CallerNameTaken):
        await create_caller(
            CallerCreateRequest(name="dup", policy_path="policies/dup.yaml"),
            repo,
            audit_repo=audit,
        )

    # Core #19: forensic row must be durably committed on the error path.
    audit.commit.assert_called_once()


@pytest.mark.asyncio
async def test_caller_create_no_commit_on_happy_path() -> None:
    """Happy path: commit is NOT called explicitly (AdminScopeCM owns it)."""
    repo = MagicMock()
    repo.create = AsyncMock(return_value=_dummy_caller("ok"))
    audit = _mock_audit_repo()

    result = await create_caller(
        CallerCreateRequest(name="ok", policy_path="policies/ok.yaml"),
        repo,
        audit_repo=audit,
    )

    assert result.name == "ok"
    # Happy path: no explicit commit — AdminScopeCM.__aexit__ commits.
    audit.commit.assert_not_called()


# ---------------------------------------------------------------------------
# caller_revoke — CallerNotFoundError + CallerAlreadyRevokedError paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_caller_revoke_audit_commit_on_not_found() -> None:
    """Core #19: audit row must be durably committed when the caller is not found."""
    repo = MagicMock()
    repo.revoke = AsyncMock(side_effect=CallerNotFoundError("ghost"))
    audit = _mock_audit_repo()

    with pytest.raises(CallerNotFound):
        await revoke_caller("ghost", repo, audit_repo=audit)

    # Core #19: forensic row must be durably committed on the error path.
    audit.commit.assert_called_once()


@pytest.mark.asyncio
async def test_caller_revoke_audit_commit_on_already_revoked() -> None:
    """Core #19: audit row must be durably committed when caller is already revoked."""
    repo = MagicMock()
    repo.revoke = AsyncMock(side_effect=CallerAlreadyRevokedError("already-gone"))
    audit = _mock_audit_repo()

    with pytest.raises(CallerAlreadyRevoked):
        await revoke_caller("already-gone", repo, audit_repo=audit)

    # Core #19: forensic row must be durably committed on the already-revoked path.
    audit.commit.assert_called_once()


@pytest.mark.asyncio
async def test_caller_revoke_no_commit_on_happy_path() -> None:
    """Happy path: commit is NOT called explicitly (AdminScopeCM owns it)."""
    repo = MagicMock()
    repo.revoke = AsyncMock(return_value=None)
    audit = _mock_audit_repo()

    await revoke_caller("active", repo, audit_repo=audit)

    # Happy path: no explicit commit — AdminScopeCM.__aexit__ commits.
    audit.commit.assert_not_called()
