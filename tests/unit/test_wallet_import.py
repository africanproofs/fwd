"""Wallet-import use case: D9 refusal-table tests.

v0.5.0a7: import_wallet gained keyword-only audit_repo param. All calls
updated to pass a mock AuditRepo (append is AsyncMock).
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from fwd.app.wallet_import import (
    PrivkeyFileBadContent,
    PrivkeyFileBadMode,
    PrivkeyFileBadOwner,
    PrivkeyFileNotFound,
    WalletAddressMismatch,
    WalletImportRequest,
    WalletNameTakenImport,
    import_wallet,
)
from fwd.infra.wallet_repo import Wallet, WalletExistsError


def _write_privkey(tmp_path: pytest.TempPathFactory, content: str = "aa" * 32) -> os.PathLike[str]:  # type: ignore[type-arg]
    p = tmp_path / "privkey.hex"
    p.write_text(content, encoding="ascii")
    p.chmod(0o600)
    return p


def _mock_signer(wallet: Wallet | None = None, side_effect: Exception | None = None) -> MagicMock:
    signer = MagicMock()
    if side_effect is not None:
        signer.import_wallet = AsyncMock(side_effect=side_effect)
    else:
        signer.import_wallet = AsyncMock(return_value=wallet or _dummy_wallet())
    return signer


def _mock_audit_repo() -> MagicMock:
    """Minimal mock AuditRepo: append and commit are AsyncMock."""
    repo = MagicMock()
    repo.append = AsyncMock(return_value=None)
    repo.commit = AsyncMock(return_value=None)
    return repo


def _dummy_wallet() -> Wallet:
    from datetime import UTC, datetime

    return Wallet(
        name="w1",
        address="0x" + "ab" * 20,
        privkey_ciphertext="vault:v1:abc",
        vault_master_key="fwd-master",
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
    )


# --- Refusal table tests (D9) -----------------------------------------------


@pytest.mark.asyncio
async def test_file_not_found_raises(tmp_path: pytest.TempPathFactory) -> None:
    missing = tmp_path / "nope.hex"
    req = WalletImportRequest(name="w", policy_path="policies/w.yaml", privkey_file=missing)
    with pytest.raises(PrivkeyFileNotFound):
        await import_wallet(req, _mock_signer(), audit_repo=_mock_audit_repo())


@pytest.mark.asyncio
async def test_bad_mode_raises(tmp_path: pytest.TempPathFactory) -> None:
    p = _write_privkey(tmp_path)
    os.chmod(p, 0o644)
    req = WalletImportRequest(name="w", policy_path="policies/w.yaml", privkey_file=p)
    with pytest.raises(PrivkeyFileBadMode):
        await import_wallet(req, _mock_signer(), audit_repo=_mock_audit_repo())


@pytest.mark.asyncio
async def test_bad_owner_raises(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _write_privkey(tmp_path)
    monkeypatch.setattr(os, "getuid", lambda: 9999)
    req = WalletImportRequest(name="w", policy_path="policies/w.yaml", privkey_file=p)
    with pytest.raises(PrivkeyFileBadOwner):
        await import_wallet(req, _mock_signer(), audit_repo=_mock_audit_repo())


@pytest.mark.asyncio
async def test_bad_content_not_hex_raises(tmp_path: pytest.TempPathFactory) -> None:
    p = tmp_path / "privkey.hex"
    p.write_text("not-hex-content!", encoding="ascii")
    p.chmod(0o600)
    req = WalletImportRequest(name="w", policy_path="policies/w.yaml", privkey_file=p)
    with pytest.raises(PrivkeyFileBadContent):
        await import_wallet(req, _mock_signer(), audit_repo=_mock_audit_repo())


@pytest.mark.asyncio
async def test_bad_content_wrong_length_raises(tmp_path: pytest.TempPathFactory) -> None:
    p = tmp_path / "privkey.hex"
    p.write_text("abcd" * 4, encoding="ascii")  # 8 bytes, not 32
    p.chmod(0o600)
    req = WalletImportRequest(name="w", policy_path="policies/w.yaml", privkey_file=p)
    with pytest.raises(PrivkeyFileBadContent):
        await import_wallet(req, _mock_signer(), audit_repo=_mock_audit_repo())


@pytest.mark.asyncio
async def test_wallet_exists_raises(tmp_path: pytest.TempPathFactory) -> None:
    p = _write_privkey(tmp_path)
    req = WalletImportRequest(name="dup", policy_path="policies/w.yaml", privkey_file=p)
    signer = _mock_signer(side_effect=WalletExistsError("dup"))
    with pytest.raises(WalletNameTakenImport):
        await import_wallet(req, signer, audit_repo=_mock_audit_repo())


@pytest.mark.asyncio
async def test_address_mismatch_surfaces(tmp_path: pytest.TempPathFactory) -> None:
    p = _write_privkey(tmp_path)
    req = WalletImportRequest(
        name="w",
        policy_path="policies/w.yaml",
        privkey_file=p,
        expected_address="0x" + "00" * 20,
    )
    mismatch = WalletAddressMismatch(expected="0x" + "00" * 20, derived="0x" + "ab" * 20)
    signer = _mock_signer(side_effect=mismatch)
    with pytest.raises(WalletAddressMismatch):
        await import_wallet(req, signer, audit_repo=_mock_audit_repo())


@pytest.mark.asyncio
async def test_happy_path_returns_wallet(tmp_path: pytest.TempPathFactory) -> None:
    p = _write_privkey(tmp_path)
    req = WalletImportRequest(name="w1", policy_path="policies/w.yaml", privkey_file=p)
    wallet = _dummy_wallet()
    result = await import_wallet(req, _mock_signer(wallet=wallet), audit_repo=_mock_audit_repo())
    assert result.name == "w1"


# --- F1.2: missing `shred` is a hard failure, NOT a silent unlink fallback ---


@pytest.mark.asyncio
async def test_shred_missing_raises_shred_source_failed(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per architecture.md § Wallet provisioning § Import: missing `shred`
    must NOT silently fall through to plain `unlink()`. The wallet is
    provisioned; the source file remains on disk; the CLI surfaces a
    non-zero exit code via ShredSourceFailed.

    Closes audit F1.2 (v0.4.0a1 audit).
    """
    from fwd.app.wallet_import import ShredSourceFailed

    p = _write_privkey(tmp_path)
    req = WalletImportRequest(
        name="w-shred",
        policy_path="policies/w.yaml",
        privkey_file=p,
        shred_source=True,
    )
    # Simulate `shred` not on PATH.
    monkeypatch.setattr("fwd.app.wallet_import.shutil.which", lambda _: None)

    with pytest.raises(ShredSourceFailed):
        await import_wallet(req, _mock_signer(), audit_repo=_mock_audit_repo())

    # The source file MUST still exist (architecture.md doctrine: "the
    # wallet is provisioned but the source file remains on disk for the
    # operator to handle").
    assert p.exists(), "shred fallback unlinked the file silently — F1.2 regression"
