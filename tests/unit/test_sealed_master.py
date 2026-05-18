"""SealedMaster unit tests (real crypto, no mocks needed).

Verifies:
- round-trip: encrypt then decrypt == original plaintext;
- ciphertext prefix is "seal:v1:";
- two encrypts of the same plaintext differ (random nonce);
- decrypt of non-"seal:v1:" prefix raises SealError;
- decrypt of corrupted blob raises SealError;
- __init__ raises SealError on: missing file, wrong mode (0644), wrong size
  (31 bytes), not-a-file (directory path);
- __aexit__ zeroizes: after ``async with``, internal bytearray is all-zero;
- 32-byte all-zero plaintext and a 32-byte privkey-shaped plaintext both
  round-trip (the real privkey use case).
"""

from __future__ import annotations

import os
from pathlib import Path  # noqa: TC003

import pytest

from fwd import settings as settings_mod
from fwd.infra.sealed_master import SealedMaster, SealError


def _make_master_file(tmp_path: Path, *, size: int = 32, mode: int = 0o600) -> Path:
    """Write a random (or sized) key file with the given mode."""
    p = tmp_path / "master.key"
    p.write_bytes(os.urandom(size) if size > 0 else b"x" * size)
    if size == 31:
        p.write_bytes(b"\x00" * 31)
    os.chmod(p, mode)
    return p


def _set_master_file(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    """Point settings at ``path`` for the duration of the test."""
    monkeypatch.setenv("FWD_MASTER_KEY_FILE", path)
    settings_mod.get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Happy-path crypto
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = _make_master_file(tmp_path)
    _set_master_file(monkeypatch, str(key_file))

    plaintext = b"\xde\xad\xbe\xef" * 8  # 32 bytes
    async with SealedMaster() as m:
        ct = await m.encrypt(plaintext)
        recovered = await m.decrypt(ct)
    assert recovered == plaintext


@pytest.mark.asyncio
async def test_ciphertext_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = _make_master_file(tmp_path)
    _set_master_file(monkeypatch, str(key_file))

    async with SealedMaster() as m:
        ct = await m.encrypt(b"\x01" * 32)
    assert ct.startswith("seal:v1:")


@pytest.mark.asyncio
async def test_two_encrypts_differ(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Random nonce means two encrypts of the same plaintext differ."""
    key_file = _make_master_file(tmp_path)
    _set_master_file(monkeypatch, str(key_file))

    plaintext = b"\xaa" * 32
    async with SealedMaster() as m:
        ct1 = await m.encrypt(plaintext)
        ct2 = await m.encrypt(plaintext)
    assert ct1 != ct2


@pytest.mark.asyncio
async def test_decrypt_wrong_prefix_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = _make_master_file(tmp_path)
    _set_master_file(monkeypatch, str(key_file))

    async with SealedMaster() as m:
        with pytest.raises(SealError, match="seal:v1:"):
            await m.decrypt("vault:v1:somethingrandom")


@pytest.mark.asyncio
async def test_decrypt_corrupted_blob_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Flipping a byte in the ciphertext must trigger an AESGCM auth failure."""
    key_file = _make_master_file(tmp_path)
    _set_master_file(monkeypatch, str(key_file))

    import base64

    plaintext = b"\x42" * 32
    async with SealedMaster() as m:
        ct = await m.encrypt(plaintext)

    # Corrupt one byte in the base64 payload.
    prefix = "seal:v1:"
    blob = bytearray(base64.b64decode(ct[len(prefix) :]))
    blob[12] ^= 0xFF  # flip a byte in the ciphertext portion
    corrupted = prefix + base64.b64encode(bytes(blob)).decode("ascii")

    async with SealedMaster() as m:
        with pytest.raises(SealError, match="decrypt failed"):
            await m.decrypt(corrupted)


# ---------------------------------------------------------------------------
# __init__ validation failures
# ---------------------------------------------------------------------------


def test_init_missing_file(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_master_file(monkeypatch, "/nonexistent/path/master.key")
    with pytest.raises(SealError, match="not found"):
        SealedMaster()


def test_init_wrong_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = _make_master_file(tmp_path, mode=0o644)
    _set_master_file(monkeypatch, str(key_file))
    with pytest.raises(SealError, match="0600"):
        SealedMaster()


def test_init_wrong_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """31-byte file must be rejected."""
    p = tmp_path / "short.key"
    p.write_bytes(b"\x00" * 31)
    os.chmod(p, 0o600)
    _set_master_file(monkeypatch, str(p))
    with pytest.raises(SealError, match="31"):
        SealedMaster()


def test_init_not_a_file_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Passing a directory path must be rejected."""
    _set_master_file(monkeypatch, str(tmp_path))
    with pytest.raises(SealError, match="not found"):
        SealedMaster()


# ---------------------------------------------------------------------------
# __aexit__ zeroizes the master key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aexit_zeroizes_master(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """After ``async with``, the internal bytearray must be all zeros."""
    key_file = _make_master_file(tmp_path)
    _set_master_file(monkeypatch, str(key_file))

    m = SealedMaster()
    async with m:
        pass  # normal exit triggers __aexit__

    assert all(b == 0 for b in m._master), "zeroize failed: master bytearray not all zeros"


# ---------------------------------------------------------------------------
# Real privkey-shaped plaintexts round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_zero_plaintext_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """32-byte all-zero plaintext (edge case) must survive the round-trip."""
    key_file = _make_master_file(tmp_path)
    _set_master_file(monkeypatch, str(key_file))

    plaintext = b"\x00" * 32
    async with SealedMaster() as m:
        ct = await m.encrypt(plaintext)
        recovered = await m.decrypt(ct)
    assert recovered == plaintext


@pytest.mark.asyncio
async def test_privkey_shaped_plaintext_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """32-byte random privkey-shaped plaintext must survive the round-trip."""
    from eth_account import Account

    key_file = _make_master_file(tmp_path)
    _set_master_file(monkeypatch, str(key_file))

    real = Account.create()
    privkey_bytes = bytes(real.key)
    assert len(privkey_bytes) == 32

    async with SealedMaster() as m:
        ct = await m.encrypt(privkey_bytes)
        recovered = await m.decrypt(ct)
    assert recovered == privkey_bytes
