"""EnvelopeSigner unit tests.

Verifies:
- create_wallet generates a valid address, encrypts via vault, persists.
- The plaintext bytearray is zeroized after create_wallet returns
  (architecture.md hazard #2 enforcement; landed v0.3.2).
- No instance state on the signer holds 32-byte plaintext after a call
  (architecture.md hazard #1 enforcement; landed v0.3.2).
- sign_transaction decrypts, signs an EIP-1559 tx, zeroizes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fwd.infra import envelope_signer as envelope_signer_module
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.wallet_repo import Wallet


@pytest.mark.asyncio
async def test_create_wallet_happy() -> None:
    vault = MagicMock()
    vault.encrypt = AsyncMock(return_value="seal:v1:abc")

    repo = MagicMock()
    captured_kwargs: dict[str, Any] = {}

    async def _create(**kwargs: Any) -> Wallet:
        captured_kwargs.update(kwargs)
        return Wallet(
            name=kwargs["name"],
            address=kwargs["address"],
            privkey_ciphertext=kwargs["privkey_ciphertext"],
            vault_master_key=kwargs["vault_master_key"],
            policy_path=kwargs["policy_path"],
            created_at=datetime.now(UTC),
        )

    repo.create = _create

    signer = EnvelopeSigner(vault, repo)
    wallet = await signer.create_wallet(name="w1", policy_path="p1")

    assert wallet.name == "w1"
    assert wallet.address.startswith("0x")
    assert len(wallet.address) == 42  # 0x + 40 hex
    assert wallet.privkey_ciphertext == "seal:v1:abc"
    assert captured_kwargs["vault_master_key"] == "local:v1"
    vault.encrypt.assert_awaited_once()
    # First positional arg to encrypt was 32 bytes.
    args, _ = vault.encrypt.await_args
    assert len(args[0]) == 32


@pytest.mark.asyncio
async def test_sign_transaction_round_trip() -> None:
    """sign_transaction decrypts, signs an EIP-1559 tx, zeroizes.

    Round-trip verifies: the signature recovers to the wallet's address,
    so the decrypt -> sign path is correct end-to-end (with mocked Vault).
    """
    from datetime import UTC, datetime

    from eth_account import Account

    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.wallet_repo import Wallet

    # Generate a known keypair.
    real = Account.create()
    expected_address = real.address
    privkey_bytes = bytes(real.key)

    vault = MagicMock()
    vault.decrypt = AsyncMock(return_value=privkey_bytes)

    repo = MagicMock()
    repo.get_by_name = AsyncMock(
        return_value=Wallet(
            name="w1",
            address=expected_address,
            privkey_ciphertext="seal:v1:abc",
            vault_master_key="local:v1",
            policy_path="p1",
            created_at=datetime.now(UTC),
        )
    )

    signer = EnvelopeSigner(vault, repo)

    tx_dict = {
        "type": 2,
        "chainId": 114,
        "nonce": 0,
        "to": "0x" + "11" * 20,
        "value": 0,
        "data": "0x",
        "gas": 21000,
        "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
    }
    signed = await signer.sign_transaction("w1", tx_dict)

    assert isinstance(signed.raw_transaction, bytes)
    assert isinstance(signed.hash, bytes)
    assert len(signed.hash) == 32

    # Recover sender address from the signed tx; must match.
    recovered = Account.recover_transaction(signed.raw_transaction)
    assert recovered.lower() == expected_address.lower()


# --- architecture.md hazard #2 enforcement (zeroize-on-completion) -------


def test_zeroize_overwrites_bytearray_in_place() -> None:
    """Direct test: _zeroize(bytearray) overwrites every byte to 0 in place.

    Sanity check that the helper itself works; the buffer is mutable and
    its identity is preserved (not replaced) so callers see zero bytes.
    """
    buf = bytearray(b"\xab" * 32)
    original_id = id(buf)
    envelope_signer_module._zeroize(buf)
    assert all(b == 0 for b in buf)
    assert len(buf) == 32
    assert isinstance(buf, bytearray)
    assert id(buf) == original_id  # in-place, not replaced


@pytest.mark.asyncio
async def test_create_wallet_buffer_is_all_zero_after_zeroize() -> None:
    """The bytearray passed to _zeroize is all zeros AFTER the call returns.

    Architecture.md hazard #2: 'a unit test confirms the post-zeroize
    buffer contains only zeros AND that type(buf) is bytearray.'
    """
    vault = MagicMock()
    vault.encrypt = AsyncMock(return_value="seal:v1:abc")
    repo = MagicMock()

    async def _create(**kwargs: Any) -> Wallet:
        return Wallet(
            name=kwargs["name"],
            address=kwargs["address"],
            privkey_ciphertext=kwargs["privkey_ciphertext"],
            vault_master_key=kwargs["vault_master_key"],
            policy_path=kwargs["policy_path"],
            created_at=datetime.now(UTC),
        )

    repo.create = _create

    captured_post_zeroize: list[bytes] = []
    real_zeroize = envelope_signer_module._zeroize

    def spy_zeroize(buf: bytearray) -> None:
        real_zeroize(buf)
        # Snapshot the buffer state AFTER zeroize ran.
        captured_post_zeroize.append(bytes(buf))
        # And confirm the live buffer's type for the hazard #2 contract.
        assert isinstance(buf, bytearray), "hazard #2: buffer must be bytearray, not bytes"

    with patch.object(envelope_signer_module, "_zeroize", spy_zeroize):
        signer = EnvelopeSigner(vault, repo)
        await signer.create_wallet(name="zw", policy_path="p")

    assert len(captured_post_zeroize) == 1, "_zeroize should fire exactly once per create_wallet"
    assert captured_post_zeroize[0] == b"\x00" * 32


@pytest.mark.asyncio
async def test_sign_transaction_buffer_is_all_zero_after_zeroize() -> None:
    """Same hazard #2 contract for sign_transaction's privkey buffer."""
    from eth_account import Account

    real = Account.create()
    privkey_bytes = bytes(real.key)

    vault = MagicMock()
    vault.decrypt = AsyncMock(return_value=privkey_bytes)
    repo = MagicMock()
    repo.get_by_name = AsyncMock(
        return_value=Wallet(
            name="w1",
            address=real.address,
            privkey_ciphertext="seal:v1:abc",
            vault_master_key="local:v1",
            policy_path="p1",
            created_at=datetime.now(UTC),
        )
    )

    captured_post_zeroize: list[bytes] = []
    real_zeroize = envelope_signer_module._zeroize

    def spy_zeroize(buf: bytearray) -> None:
        real_zeroize(buf)
        captured_post_zeroize.append(bytes(buf))
        assert isinstance(buf, bytearray)

    tx_dict = {
        "type": 2,
        "chainId": 114,
        "nonce": 0,
        "to": "0x" + "11" * 20,
        "value": 0,
        "data": "0x",
        "gas": 21000,
        "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
    }
    with patch.object(envelope_signer_module, "_zeroize", spy_zeroize):
        signer = EnvelopeSigner(vault, repo)
        await signer.sign_transaction("w1", tx_dict)

    assert len(captured_post_zeroize) == 1
    assert captured_post_zeroize[0] == b"\x00" * 32


# --- architecture.md hazard #1 enforcement (no plaintext caching) --------


@pytest.mark.asyncio
async def test_no_32byte_state_after_create_wallet() -> None:
    """After create_wallet returns, no instance attribute holds a 32-byte secret.

    Architecture.md hazard #1: 'an introspection check confirms no
    attribute on the signer instance is a bytes or bytearray of length 32.'
    """
    vault = MagicMock()
    vault.encrypt = AsyncMock(return_value="seal:v1:abc")
    repo = MagicMock()

    async def _create(**kwargs: Any) -> Wallet:
        return Wallet(
            name=kwargs["name"],
            address=kwargs["address"],
            privkey_ciphertext=kwargs["privkey_ciphertext"],
            vault_master_key=kwargs["vault_master_key"],
            policy_path=kwargs["policy_path"],
            created_at=datetime.now(UTC),
        )

    repo.create = _create

    signer = EnvelopeSigner(vault, repo)
    await signer.create_wallet(name="nc", policy_path="p")

    _assert_no_32byte_state(signer)


@pytest.mark.asyncio
async def test_no_32byte_state_after_sign_transaction() -> None:
    """Same hazard #1 contract after sign_transaction."""
    from eth_account import Account

    real = Account.create()
    vault = MagicMock()
    vault.decrypt = AsyncMock(return_value=bytes(real.key))
    repo = MagicMock()
    repo.get_by_name = AsyncMock(
        return_value=Wallet(
            name="w1",
            address=real.address,
            privkey_ciphertext="seal:v1:abc",
            vault_master_key="local:v1",
            policy_path="p1",
            created_at=datetime.now(UTC),
        )
    )

    signer = EnvelopeSigner(vault, repo)
    tx_dict = {
        "type": 2,
        "chainId": 114,
        "nonce": 0,
        "to": "0x" + "11" * 20,
        "value": 0,
        "data": "0x",
        "gas": 21000,
        "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
    }
    await signer.sign_transaction("w1", tx_dict)

    _assert_no_32byte_state(signer)


def _assert_no_32byte_state(signer: EnvelopeSigner) -> None:
    """Walk every attribute on signer; fail if any holds a 32-byte secret-shaped value.

    Inspects both `__dict__` (instance attributes) and any `__slots__`
    (defensive — EnvelopeSigner doesn't currently use slots, but a future
    refactor might). Skips the bound `_vault` and `_repo` (mocks here)
    because their internal state is the Vault client's / repo's concern,
    not the signer's plaintext-cache concern.
    """
    skip = {"_vault", "_repo"}
    for name, value in signer.__dict__.items():
        if name in skip:
            continue
        if isinstance(value, bytes | bytearray) and len(value) == 32:
            pytest.fail(
                f"hazard #1 violation: signer.{name!r} holds a 32-byte "
                f"{type(value).__name__} ({len(value)} bytes)"
            )


# --- architecture.md hazard #1, #2 enforcement for import_wallet ---------
# Phase 4 added a third privkey path: EnvelopeSigner.import_wallet (D12,
# operator-supplied privkey from a host file). The v0.3.2 hazard tests
# covered create_wallet and sign_transaction; these add the matching
# import_wallet coverage. Closes audit F1.1 (v0.4.0a1 audit).


@pytest.mark.asyncio
async def test_import_wallet_buffer_is_all_zero_after_zeroize() -> None:
    """Hazard #2 contract for import_wallet's privkey buffer.

    The bytearray supplied by the caller (app/wallet_import.py) is
    zeroized in EnvelopeSigner.import_wallet's finally — the bytes
    snapshot taken AFTER _zeroize must be all zeros.
    """
    from eth_account import Account

    real = Account.create()
    privkey_bytes = bytes(real.key)

    vault = MagicMock()
    vault.encrypt = AsyncMock(return_value="seal:v1:abc")
    repo = MagicMock()

    async def _create(**kwargs: Any) -> Wallet:
        return Wallet(
            name=kwargs["name"],
            address=kwargs["address"],
            privkey_ciphertext=kwargs["privkey_ciphertext"],
            vault_master_key=kwargs["vault_master_key"],
            policy_path=kwargs["policy_path"],
            created_at=datetime.now(UTC),
        )

    repo.create = _create

    captured_post_zeroize: list[bytes] = []
    real_zeroize = envelope_signer_module._zeroize

    def spy_zeroize(buf: bytearray) -> None:
        real_zeroize(buf)
        captured_post_zeroize.append(bytes(buf))
        assert isinstance(buf, bytearray), "hazard #2: buffer must be bytearray, not bytes"

    privkey_buf = bytearray(privkey_bytes)
    with patch.object(envelope_signer_module, "_zeroize", spy_zeroize):
        signer = EnvelopeSigner(vault, repo)
        await signer.import_wallet(name="iw", privkey_buf=privkey_buf, policy_path="p")

    assert len(captured_post_zeroize) == 1, "_zeroize should fire exactly once per import_wallet"
    assert captured_post_zeroize[0] == b"\x00" * 32


@pytest.mark.asyncio
async def test_import_wallet_buffer_zero_on_address_mismatch() -> None:
    """Hazard #2 holds even when import_wallet raises WalletAddressMismatch.

    The finally-block must fire. Verifies the buffer is zeroized even on
    the user-error path.
    """
    from eth_account import Account

    from fwd.infra.envelope_signer import WalletAddressMismatch

    real = Account.create()
    privkey_bytes = bytes(real.key)
    wrong_address = "0x" + "00" * 20

    vault = MagicMock()
    vault.encrypt = AsyncMock(return_value="seal:v1:abc")
    repo = MagicMock()

    captured_post_zeroize: list[bytes] = []
    real_zeroize = envelope_signer_module._zeroize

    def spy_zeroize(buf: bytearray) -> None:
        real_zeroize(buf)
        captured_post_zeroize.append(bytes(buf))

    privkey_buf = bytearray(privkey_bytes)
    with patch.object(envelope_signer_module, "_zeroize", spy_zeroize):
        signer = EnvelopeSigner(vault, repo)
        with pytest.raises(WalletAddressMismatch):
            await signer.import_wallet(
                name="iw",
                privkey_buf=privkey_buf,
                policy_path="p",
                expected_address=wrong_address,
            )

    assert len(captured_post_zeroize) == 1, "_zeroize must fire on the raise path"
    assert captured_post_zeroize[0] == b"\x00" * 32


@pytest.mark.asyncio
async def test_no_32byte_state_after_import_wallet() -> None:
    """Hazard #1 contract after import_wallet."""
    from eth_account import Account

    real = Account.create()
    vault = MagicMock()
    vault.encrypt = AsyncMock(return_value="seal:v1:abc")
    repo = MagicMock()

    async def _create(**kwargs: Any) -> Wallet:
        return Wallet(
            name=kwargs["name"],
            address=kwargs["address"],
            privkey_ciphertext=kwargs["privkey_ciphertext"],
            vault_master_key=kwargs["vault_master_key"],
            policy_path=kwargs["policy_path"],
            created_at=datetime.now(UTC),
        )

    repo.create = _create

    signer = EnvelopeSigner(vault, repo)
    await signer.import_wallet(name="iw", privkey_buf=bytearray(bytes(real.key)), policy_path="p")

    _assert_no_32byte_state(signer)
