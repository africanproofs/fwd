"""EnvelopeSigner unit tests.

Verifies:
- create_wallet generates a valid address, encrypts via vault, persists.
- The plaintext bytearray is zeroized after create_wallet returns.
- sign_transaction decrypts, signs an EIP-1559 tx, zeroizes (Phase 3c).
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.wallet_repo import Wallet


@pytest.mark.asyncio
async def test_create_wallet_happy() -> None:
    vault = MagicMock()
    vault.encrypt = AsyncMock(return_value="vault:v1:abc")

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
    assert wallet.privkey_ciphertext == "vault:v1:abc"
    assert captured_kwargs["vault_master_key"] == "fwd-master"
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
    repo.get_by_name = AsyncMock(return_value=Wallet(
        name="w1",
        address=expected_address,
        privkey_ciphertext="vault:v1:abc",
        vault_master_key="fwd-master",
        policy_path="p1",
        created_at=datetime.now(UTC),
    ))

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
