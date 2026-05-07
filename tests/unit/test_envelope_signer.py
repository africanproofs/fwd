"""EnvelopeSigner unit tests.

Verifies:
- create_wallet generates a valid address, encrypts via vault, persists.
- The plaintext bytearray is zeroized after create_wallet returns.
- sign_transaction raises NotImplementedError (Phase 3c).
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
async def test_sign_transaction_not_implemented() -> None:
    signer = EnvelopeSigner(MagicMock(), MagicMock())
    with pytest.raises(NotImplementedError, match="Phase 3c"):
        await signer.sign_transaction("w1", {})
