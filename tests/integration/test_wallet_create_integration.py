"""End-to-end wallet-create against the live dev Vault.

Skipped automatically if VAULT_ADDR isn't reachable (see conftest.py).
The test:
  1. Migrates the wallets table into a tmp SQLite.
  2. Reads FWD_VAULT_ROLE_ID + FWD_VAULT_SECRET_ID from .env-injected env.
  3. Calls EnvelopeSigner.create_wallet(name=..., policy_path=...).
  4. Asserts the returned address is a valid checksum address.
  5. Asserts a row exists in wallets with privkey_ciphertext starting "vault:v1:".
  6. Decrypts the ciphertext via VaultClient.decrypt, asserts result is 32 bytes.
  7. Re-derives the address from the decrypted privkey, asserts it matches step 4.
"""

from __future__ import annotations

import os
from pathlib import Path  # noqa: TC003

import pytest  # noqa: TC002
from eth_account import Account
from eth_utils import to_checksum_address  # type: ignore[attr-defined]
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd import settings as settings_mod
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.vault_client import VaultClient
from fwd.infra.wallet_repo import WalletRepo, metadata
from tests.conftest import needs_vault


@needs_vault
@pytest.mark.asyncio
async def test_create_then_decrypt_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not os.environ.get("FWD_VAULT_ROLE_ID") or not os.environ.get("FWD_VAULT_SECRET_ID"):
        pytest.skip(
            "FWD_VAULT_ROLE_ID/FWD_VAULT_SECRET_ID not in env (run inside compose or set manually)"
        )

    # Vault is on fwd-internal only (not published to host). Running from the
    # host requires VAULT_ADDR pointing at a published port. If unreachable,
    # needs_vault will have already skipped this test.
    monkeypatch.setenv("VAULT_ADDR", os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"))
    settings_mod.get_settings.cache_clear()

    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)

    async with VaultClient() as vault, AsyncSession(engine) as session:
        repo = WalletRepo(session)
        signer = EnvelopeSigner(vault, repo)
        wallet = await signer.create_wallet(name="integ-test", policy_path="integ-test")
        await session.commit()

        # Re-fetch from DB to confirm it landed.
        got = await repo.get_by_name("integ-test")
        assert got is not None
        assert got.privkey_ciphertext.startswith("vault:v1:")
        assert got.vault_master_key == "fwd-master"

        # Decrypt round-trip.
        plaintext = await vault.decrypt(got.privkey_ciphertext)
        assert len(plaintext) == 32

        # Re-derive address from decrypted privkey, must match.
        derived = to_checksum_address(Account.from_key(plaintext).address)
        assert derived == wallet.address

    await engine.dispose()
