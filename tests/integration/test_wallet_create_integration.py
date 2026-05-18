"""End-to-end wallet-create using the sealed local master (v1.0.0a1).

The test:
  1. Migrates the wallets table into a tmp SQLite.
  2. Constructs a SealedMaster over a tmp 0600 master-key file.
  3. Calls EnvelopeSigner.create_wallet(name=..., policy_path=...).
  4. Asserts the returned address is a valid checksum address.
  5. Asserts a row exists in wallets with privkey_ciphertext starting "seal:v1:".
  6. Decrypts the ciphertext via SealedMaster.decrypt, asserts result is 32 bytes.
  7. Re-derives the address from the decrypted privkey, asserts it matches step 4.
"""

from __future__ import annotations

import os
from pathlib import Path  # noqa: TC003

import pytest
from eth_account import Account
from eth_utils import to_checksum_address  # type: ignore[attr-defined]
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd import settings as settings_mod
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.sealed_master import SealedMaster
from fwd.infra.wallet_repo import WalletRepo, metadata


@pytest.mark.asyncio
async def test_create_then_decrypt_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Set up a temporary 0600 master key file.
    key_file = tmp_path / "master.key"
    key_file.write_bytes(os.urandom(32))
    os.chmod(key_file, 0o600)
    monkeypatch.setenv("FWD_MASTER_KEY_FILE", str(key_file))
    settings_mod.get_settings.cache_clear()

    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)

    async with SealedMaster() as master, AsyncSession(engine) as session:
        repo = WalletRepo(session)
        signer = EnvelopeSigner(master, repo)
        wallet = await signer.create_wallet(name="integ-test", policy_path="integ-test")
        await session.commit()

        # Re-fetch from DB to confirm it landed.
        got = await repo.get_by_name("integ-test")
        assert got is not None
        assert got.privkey_ciphertext.startswith("seal:v1:")
        assert got.vault_master_key == "local:v1"

        # Decrypt round-trip.
        plaintext = await master.decrypt(got.privkey_ciphertext)
        assert len(plaintext) == 32

        # Re-derive address from decrypted privkey, must match.
        derived = to_checksum_address(Account.from_key(plaintext).address)
        assert derived == wallet.address

    await engine.dispose()
