"""End-to-end Phase 4 caller-auth: real SealedMaster + real argon2id (v1.1.0a9).

The test exercises the full Phase 4 flow with real cryptographic primitives:
  - generate_api_key produces an actual base64url token + argon2id hash.
  - CallerRepo.create persists the hash + prefix to a real (tmp) SQLite.
  - resolve_caller round-trips: prefix lookup -> argon2id verify -> match.
  - sign_transaction uses the resolved Caller's policy_path.
  - Real SealedMaster encrypts the wallet privkey; real SealedMaster decrypts
    at sign time; NO RPC (zero-egress, v1.1.0a9).

v1.1.0a9 update: sign_and_send → sign_transaction (zero-egress). No mock RPC.
Client-supplied gas + fee params. status="pending" in tx row.

Verifies:
  - The Phase 4 Caller object is correctly constructed and persisted.
  - resolve_caller(generated.key) returns the active Caller.
  - resolve_caller after revoke() returns None.
  - resolve_caller with a forged key returns None even with prefix match.
  - sign_transaction is callable end-to-end with the resolved caller in
    request context (verifies the full auth + policy + signing path).
  - signed_raw_tx recovers to the wallet's address via eth_account.

Per D11, this test does NOT exercise admin auth — admin auth is unit-
tested in test_admin_caller_bright_line.py. This integration is the
caller-side companion.
"""

from __future__ import annotations

import os
from pathlib import Path

import eth_abi
import pytest
from eth_account import Account
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd import settings as settings_mod
from fwd.app.caller_resolution import resolve_caller
from fwd.app.sign_transaction import SignTransactionRequest, sign_transaction
from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.api_key import generate_api_key
from fwd.infra.audit_repo import AuditRepo, audit_metadata
from fwd.infra.caller_repo import CallerRepo
from fwd.infra.caller_repo import metadata as caller_metadata
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.nonce_repo import metadata as nonce_metadata
from fwd.infra.rate_repo import RateRepo, rate_metadata
from fwd.infra.sealed_master import SealedMaster
from fwd.infra.transaction_repo import TransactionRepo
from fwd.infra.transaction_repo import metadata as transaction_metadata
from fwd.infra.wallet_repo import WalletRepo
from fwd.infra.wallet_repo import metadata as wallet_metadata

_ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

# ERC-20 contract address the policy permits (lowercase).
_ERC20_CONTRACT = "0x" + "22" * 20
# ERC-20 transfer(address,uint256) selector.
_TRANSFER_SELECTOR = "0xa9059cbb"
# Recipient for the test transfer.
_RECIPIENT = "0x" + "33" * 20
_CHAIN_ID = 114


def _transfer_calldata(to: str = _RECIPIENT, amount: int = 0) -> str:
    """Return 0x-prefixed calldata for ERC20 transfer(address,uint256)."""
    encoded = eth_abi.encode(["address", "uint256"], [to, amount])
    raw = bytes.fromhex(_TRANSFER_SELECTOR[2:]) + encoded
    return "0x" + raw.hex()


def _make_integ_policy(wallet_name: str, caller_name: str) -> Policy:
    """Minimal permissive policy for integration testing."""
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {
                caller_name: {"policy_path": "perm/integ"},
            },
            "wallets": {
                wallet_name: {"policy_path": "wc/integ"},
            },
            "permissions": {
                "perm/integ": {
                    "contracts": {
                        _ERC20_CONTRACT: {
                            "abi": "erc20",
                            "methods": {
                                "transfer(address,uint256)": {
                                    "max_value_wei": "0",
                                }
                            },
                        }
                    },
                    "wallet_allowlist": [wallet_name],
                }
            },
            "wallet_constraints": {
                "wc/integ": {},
            },
        }
    )


@pytest.mark.asyncio
async def test_caller_create_resolve_and_sign_e2e(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Full Phase 4 round-trip: argon2id + real SealedMaster, zero-egress."""
    # Set up a temporary 0600 master key file.
    key_file = tmp_path / "master.key"
    key_file.write_bytes(os.urandom(32))
    os.chmod(key_file, 0o600)
    monkeypatch.setenv("FWD_MASTER_KEY_FILE", str(key_file))
    settings_mod.get_settings.cache_clear()

    # Build a single tmp DB with all tables.
    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(wallet_metadata.create_all)
        await conn.run_sync(caller_metadata.create_all)
        await conn.run_sync(nonce_metadata.create_all)
        await conn.run_sync(transaction_metadata.create_all)
        await conn.run_sync(rate_metadata.create_all)
        await conn.run_sync(audit_metadata.create_all)

    # Load the real ABI registry (config/abis/).
    registry = AbiRegistry.load(_ABIS_DIR)

    async with SealedMaster() as master, AsyncSession(engine) as session:
        wallet_repo = WalletRepo(session)
        caller_repo = CallerRepo(session)
        tx_repo = TransactionRepo(session)
        nonce_repo = NonceRepo(session)
        rate_repo = RateRepo(session)
        audit_repo = AuditRepo(session)
        signer = EnvelopeSigner(master, wallet_repo)

        # 1. Real argon2id key generation.
        generated = generate_api_key()
        assert generated.key.startswith("fwd_live_")
        assert len(generated.key) == 52  # fwd_live_(9) + 43 random

        # 2. Persist the caller with the real hash + prefix.
        caller = await caller_repo.create(
            name="integ-caller-test",
            api_key_hash=generated.key_hash,
            api_key_prefix=generated.key_prefix,
            policy_path="perm/integ",
        )
        await session.commit()
        # Sanity: the persisted Caller carries the same hash + prefix.
        assert caller.name == "integ-caller-test"
        assert caller.api_key_prefix == generated.key_prefix
        assert caller.api_key_hash == generated.key_hash

        # 3. Resolve the caller from the bearer token via real argon2id verify.
        resolved = await resolve_caller(generated.key, caller_repo)
        assert resolved is not None, "argon2id round-trip failed"
        assert resolved.name == "integ-caller-test"
        assert resolved.policy_path == "perm/integ"
        assert resolved.api_key_prefix == generated.key_prefix

        # 4. Forged key with the same prefix -> resolve returns None.
        forged_key = "fwd_live_" + generated.key_prefix + ("x" * (43 - len(generated.key_prefix)))
        forged_resolved = await resolve_caller(forged_key, caller_repo)
        assert forged_resolved is None, "argon2id false-positive: forged key resolved"

        # 5. Malformed key -> resolve returns None.
        assert await resolve_caller("not-a-key", caller_repo) is None
        assert await resolve_caller("fwd_live_short", caller_repo) is None

        # 6. Create a wallet via the real SealedMaster path (Phase 3b).
        wallet = await signer.create_wallet(name="integ-caller-wallet", policy_path="perm/integ")
        await session.commit()

        # 7. Seed nonce for the wallet (zero-egress: fwd cannot call the chain).
        await nonce_repo.init_for_wallet("integ-caller-wallet", _CHAIN_ID, 0)
        await session.commit()

        # 8. Build policy.
        policy = _make_integ_policy("integ-caller-wallet", "integ-caller-test")

        # 9. sign_transaction — zero-egress; real SealedMaster decrypt + sign.
        request = SignTransactionRequest(
            wallet="integ-caller-wallet",
            caller=resolved.name,
            chain=_CHAIN_ID,
            to=_ERC20_CONTRACT,
            value_wei="0",
            data=_transfer_calldata(),
            gas=21_000,
            max_fee_per_gas=3_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
        )
        result = await sign_transaction(
            request,
            signer,
            tx_repo,
            nonce_repo,
            caller=resolved,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )

        assert result.nonce == 0
        assert result.hash.startswith("0x")
        assert result.signed_raw_tx.startswith("0x")

        # 10. Round-trip: signed raw tx must recover to the wallet's address.
        raw_bytes = bytes.fromhex(result.signed_raw_tx[2:])
        recovered = Account.recover_transaction(raw_bytes)
        assert recovered.lower() == wallet.address.lower()

        # 11. Revoke the caller; resolve returns None.
        await caller_repo.revoke("integ-caller-test")
        await session.commit()
        revoked_resolution = await resolve_caller(generated.key, caller_repo)
        assert revoked_resolution is None, "revoked caller still resolves"

    await engine.dispose()
