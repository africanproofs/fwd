"""End-to-end sign-transaction: real SealedMaster, NO RPC (v1.1.0a9 zero-egress).

fwd is now sign-only. This test verifies:
- Wallet creation (encrypt) lands a ciphertext in SQLite.
- sign_transaction decrypts via real SealedMaster, signs in-process,
  returns signed_raw_tx (hex) for the client to broadcast.
- The signed tx recovers to the wallet's address (eth_account sanity).
- A transaction row is persisted with status="pending" (not "submitted").
- tx_id is a valid UUIDv7.
- No RPC is called anywhere in the path.

Previously: mock-RPC broadcast was tested here; removed at v1.1.0a9.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import eth_abi
import pytest
from eth_account import Account
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd import settings as settings_mod
from fwd.app.sign_transaction import SignTransactionRequest, sign_transaction
from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.audit_repo import AuditRepo, audit_metadata
from fwd.infra.caller_repo import Caller
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.nonce_repo import metadata as nonces_metadata
from fwd.infra.rate_repo import RateRepo, rate_metadata
from fwd.infra.sealed_master import SealedMaster
from fwd.infra.transaction_repo import TransactionRepo
from fwd.infra.transaction_repo import metadata as tx_metadata
from fwd.infra.wallet_repo import WalletRepo
from fwd.infra.wallet_repo import metadata as wallets_metadata

_ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

# ERC-20 contract address used in the integration test (lowercase).
_ERC20_CONTRACT = "0x" + "11" * 20
_TRANSFER_SELECTOR = "0xa9059cbb"
_RECIPIENT = "0x" + "22" * 20
_CHAIN_ID = 114


def _transfer_calldata(to: str = _RECIPIENT, amount: int = 0) -> str:
    """Return 0x-prefixed calldata for ERC20 transfer(address,uint256)."""
    encoded = eth_abi.encode(["address", "uint256"], [to, amount])
    raw = bytes.fromhex(_TRANSFER_SELECTOR[2:]) + encoded
    return "0x" + raw.hex()


def _make_integ_policy(wallet_name: str, caller_name: str) -> Policy:
    """Minimal permissive policy for integration testing (no rate limits)."""
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
                            "chains": [_CHAIN_ID],
                            "methods": {
                                "transfer(address,uint256)": {
                                    "max_value_wei": "0",
                                }
                            },
                        }
                    },
                    "wallet_allowlist": [wallet_name],
                    "rate": {"per_hour": 100, "per_day": 1000},
                }
            },
            "wallet_constraints": {
                "wc/integ": {},
            },
        }
    )


@pytest.mark.asyncio
async def test_sign_transaction_real_master_no_rpc(
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
        await conn.run_sync(wallets_metadata.create_all)
        await conn.run_sync(nonces_metadata.create_all)
        await conn.run_sync(tx_metadata.create_all)
        await conn.run_sync(rate_metadata.create_all)
        await conn.run_sync(audit_metadata.create_all)

    # Load the real ABI registry.
    registry = AbiRegistry.load(_ABIS_DIR)

    async with SealedMaster() as master, AsyncSession(engine) as session:
        repo = WalletRepo(session)
        signer = EnvelopeSigner(master, repo)
        tx_repo = TransactionRepo(session)
        nonce_repo = NonceRepo(session)
        rate_repo = RateRepo(session)
        audit_repo = AuditRepo(session)

        # 1. Create a wallet via real SealedMaster.
        wallet = await signer.create_wallet(name="integ-sign-test", policy_path="perm/integ")
        await session.commit()

        # 2. Seed the nonce manually (zero-egress: fwd cannot call the chain).
        await nonce_repo.init_for_wallet("integ-sign-test", _CHAIN_ID, 0)
        await session.commit()

        # 3. Build policy + Caller.
        policy = _make_integ_policy("integ-sign-test", "integration-test-caller")
        from datetime import UTC, datetime

        integ_caller = Caller(
            name="integration-test-caller",
            api_key_hash="h",
            api_key_prefix="p",
            policy_path="perm/integ",
            created_at=datetime.now(UTC),
            revoked_at=None,
        )

        # 4. sign_transaction — no RPC, client-supplied gas + fee params.
        request = SignTransactionRequest(
            wallet="integ-sign-test",
            caller="integration-test-caller",
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
            caller=integ_caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )

        assert result.nonce == 0
        assert result.hash.startswith("0x")
        assert result.signed_raw_tx.startswith("0x")

        # 5. Verify tx_id is a valid UUIDv7.
        assert len(result.tx_id) == 36
        assert uuid.UUID(result.tx_id).version == 7

        # 6. Round-trip: decode the signed raw tx, recover sender, must match wallet.address.
        raw_bytes = bytes.fromhex(result.signed_raw_tx[2:])
        recovered = Account.recover_transaction(raw_bytes)
        assert recovered.lower() == wallet.address.lower()

        # 7. Verify the transaction row was persisted with status="pending".
        await session.commit()
        tx = await tx_repo.get_by_id(result.tx_id)
        assert tx is not None
        assert tx.status == "pending"  # NOT "submitted" — zero-egress
        assert tx.wallet == "integ-sign-test"
        assert tx.caller == "integration-test-caller"
        assert tx.chain == _CHAIN_ID

        # 8. Verify the transaction_hash row was persisted.
        hashes = await tx_repo.list_hashes_by_tx(result.tx_id)
        assert len(hashes) == 1
        assert hashes[0].sequence_num == 1
        assert hashes[0].hash_hex == result.hash

    await engine.dispose()
