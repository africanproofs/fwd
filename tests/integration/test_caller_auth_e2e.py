"""End-to-end Phase 4 caller-auth: real Vault + real argon2id + mock RPC.

Skipped when dev Vault unreachable (per tests/conftest.py::needs_vault).
The test exercises the full Phase 4 flow with real cryptographic
primitives:
  - generate_api_key produces an actual base64url token + argon2id hash.
  - CallerRepo.create persists the hash + prefix to a real (tmp) SQLite.
  - resolve_caller round-trips: prefix lookup → argon2id verify → match.
  - sign_and_send uses the resolved Caller's policy_path (stored only;
    enforcement is Phase 7 per D13).
  - Real Vault encrypts the wallet privkey; real Vault decrypts at sign
    time; mock RPC accepts the broadcast.

Verifies:
  - The Phase 4 Caller object is correctly constructed and persisted.
  - resolve_caller(generated.key) returns the active Caller.
  - resolve_caller after revoke() returns None.
  - resolve_caller with a forged key returns None even with prefix match.
  - sign_and_send is callable end-to-end with the resolved caller in
    request context (verifies the full auth + signing path lights up).

Per D11, this test does NOT exercise admin auth — admin auth is unit-
tested in test_admin_caller_bright_line.py. This integration is the
caller-side companion.
"""

from __future__ import annotations

import json as _json
import os
from pathlib import Path  # noqa: TC003

import httpx
import pytest
from eth_account import Account
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd import settings as settings_mod
from fwd.app.caller_resolution import resolve_caller
from fwd.app.sign_and_send import SignAndSendRequest, sign_and_send
from fwd.infra.api_key import generate_api_key
from fwd.infra.caller_repo import CallerRepo
from fwd.infra.caller_repo import metadata as caller_metadata
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.nonce_repo import metadata as nonce_metadata
from fwd.infra.rpc import RpcClient
from fwd.infra.transaction_repo import TransactionRepo
from fwd.infra.transaction_repo import metadata as transaction_metadata
from fwd.infra.vault_client import VaultClient
from fwd.infra.wallet_repo import WalletRepo
from fwd.infra.wallet_repo import metadata as wallet_metadata
from tests.conftest import needs_vault


def _mock_rpc_handler(chain_id: int = 114, nonce: int = 0):  # type: ignore[no-untyped-def]
    """Same mock RPC pattern as test_sign_and_send_integration.py."""
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read()
        rpc_call = _json.loads(body)
        method = rpc_call["method"]
        if method == "eth_chainId":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": rpc_call["id"], "result": hex(chain_id)}
            )
        if method == "eth_getTransactionCount":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": rpc_call["id"], "result": hex(nonce)}
            )
        if method == "eth_feeHistory":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": rpc_call["id"],
                    "result": {
                        "baseFeePerGas": [hex(1_000_000_000)] * 6,
                        "gasUsedRatio": [0.5] * 5,
                    },
                },
            )
        if method == "eth_estimateGas":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": rpc_call["id"], "result": hex(21000)}
            )
        if method == "eth_sendRawTransaction":
            captured["raw_tx_hex"] = rpc_call["params"][0]
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": rpc_call["id"],
                    "result": "0x" + "cd" * 32,  # distinguishable from sign_and_send_integration
                },
            )
        return httpx.Response(
            500,
            json={
                "jsonrpc": "2.0",
                "id": rpc_call["id"],
                "error": {"code": -32601, "message": "not handled"},
            },
        )

    return handler, captured


@needs_vault
@pytest.mark.asyncio
async def test_caller_create_resolve_and_sign_e2e(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Full Phase 4 round-trip: argon2id + real Vault + mock RPC."""
    if not os.environ.get("FWD_VAULT_ROLE_ID") or not os.environ.get("FWD_VAULT_SECRET_ID"):
        pytest.skip("FWD_VAULT_ROLE_ID/SECRET_ID not in env")

    monkeypatch.setenv("VAULT_ADDR", os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"))
    settings_mod.get_settings.cache_clear()

    # Build a single tmp DB with all tables (callers + wallets + nonces + transactions).
    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(wallet_metadata.create_all)
        await conn.run_sync(caller_metadata.create_all)
        await conn.run_sync(nonce_metadata.create_all)
        await conn.run_sync(transaction_metadata.create_all)

    handler, captured = _mock_rpc_handler(chain_id=114, nonce=0)
    mock_http = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async with VaultClient() as vault, AsyncSession(engine) as session:
        wallet_repo = WalletRepo(session)
        caller_repo = CallerRepo(session)
        tx_repo = TransactionRepo(session)
        nonce_repo = NonceRepo(session)
        signer = EnvelopeSigner(vault, wallet_repo)

        # 1. Real argon2id key generation.
        generated = generate_api_key()
        assert generated.key.startswith("fwd_live_")
        assert len(generated.key) == 52  # fwd_live_(9) + 43 random

        # 2. Persist the caller with the real hash + prefix.
        caller = await caller_repo.create(
            name="integ-caller-test",
            api_key_hash=generated.key_hash,
            api_key_prefix=generated.key_prefix,
            policy_path="integ-caller-policy",
        )
        await session.commit()
        # Sanity: the persisted Caller carries the same hash + prefix we just
        # generated. (Closes audit F6.1: this previously was an unused assignment.)
        assert caller.name == "integ-caller-test"
        assert caller.api_key_prefix == generated.key_prefix
        assert caller.api_key_hash == generated.key_hash

        # 3. Resolve the caller from the bearer token via real argon2id verify.
        resolved = await resolve_caller(generated.key, caller_repo)
        assert resolved is not None, "argon2id round-trip failed"
        assert resolved.name == "integ-caller-test"
        assert resolved.policy_path == "integ-caller-policy"
        assert resolved.api_key_prefix == generated.key_prefix

        # 4. Forged key with the same prefix → resolve returns None.
        forged_key = "fwd_live_" + generated.key_prefix + ("x" * (43 - len(generated.key_prefix)))
        forged_resolved = await resolve_caller(forged_key, caller_repo)
        assert forged_resolved is None, "argon2id false-positive: forged key resolved"

        # 5. Malformed key → resolve returns None.
        assert await resolve_caller("not-a-key", caller_repo) is None
        assert await resolve_caller("fwd_live_short", caller_repo) is None

        # 6. Create a wallet via the real Vault path (Phase 3b).
        wallet = await signer.create_wallet(
            name="integ-caller-wallet", policy_path="integ-caller-policy"
        )
        await session.commit()

        # 7. Build an RpcClient using the mock transport.
        rpc = RpcClient(114, "http://mock-rpc", mock_http)

        # 8. sign_and_send through the real signer (decrypt via real Vault) and
        #    mock RPC. The resolved caller's policy_path is what would be used
        #    by Phase 7's policy engine; in Phase 4 it's stored, not enforced.
        #    (v0.4.0a3 added the explicit caller field per F8.1; v0.4.0a3 +
        #    v0.4.0a5 added the tx_repo + nonce_repo args.)
        request = SignAndSendRequest(
            wallet="integ-caller-wallet",
            caller=resolved.name,
            chain=114,
            to="0x" + "22" * 20,
            value_wei="0",
            data="0x",
            gas=21000,
        )
        result = await sign_and_send(request, signer, rpc, tx_repo, nonce_repo)

        assert result.hash == "0x" + "cd" * 32
        assert result.nonce == 0
        assert "raw_tx_hex" in captured

        # 9. Round-trip: signed raw tx must recover to the wallet's address.
        raw_bytes = bytes.fromhex(captured["raw_tx_hex"][2:])
        recovered = Account.recover_transaction(raw_bytes)
        assert recovered.lower() == wallet.address.lower()

        # 10. Revoke the caller; resolve returns None.
        await caller_repo.revoke("integ-caller-test")
        await session.commit()
        revoked_resolution = await resolve_caller(generated.key, caller_repo)
        assert revoked_resolution is None, "revoked caller still resolves"

    await mock_http.aclose()
    await engine.dispose()
