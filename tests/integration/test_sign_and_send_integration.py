"""End-to-end sign-and-send: real Vault + mock RPC.

Skipped when dev Vault unreachable (per tests/conftest.py::needs_vault).
The test mocks only the RPC layer; the Vault round-trip (encrypt at
wallet creation, decrypt at sign) goes through the live dev Vault.

Verifies:
- Wallet creation (encrypt) lands a ciphertext in SQLite.
- sign_and_send decrypts via real Vault, signs in-process, broadcasts to
  the mock RPC.
- The signed tx recovers to the wallet's address.
- A transaction row is persisted (tx_id returned in result).
- GET /v1/transactions/{tx_id} (via repo) returns the expected row shape.
"""

from __future__ import annotations

import json as _json
import os
import uuid
from pathlib import Path  # noqa: TC003

import httpx
import pytest
from eth_account import Account
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd import settings as settings_mod
from fwd.app.sign_and_send import SignAndSendRequest, sign_and_send
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.rpc import RpcClient
from fwd.infra.transaction_repo import TransactionRepo
from fwd.infra.transaction_repo import metadata as tx_metadata
from fwd.infra.vault_client import VaultClient
from fwd.infra.wallet_repo import WalletRepo
from fwd.infra.wallet_repo import metadata as wallets_metadata
from tests.conftest import needs_vault


def _mock_rpc_handler(chain_id: int = 114, nonce: int = 0):  # type: ignore[no-untyped-def]
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
                    "result": "0x" + "ab" * 32,
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
async def test_sign_and_send_real_vault_mock_rpc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not os.environ.get("FWD_VAULT_ROLE_ID") or not os.environ.get("FWD_VAULT_SECRET_ID"):
        pytest.skip("FWD_VAULT_ROLE_ID/SECRET_ID not in env")

    monkeypatch.setenv("VAULT_ADDR", os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"))
    settings_mod.get_settings.cache_clear()

    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(wallets_metadata.create_all)
        await conn.run_sync(tx_metadata.create_all)

    handler, captured = _mock_rpc_handler(chain_id=114, nonce=0)
    mock_http = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async with VaultClient() as vault, AsyncSession(engine) as session:
        repo = WalletRepo(session)
        signer = EnvelopeSigner(vault, repo)
        tx_repo = TransactionRepo(session)

        # 1. Create a wallet against real Vault.
        wallet = await signer.create_wallet(name="integ-sign-test", policy_path="integ-sign")
        await session.commit()

        # 2. Build an RpcClient using the mock transport.
        rpc = RpcClient(114, "http://mock-rpc", mock_http)

        # 3. sign_and_send.
        request = SignAndSendRequest(
            wallet="integ-sign-test",
            caller="integration-test-caller",
            chain=114,
            to="0x" + "11" * 20,
            value_wei="0",
            data="0x",
            gas=21000,
        )
        result = await sign_and_send(request, signer, rpc, tx_repo)

        assert result.hash == "0x" + "ab" * 32
        assert result.nonce == 0
        assert "raw_tx_hex" in captured

        # 4. Verify tx_id is a valid UUIDv7.
        assert len(result.tx_id) == 36
        assert uuid.UUID(result.tx_id).version == 7

        # 5. Round-trip: decode the signed raw tx, recover sender, must match wallet.address.
        raw_bytes = bytes.fromhex(captured["raw_tx_hex"][2:])
        recovered = Account.recover_transaction(raw_bytes)
        assert recovered.lower() == wallet.address.lower()

        # 6. Verify the transaction row was persisted.
        await session.commit()
        tx = await tx_repo.get_by_id(result.tx_id)
        assert tx is not None
        assert tx.status == "submitted"
        assert tx.wallet == "integ-sign-test"
        assert tx.caller == "integration-test-caller"
        assert tx.chain == 114

        # 7. Verify the transaction_hash row was persisted.
        hashes = await tx_repo.list_hashes_by_tx(result.tx_id)
        assert len(hashes) == 1
        assert hashes[0].sequence_num == 1
        assert hashes[0].hash_hex == "0x" + "ab" * 32

    await mock_http.aclose()
    await engine.dispose()
