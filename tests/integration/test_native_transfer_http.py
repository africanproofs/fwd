"""Real-ASGI integration: POST /v1/sign-transaction over a native_transfers policy.

Mirrors tests/integration/test_fsp_chain_id_gate_http.py's shape (a real
FastAPI TestClient hitting the actual route so the SignTransactionBody API
model validator, the policy gate, and the signing path all run for real) —
but exercises the NEW native-transfer branch instead of an FSP message.

Proves:
  - A bound native_transfers caller POSTing to a whitelisted recipient with
    empty data gets 200 + a signed_raw_tx whose decoded `to`/`value`/`data`
    match the request.
  - The same caller POSTing to an off-allowlist recipient gets 403
    policy_denied.
  - An audit row records the native-transfer intent (to + value_wei).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest  # noqa: TC002
from eth_account.typed_transactions import TypedTransaction
from hexbytes import HexBytes

if TYPE_CHECKING:
    from collections.abc import Coroutine


def _run(coro: Coroutine):  # type: ignore[type-arg]
    """Run a coroutine on a fresh loop, then RESTORE a current loop.

    `asyncio.run` clears the thread's current event loop on exit
    (`set_event_loop(None)`), which pollutes any later test that calls the
    deprecated `asyncio.get_event_loop()`. Restoring a fresh loop keeps this
    sync test from leaking loop state across the suite.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())

_ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"
_CHAIN_ID = 14  # Flare
_ALLOWED_RECIPIENT = "0x" + "44" * 20
_OFF_ALLOWLIST_RECIPIENT = "0x" + "55" * 20
_MAX_VALUE_WEI = "400000000000000000000"
_VALUE_WEI = "1000000000000000000"  # 1 FLR — well under the cap

_POLICY_YAML = f"""\
version: 1

callers:
  funding-caller:
    policy_path: perm/funding-flare

wallets:
  funding-wallet:
    policy_path: wc/funding

permissions: {{}}

native_transfers:
  perm/funding-flare:
    chains: [{_CHAIN_ID}]
    recipient_allowlist:
      - "{_ALLOWED_RECIPIENT}"
    max_value_wei: "{_MAX_VALUE_WEI}"
    wallet_allowlist:
      - funding-wallet
    rate:
      per_hour: 100
      per_day: 1000

wallet_constraints:
  wc/funding: {{}}
"""


async def _seed(db_url: str) -> str:
    """Create tables, mint the funding caller, create + nonce-init the wallet.

    Returns the minted bearer token.
    """
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

    from fwd.infra.api_key import generate_api_key
    from fwd.infra.audit_repo import audit_metadata
    from fwd.infra.caller_repo import CallerRepo
    from fwd.infra.caller_repo import metadata as caller_metadata
    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.nonce_repo import NonceRepo
    from fwd.infra.nonce_repo import metadata as nonce_metadata
    from fwd.infra.rate_repo import rate_metadata
    from fwd.infra.sealed_master import SealedMaster
    from fwd.infra.transaction_repo import metadata as tx_metadata
    from fwd.infra.wallet_repo import WalletRepo
    from fwd.infra.wallet_repo import metadata as wallet_metadata

    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(wallet_metadata.create_all)
        await conn.run_sync(caller_metadata.create_all)
        await conn.run_sync(nonce_metadata.create_all)
        await conn.run_sync(tx_metadata.create_all)
        await conn.run_sync(rate_metadata.create_all)
        await conn.run_sync(audit_metadata.create_all)

    token = ""
    async with SealedMaster() as master, AsyncSession(engine) as session:
        caller_repo = CallerRepo(session)
        signer = EnvelopeSigner(master, WalletRepo(session))
        nonce_repo = NonceRepo(session)

        gen = generate_api_key()
        await caller_repo.create(
            name="funding-caller",
            api_key_hash=gen.key_hash,
            api_key_prefix=gen.key_prefix,
            policy_path="perm/funding-flare",
        )
        token = gen.key

        await signer.create_wallet(name="funding-wallet", policy_path="wc/funding")
        await session.commit()
        await nonce_repo.init_for_wallet("funding-wallet", _CHAIN_ID, 0)
        await session.commit()

    await engine.dispose()
    return token


def test_native_transfer_allow_then_deny_off_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_state_db: Path,
) -> None:
    key_file = tmp_path / "master.key"
    key_file.write_bytes(os.urandom(32))
    os.chmod(key_file, 0o600)
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_POLICY_YAML)

    monkeypatch.setenv("FWD_DISABLE_MLOCK", "1")
    monkeypatch.setenv("FWD_MASTER_KEY_FILE", str(key_file))
    monkeypatch.setenv("FWD_POLICY_PATH", str(policy_file))
    monkeypatch.setenv("FWD_ABIS_DIR", str(_ABIS_DIR))
    monkeypatch.setenv("FWD_WATCHER_DISABLED", "1")

    from fwd import settings as settings_mod
    from fwd.infra import db as db_mod

    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()

    db_url = f"sqlite+aiosqlite:///{tmp_state_db}"
    token = _run(_seed(db_url))

    # Caches were warmed by the seed engine; clear so the app builds its own.
    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()

    from fastapi.testclient import TestClient

    from fwd.main import app

    auth = {"Authorization": f"Bearer {token}"}

    with TestClient(app, raise_server_exceptions=True) as client:
        # --- allow: whitelisted recipient, empty data -> 200 + signed_raw_tx ---
        r = client.post(
            "/v1/sign-transaction",
            headers=auth,
            json={
                "wallet": "funding-wallet",
                "chain": _CHAIN_ID,
                "to": _ALLOWED_RECIPIENT,
                "value_wei": _VALUE_WEI,
                "data": "0x",
                "gas": 21_000,
                "max_fee_per_gas": 3_000_000_000,
                "max_priority_fee_per_gas": 1_000_000_000,
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["signed_raw_tx"].startswith("0x")

        raw_bytes = HexBytes(body["signed_raw_tx"])
        decoded = TypedTransaction.from_bytes(raw_bytes).as_dict()
        assert HexBytes(decoded["to"]).to_0x_hex().lower() == _ALLOWED_RECIPIENT.lower()
        assert decoded["value"] == int(_VALUE_WEI)
        assert HexBytes(decoded["data"]) == HexBytes("0x")

        # --- deny: off-allowlist recipient -> 403 policy_denied ---
        r2 = client.post(
            "/v1/sign-transaction",
            headers=auth,
            json={
                "wallet": "funding-wallet",
                "chain": _CHAIN_ID,
                "to": _OFF_ALLOWLIST_RECIPIENT,
                "value_wei": _VALUE_WEI,
                "data": "0x",
                "gas": 21_000,
                "max_fee_per_gas": 3_000_000_000,
                "max_priority_fee_per_gas": 1_000_000_000,
            },
        )
        assert r2.status_code == 403, r2.text
        assert r2.json()["detail"]["error"] == "policy_denied"

        # --- audit: the approved sign-transaction row records the native
        # transfer intent (to + value_wei) ---
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import create_async_engine as _cae

        from fwd.infra.audit_repo import audit_log

        async def _fetch_audit_rows() -> list[dict[str, object]]:
            engine = _cae(db_url)
            async with engine.connect() as conn:
                result = await conn.execute(
                    select(audit_log).where(audit_log.c.action == "sign-transaction")
                )
                rows = [dict(row._mapping) for row in result.fetchall()]
            await engine.dispose()
            return rows

        rows = _run(_fetch_audit_rows())
        approved = [r for r in rows if r["decision"] == "approved"]
        assert len(approved) >= 1, f"No approved sign-transaction audit row; rows={rows}"
        assert _ALLOWED_RECIPIENT.lower() in approved[0]["request_json"].lower()
        assert _VALUE_WEI in approved[0]["request_json"]

        denied = [r for r in rows if r["decision"] == "denied"]
        assert len(denied) >= 1, f"No denied sign-transaction audit row; rows={rows}"
