"""Real-ASGI integration: chain_id is a universal FSP gate-scoping field.

This is the test the original chain_id contradiction needed and the unit tests
could not provide: it goes through the FastAPI route `/v1/sign-fsp-message` via
TestClient, so the `SignFspMessageBody` API-model validator ACTUALLY RUNS, then
the gate (`evaluate_fsp`) scopes by `chain_id`, then the message is built + signed.

The bug it guards: the API model used to FORBID `chain_id` on UPTIME /
SIGNING_POLICY while the gate REQUIRED a `chain_id` in the block's `chain_ids` —
so those types were unsignable over HTTP. The unit tests missed it because they
built the app-layer `SignFspMessageRequest` dataclass directly, bypassing the API
validator. This test asserts:

  - SIGNING_POLICY signs WITH chain_id (200) and is rejected WITHOUT it (422).
  - UPTIME signs WITH chain_id (200) and is rejected WITHOUT it (422).

Requires no network (zero-egress; FSP signing is EIP-191, no chain call).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest  # noqa: TC002

_ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"
_CHAIN_ID = 114  # coston2
_SIGNING_POLICY_HEX = "0x" + bytes(range(1, 97)).hex()  # 96 bytes (>= 64, valid)

_POLICY_YAML = f"""\
version: 1

callers:
  fsp-sp-caller:
    policy_path: fsp/signing-policy
  fsp-uptime-caller:
    policy_path: fsp/uptime

wallets:
  fsp-signing:
    policy_path: wc/fsp

permissions: {{}}

fsp_permissions:
  fsp/signing-policy:
    message_types: [SIGNING_POLICY]
    wallet_allowlist: [fsp-signing]
    chain_ids: [{_CHAIN_ID}]
    rate: {{per_hour: 100, per_day: 1000}}
  fsp/uptime:
    message_types: [UPTIME]
    wallet_allowlist: [fsp-signing]
    chain_ids: [{_CHAIN_ID}]
    rate: {{per_hour: 100, per_day: 1000}}

wallet_constraints:
  wc/fsp: {{}}
"""


async def _seed(db_url: str) -> dict[str, str]:
    """Create tables, mint the two fsp callers, import the fsp-signing wallet.

    Returns the minted bearer tokens keyed by role.
    """
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

    from fwd.infra.api_key import generate_api_key
    from fwd.infra.audit_repo import audit_metadata
    from fwd.infra.caller_repo import CallerRepo
    from fwd.infra.caller_repo import metadata as caller_metadata
    from fwd.infra.envelope_signer import EnvelopeSigner
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

    tokens: dict[str, str] = {}
    async with SealedMaster() as master, AsyncSession(engine) as session:
        caller_repo = CallerRepo(session)
        signer = EnvelopeSigner(master, WalletRepo(session))

        for role, name, ppath in (
            ("signing_policy", "fsp-sp-caller", "fsp/signing-policy"),
            ("uptime", "fsp-uptime-caller", "fsp/uptime"),
        ):
            gen = generate_api_key()
            await caller_repo.create(
                name=name,
                api_key_hash=gen.key_hash,
                api_key_prefix=gen.key_prefix,
                policy_path=ppath,
            )
            tokens[role] = gen.key

        await signer.create_wallet(name="fsp-signing", policy_path="wc/fsp")
        await session.commit()

    await engine.dispose()
    return tokens


def test_chain_id_is_a_universal_fsp_gate_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_state_db: Path,
) -> None:
    # Master key + policy file on disk.
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
    tokens = asyncio.run(_seed(db_url))

    # Caches were warmed by the seed engine; clear so the app builds its own.
    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()

    from fastapi.testclient import TestClient

    from fwd.main import app

    sp_auth = {"Authorization": f"Bearer {tokens['signing_policy']}"}
    up_auth = {"Authorization": f"Bearer {tokens['uptime']}"}

    with TestClient(app, raise_server_exceptions=True) as client:
        # --- SIGNING_POLICY WITH chain_id -> 200 + signature (the fixed case) ---
        r = client.post(
            "/v1/sign-fsp-message",
            headers=sp_auth,
            json={
                "wallet": "fsp-signing",
                "message_type": "SIGNING_POLICY",
                "reward_epoch_id": 123,
                "chain_id": _CHAIN_ID,
                "signing_policy": _SIGNING_POLICY_HEX,
            },
        )
        assert r.status_code == 200, r.text
        sig = r.json()["signature"]
        assert sig.startswith("0x") and len(sig) == 132, sig

        # --- SIGNING_POLICY WITHOUT chain_id -> 422 (now a required gate field) ---
        r = client.post(
            "/v1/sign-fsp-message",
            headers=sp_auth,
            json={
                "wallet": "fsp-signing",
                "message_type": "SIGNING_POLICY",
                "reward_epoch_id": 123,
                "signing_policy": _SIGNING_POLICY_HEX,
            },
        )
        assert r.status_code == 422, r.text

        # --- UPTIME WITH chain_id -> 200 (the structurally-unsignable case, fixed) ---
        r = client.post(
            "/v1/sign-fsp-message",
            headers=up_auth,
            json={
                "wallet": "fsp-signing",
                "message_type": "UPTIME",
                "reward_epoch_id": 123,
                "chain_id": _CHAIN_ID,
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["signature"].startswith("0x")

        # --- UPTIME WITHOUT chain_id -> 422 ---
        r = client.post(
            "/v1/sign-fsp-message",
            headers=up_auth,
            json={
                "wallet": "fsp-signing",
                "message_type": "UPTIME",
                "reward_epoch_id": 123,
            },
        )
        assert r.status_code == 422, r.text
