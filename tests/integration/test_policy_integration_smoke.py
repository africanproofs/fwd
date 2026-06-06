"""Integration smoke: policy lifespan load + app.state assertion.

Scope: bring up the app with TestClient (lifespan fires), verify that
_startup_policy_load ran successfully, app.state.policy is set, and a
policy-load audit row with decision="approved" was written.

v1.0.0a1: Vault removed; this test no longer requires a live Vault.
The lifespan policy-load path does not touch SealedMaster (it only reads
DB repos); no master key file is needed for this smoke test.

Requires:
  - FWD_DISABLE_MLOCK=1 (set in test so the `elif FWD_POLICY_PATH` branch
    in lifespan fires without calling mlockall or _startup_reconcile).

Note: this test does NOT attempt a full sign-and-send through TestClient --
that would require a live chain RPC. The smoke is the lifespan policy-load
path + app.state assertion, which is sufficient for a "policy integration
smoke" gate per the v0.5.0a6 canonical prompt.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest  # noqa: TC002

_ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

# Minimal policy.yaml content permitting one caller -> one wallet -> ERC-20 transfer.
_POLICY_YAML = """\
version: 1

callers:
  smoke-caller:
    policy_path: perm/smoke

wallets:
  smoke-wallet:
    policy_path: wc/smoke

permissions:
  perm/smoke:
    contracts:
      "0x1234567890abcdef1234567890abcdef12345678":
        abi: erc20
        chains: [114]
        methods:
          "transfer(address,uint256)":
            max_value_wei: "0"
    wallet_allowlist:
      - smoke-wallet

wallet_constraints:
  wc/smoke: {}
"""


def test_lifespan_policy_load_writes_approved_audit_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_state_db: Path,
) -> None:
    """Policy lifespan load: app.state.policy set + approved audit row written."""
    # Write the tmp policy.yaml.
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_POLICY_YAML)

    # Write a valid 0600 master key file so /healthz sealed_master probe passes.
    key_file = tmp_path / "master.key"
    key_file.write_bytes(secrets.token_bytes(32))
    os.chmod(key_file, 0o600)

    # Set env vars so the lifespan elif-branch fires.
    monkeypatch.setenv("FWD_DISABLE_MLOCK", "1")
    monkeypatch.setenv("FWD_MASTER_KEY_FILE", str(key_file))
    monkeypatch.setenv("FWD_POLICY_PATH", str(policy_file))
    monkeypatch.setenv("FWD_ABIS_DIR", str(_ABIS_DIR))
    monkeypatch.setenv("FWD_WATCHER_DISABLED", "1")

    # Clear all lru_cache'd settings so our env changes are picked up.
    from fwd import settings as settings_mod
    from fwd.infra import db as db_mod

    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()

    # Create all tables in the tmp DB before starting the app (mirrors the
    # Dockerfile CMD's `alembic upgrade head`). Without this, CallerRepo and
    # WalletRepo queries in _startup_policy_load raise "no such table".
    import asyncio

    from sqlalchemy.ext.asyncio import create_async_engine as _cae

    db_url = f"sqlite+aiosqlite:///{tmp_state_db}"

    async def _create_tables() -> None:
        from fwd.infra.audit_repo import audit_metadata
        from fwd.infra.caller_repo import metadata as caller_metadata
        from fwd.infra.nonce_repo import metadata as nonce_metadata
        from fwd.infra.rate_repo import rate_metadata
        from fwd.infra.transaction_repo import metadata as tx_metadata
        from fwd.infra.wallet_repo import metadata as wallet_metadata

        engine = _cae(db_url)
        async with engine.begin() as conn:
            await conn.run_sync(wallet_metadata.create_all)
            await conn.run_sync(caller_metadata.create_all)
            await conn.run_sync(nonce_metadata.create_all)
            await conn.run_sync(tx_metadata.create_all)
            await conn.run_sync(rate_metadata.create_all)
            await conn.run_sync(audit_metadata.create_all)
        await engine.dispose()

    asyncio.get_event_loop().run_until_complete(_create_tables())

    # Import app AFTER env is set so the module-level settings resolve correctly.
    from fastapi.testclient import TestClient

    from fwd.main import app

    # Bring up app with lifespan -- the elif-branch calls _startup_policy_load.
    with TestClient(app, raise_server_exceptions=True) as client:
        # Verify app.state.policy was stashed.
        from fwd.domain.policy import Policy

        assert hasattr(app.state, "policy"), "app.state.policy not set after lifespan"
        assert isinstance(app.state.policy, Policy)
        assert hasattr(app.state, "abi_registry"), "app.state.abi_registry not set"

        # Verify a policy-load audit row with decision="approved" was written.
        import asyncio

        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import create_async_engine as _cae

        from fwd.infra.audit_repo import audit_log

        db_url = os.environ["DATABASE_URL"]

        async def _fetch_audit_rows() -> list[dict[str, object]]:
            engine = _cae(db_url)
            async with engine.connect() as conn:
                result = await conn.execute(
                    select(audit_log).where(audit_log.c.action == "policy-load")
                )
                rows = [dict(row._mapping) for row in result.fetchall()]
            await engine.dispose()
            return rows

        rows = asyncio.get_event_loop().run_until_complete(_fetch_audit_rows())
        assert len(rows) >= 1, "No policy-load audit row found"
        approved = [r for r in rows if r["decision"] == "approved"]
        assert len(approved) >= 1, f"No approved policy-load row; rows={rows}"

        # Sanity: healthz still responds 200.
        resp = client.get("/healthz")
        assert resp.status_code == 200
