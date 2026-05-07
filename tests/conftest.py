"""Test fixtures.

The integration test (test_wallet_create_integration.py) consumes Vault
+ SQLite fixtures from here. Unit tests (everything else under tests/)
do not touch this file.
"""
from __future__ import annotations

import os
from pathlib import Path  # noqa: TC003

import httpx
import pytest


def _vault_reachable() -> bool:
    addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
    try:
        httpx.get(f"{addr}/v1/sys/health", timeout=2.0)
    except Exception:
        return False
    return True


# Skip the integration tests if the dev Vault isn't up.
needs_vault = pytest.mark.skipif(
    not _vault_reachable(),
    reason="dev Vault not reachable at VAULT_ADDR; integration test skipped",
)


@pytest.fixture()
def tmp_state_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "state.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db}")
    # Reset the lru_cache'd settings + engine so the new DATABASE_URL takes effect.
    from fwd import settings as settings_mod
    from fwd.infra import db as db_mod
    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()
    return db
