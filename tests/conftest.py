"""Test fixtures.

v1.0.0a1: Vault removed; integration tests no longer require a live Vault.
The `needs_vault` marker and `_vault_reachable()` helper are deleted.
Integration tests run unconditionally using a SealedMaster over a tmp master
file (constructed per-test via the `tmp_master_file` fixture).
"""

from __future__ import annotations

import os
from pathlib import Path  # noqa: TC003

import pytest


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


@pytest.fixture()
def tmp_master_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Write a fresh 32-byte master key to a tmp 0600 file and point settings at it."""
    key_file = tmp_path / "master.key"
    key_file.write_bytes(os.urandom(32))
    os.chmod(key_file, 0o600)
    monkeypatch.setenv("FWD_MASTER_KEY_FILE", str(key_file))
    from fwd import settings as settings_mod

    settings_mod.get_settings.cache_clear()
    return key_file
