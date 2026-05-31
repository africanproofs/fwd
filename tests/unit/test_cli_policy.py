"""CLI tests for `clifwd policy validate`.

Schema-only mode is pure (no DB). Full mode opens the live DB + ABI registry
and runs the same check_consistency the daemon runs at startup; here it's
driven against a tmp SQLite with empty caller/wallet tables. check_consistency
itself is covered exhaustively by test_policy_loader; these tests guard the CLI
plumbing (schema gate, asyncio/session wiring, exit codes).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import create_async_engine
from typer.testing import CliRunner

from fwd.cli.main import app
from fwd.infra.caller_repo import metadata as caller_metadata
from fwd.infra.wallet_repo import metadata as wallet_metadata

if TYPE_CHECKING:
    import pytest

runner = CliRunner()

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

_GOOD_POLICY = """\
version: 1
callers:
  c1:
    policy_path: perm/c1
wallets:
  w1:
    policy_path: wc/w1
permissions:
  perm/c1:
    contracts:
      "0x1234567890abcdef1234567890abcdef12345678":
        abi: erc20
        chains: [114]
        methods:
          "transfer(address,uint256)":
            max_value_wei: "0"
    wallet_allowlist: [w1]
wallet_constraints:
  wc/w1: {}
"""

# Schema-valid but consistency-broken: unknown abi.
_BAD_ABI_POLICY = """\
version: 1
callers: {}
wallets: {}
permissions:
  perm/x:
    contracts:
      "0x1234567890abcdef1234567890abcdef12345678":
        abi: no_such_abi
        chains: [114]
        methods: {}
    wallet_allowlist: []
wallet_constraints: {}
"""

# Schema-invalid: a29 requires `chains` on every contract rule.
_BAD_SCHEMA_POLICY = """\
version: 1
callers: {}
wallets: {}
permissions:
  perm/x:
    contracts:
      "0x1234567890abcdef1234567890abcdef12345678":
        abi: erc20
        methods: {}
    wallet_allowlist: []
wallet_constraints: {}
"""


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# schema-only mode (no DB)
# ---------------------------------------------------------------------------


def test_validate_schema_only_ok(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["policy", "validate", "--policy", str(_write(tmp_path, _GOOD_POLICY)), "--schema-only"]
    )
    assert result.exit_code == 0, result.output
    assert "schema OK" in result.output
    assert "VALID (schema-only)" in result.output


def test_validate_schema_invalid_missing_chains(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["policy", "validate", "--policy", str(_write(tmp_path, _BAD_SCHEMA_POLICY)), "--schema-only"],
    )
    assert result.exit_code == 2
    assert "INVALID (schema)" in result.output


# ---------------------------------------------------------------------------
# full mode (schema + consistency) against a tmp DB
# ---------------------------------------------------------------------------


def _make_db(tmp_path: Path) -> Path:
    db = tmp_path / "state.db"

    async def _setup() -> None:
        eng = create_async_engine(f"sqlite+aiosqlite:///{db}")
        async with eng.begin() as conn:
            await conn.run_sync(caller_metadata.create_all)
            await conn.run_sync(wallet_metadata.create_all)
        await eng.dispose()

    asyncio.run(_setup())
    return db


def _full_mode_env(monkeypatch: pytest.MonkeyPatch, db: Path) -> None:
    from fwd.infra import db as db_module
    from fwd.settings import get_settings

    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db}")
    monkeypatch.setenv("FWD_ABIS_DIR", str(ABIS_DIR))
    # The settings + engine + session factory are lru_cached — clear so they
    # pick up the monkeypatched env, and again on teardown to not pollute peers.
    get_settings.cache_clear()
    db_module.get_engine.cache_clear()
    db_module._session_factory.cache_clear()


def test_validate_full_consistent_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db(tmp_path)
    _full_mode_env(monkeypatch, db)
    try:
        result = runner.invoke(
            app, ["policy", "validate", "--policy", str(_write(tmp_path, _GOOD_POLICY))]
        )
        assert result.exit_code == 0, result.output
        assert "VALID (schema + consistency)" in result.output
    finally:
        from fwd.infra import db as db_module
        from fwd.settings import get_settings

        get_settings.cache_clear()
        db_module.get_engine.cache_clear()
        db_module._session_factory.cache_clear()


def test_validate_full_unknown_abi_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db(tmp_path)
    _full_mode_env(monkeypatch, db)
    try:
        result = runner.invoke(
            app, ["policy", "validate", "--policy", str(_write(tmp_path, _BAD_ABI_POLICY))]
        )
        assert result.exit_code == 2, result.output
        assert "no_such_abi" in result.output
        assert "consistency error" in result.output
    finally:
        from fwd.infra import db as db_module
        from fwd.settings import get_settings

        get_settings.cache_clear()
        db_module.get_engine.cache_clear()
        db_module._session_factory.cache_clear()
