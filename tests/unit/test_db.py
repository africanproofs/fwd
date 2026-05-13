"""Regression tests for `fwd.infra.db` — the production engine path.

The Phase 5 GA drill at v0.4.4 surfaced a critical concurrency bug: any
sign-and-send request failed with `(sqlite3.OperationalError) database is
locked\\n[SQL: BEGIN IMMEDIATE]`. Root cause: sqlite3's DB-API driver wraps
every statement in an implicit BEGIN (DEFERRED) by default; SQLAlchemy's
`begin` event then fires AFTER that implicit BEGIN, so our `BEGIN
IMMEDIATE` SQL fails with "cannot start a transaction within a
transaction" (which surfaces to other concurrent connections as
"database is locked").

The v0.4.0a5 unit test (`test_concurrent_reservations_are_monotonic_no_gaps`
in tests/unit/test_nonce_repo.py) passed because it built its own engine
inline, and asyncio.gather scheduling allowed each BEGIN/COMMIT to
complete before the next started — masking the implicit-BEGIN conflict.

These tests exercise the ACTUAL production path through `fwd.infra.db`:
- `session_scope()` must execute a write without raising.
- Two concurrent `session_scope()` blocks each writing must both succeed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path  # noqa: TC003

import pytest
from sqlalchemy import text

from fwd import settings as settings_mod
from fwd.infra import db as db_mod
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.nonce_repo import metadata as nonce_metadata
from fwd.infra.wallet_repo import metadata as wallet_metadata


@pytest.fixture()
def fresh_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Patch DATABASE_URL + reset caches so each test gets a clean tmp engine."""
    db = tmp_path / "regression.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db}")
    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()
    return db


@pytest.mark.asyncio
async def test_session_scope_executes_write_without_implicit_begin_conflict(
    fresh_db: Path,
) -> None:
    """Single writer through the production engine.

    Pre-v0.4.5 (before isolation_level=None), this raised:
        sqlite3.OperationalError: cannot start a transaction within a transaction
    on the first INSERT (the implicit BEGIN clashed with our BEGIN IMMEDIATE).
    """
    engine = db_mod.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(wallet_metadata.create_all)
        await conn.run_sync(nonce_metadata.create_all)

    async with db_mod.session_scope() as session:
        repo = NonceRepo(session)
        # init_for_wallet attempts to INSERT — triggers BEGIN IMMEDIATE via the
        # engine.sync_engine "begin" event handler. Pre-fix this raises.
        await repo.init_for_wallet("w", 114, 0)

    # No exception → fix is in place. Sanity-check the row landed.
    async with db_mod.session_scope() as session:
        row = await session.execute(text("SELECT next_nonce FROM nonces WHERE wallet='w'"))
        assert row.scalar_one() == 0

    await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_session_scope_writes_through_real_infra(
    fresh_db: Path,
) -> None:
    """Two concurrent session_scope writers must both complete.

    Pre-v0.4.5 this failed: the second writer hit "database is locked"
    because the first writer's implicit-BEGIN-then-BEGIN-IMMEDIATE chain
    left the connection in a "in transaction" state that the second writer
    couldn't acquire.
    """
    engine = db_mod.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(wallet_metadata.create_all)
        await conn.run_sync(nonce_metadata.create_all)

    # Seed the row once so reserve_next has something to update.
    async with db_mod.session_scope() as session:
        await NonceRepo(session).init_for_wallet("w", 114, 100)

    async def _reserve_once() -> int:
        async with db_mod.session_scope() as session:
            return await NonceRepo(session).reserve_next("w", 114)

    # 5 concurrent reservations — small enough to keep the test fast,
    # large enough to exercise the writer-serialization path multiple times.
    reserved = await asyncio.gather(*[_reserve_once() for _ in range(5)])
    await engine.dispose()

    assert sorted(reserved) == [100, 101, 102, 103, 104], (
        f"expected monotonic [100..104] but got {sorted(reserved)} — "
        f"BEGIN IMMEDIATE through fwd.infra.db.session_scope failed"
    )
    assert len(set(reserved)) == 5, f"duplicate reservations: {reserved}"
