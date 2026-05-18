"""SQLAlchemy async engine + session factory.

Per architecture.md § SQLite schema, fwd applies these PRAGMAs at startup:
  journal_mode=WAL, synchronous=NORMAL, busy_timeout=30000, foreign_keys=ON.
  (busy_timeout bumped 5000 -> 30000 at v0.4.5 to absorb concurrent-writer
  queueing during sign-and-send bursts; the connect handler below sets
  30000 — this docstring previously still read 5000, reconciled v0.5.5
  per Core invariant #18.)

Phase 3b applies them via the connection-event handler below.
Phase 5a5 adds a BEGIN IMMEDIATE event listener to serialize writers
per architecture.md § Signing flow step 6.

v0.4.5 fixes a critical concurrency bug surfaced by the Phase 5 GA drill:
sqlite3's DB-API driver wraps every statement in an implicit BEGIN
(DEFERRED) by default. SQLAlchemy's `begin` event then fires AFTER the
implicit BEGIN has already started a transaction, so our `BEGIN IMMEDIATE`
SQL fails with "cannot start a transaction within a transaction" (which
surfaces to other concurrent connections as "database is locked"). The
fix sets `isolation_level=None` on the raw DBAPI connection, which
disables sqlite3's implicit transactions; SQLAlchemy then begins manually
via our event handler with `BEGIN IMMEDIATE`. See the SQLAlchemy SQLite
docs on serializable isolation:
https://docs.sqlalchemy.org/en/20/dialects/sqlite.html#serializable-isolation-savepoints-transactional-ddl
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from functools import lru_cache
from typing import TYPE_CHECKING

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)

from fwd.settings import get_settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.ext.asyncio import AsyncSession


def _apply_sqlite_pragmas(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
    # Disable sqlite3's implicit transaction wrap so SQLAlchemy's `begin`
    # event handler can issue an explicit BEGIN IMMEDIATE without colliding
    # with an already-open DEFERRED transaction. v0.4.5 fix per the docstring.
    dbapi_connection.isolation_level = None

    cur = dbapi_connection.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    # busy_timeout sized for concurrent writer queueing during sign-and-send.
    # Each request holds the writer lock for the full sign-and-send critical
    # section (~1s: Vault decrypt + RPC fee_history + estimate_gas + broadcast +
    # INSERT). With ~10 concurrent requests we expect ~10s wait at the back of
    # the queue; 30s gives headroom. Phase 5 follow-up may split the critical
    # section into reserve-then-commit + work-outside-lock + insert-then-commit
    # to drop writer-lock time to ~ms; until then, this timeout absorbs the
    # contention. See docs/history/0.4.5-*.md.
    cur.execute("PRAGMA busy_timeout=30000")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


def _begin_immediate(conn) -> None:  # type: ignore[no-untyped-def]
    # Force BEGIN IMMEDIATE on every transaction per architecture.md § Signing
    # flow step 6: serializes all writers, ensuring monotonic nonce reservation.
    # Registered on engine.sync_engine so it is instance-scoped (not global).
    # Cost: global write serialization per engine — acceptable for v1 volume.
    #
    # This depends on `_apply_sqlite_pragmas` setting isolation_level=None on
    # the DBAPI connection — otherwise sqlite3's implicit BEGIN (DEFERRED)
    # would already have started a transaction and this BEGIN IMMEDIATE
    # would fail with "cannot start a transaction within a transaction".
    conn.exec_driver_sql("BEGIN IMMEDIATE")


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    s = get_settings()
    engine = create_async_engine(s.database_url, future=True)
    # The pragmas hook attaches to the *sync* DBAPI connection event —
    # async engines re-emit it.
    event.listen(Engine, "connect", _apply_sqlite_pragmas)
    # Force BEGIN IMMEDIATE on every transaction (architecture.md § Signing flow step 6).
    event.listen(engine.sync_engine, "begin", _begin_immediate)
    return engine


@lru_cache(maxsize=1)
def _session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False)


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    factory = _session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
