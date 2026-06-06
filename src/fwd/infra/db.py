"""SQLAlchemy async engine + session factory.

Per architecture.md § SQLite schema, fwd applies these PRAGMAs at startup:
  journal_mode=WAL, synchronous=NORMAL, busy_timeout=30000, foreign_keys=ON.

The connection-event handler below sets isolation_level=None on the raw DBAPI
connection, which disables sqlite3's implicit BEGIN (DEFERRED) wrapping.
SQLAlchemy's `begin` event can then issue an explicit BEGIN IMMEDIATE to
serialize all writers per architecture.md § Signing flow step 6. Without this,
sqlite3's implicit BEGIN (DEFERRED) would already be open when our `begin`
event fires, causing "cannot start a transaction within a transaction".
See the SQLAlchemy SQLite docs on serializable isolation:
https://docs.sqlalchemy.org/en/20/dialects/sqlite.html#serializable-isolation-savepoints-transactional-ddl
"""

from __future__ import annotations

import contextvars
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

# Context var that marks a session as read-only — skips BEGIN IMMEDIATE.
# Default False: all sessions are read-write (BEGIN IMMEDIATE) unless
# the caller explicitly opts into read-only via session_scope(read_only=True).
_ro_ctx: contextvars.ContextVar[bool] = contextvars.ContextVar("_ro", default=False)


def _apply_sqlite_pragmas(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
    # Disable sqlite3's implicit transaction wrap so SQLAlchemy's `begin`
    # event handler can issue an explicit BEGIN IMMEDIATE without colliding
    # with an already-open DEFERRED transaction. v0.4.5 fix per the docstring.
    dbapi_connection.isolation_level = None

    cur = dbapi_connection.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    # busy_timeout sized for concurrent writer queueing. fwd is sign-only
    # (no RPC, no broadcast): the writer lock is held for sub-ms per request.
    # 30s provides generous headroom for concurrent callers. See docs/history/0.4.5-*.md.
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
    #
    # Read-only sessions (session_scope(read_only=True)) skip BEGIN IMMEDIATE
    # so they do not contend on the SQLite writer lock — safe because they
    # never write (no commit at the end of session_scope for read_only=True).
    if _ro_ctx.get():
        return
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
async def session_scope(read_only: bool = False) -> AsyncIterator[AsyncSession]:
    """Async session context manager.

    read_only=True: skips BEGIN IMMEDIATE (no writer-lock contention) and
    skips the final commit (pure SELECT sessions). Safe only for read-only
    callers; any accidental write will still propagate via rollback on exit.
    The canonical read-only consumer is caller_auth's argon2 SELECT.
    """
    token = _ro_ctx.set(read_only)
    try:
        factory = _session_factory()
        async with factory() as session:
            try:
                yield session
                if not read_only:
                    await session.commit()
            except Exception:
                await session.rollback()
                raise
    finally:
        _ro_ctx.reset(token)
