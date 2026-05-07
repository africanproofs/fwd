"""SQLAlchemy async engine + session factory.

Per architecture.md § SQLite schema, fwd applies these PRAGMAs at startup:
  journal_mode=WAL, synchronous=NORMAL, busy_timeout=5000, foreign_keys=ON.

Phase 3b applies them via the connection-event handler below.
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
    cur = dbapi_connection.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    s = get_settings()
    engine = create_async_engine(s.database_url, future=True)
    # The pragmas hook attaches to the *sync* DBAPI connection event —
    # async engines re-emit it.
    event.listen(Engine, "connect", _apply_sqlite_pragmas)
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
