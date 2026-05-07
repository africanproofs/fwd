"""Async repository for the callers table.

Schema mirrors architecture.md § SQLite schema:
  callers(name PK, api_key_hash UNIQUE, api_key_prefix, policy_path,
          created_at, revoked_at)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    MetaData,
    String,
    Table,
    select,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

metadata = MetaData()

callers = Table(
    "callers",
    metadata,
    Column("name", String, primary_key=True),
    Column("api_key_hash", String, nullable=False, unique=True),
    Column("api_key_prefix", String, nullable=False),
    Column("policy_path", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True), nullable=True),
)

Index(
    "idx_callers_prefix_active",
    callers.c.api_key_prefix,
    sqlite_where=callers.c.revoked_at.is_(None),
)


@dataclass(frozen=True)
class Caller:
    name: str
    api_key_hash: str
    api_key_prefix: str
    policy_path: str
    created_at: datetime
    revoked_at: datetime | None


class CallerExistsError(Exception):
    """Raised when INSERT would violate the name PK or hash uniqueness."""


class CallerNotFoundError(Exception):
    """Raised when a get_by_name finds no row."""


class CallerAlreadyRevokedError(Exception):
    """Raised when revoke() is called on an already-revoked caller."""


class CallerRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        name: str,
        api_key_hash: str,
        api_key_prefix: str,
        policy_path: str,
    ) -> Caller:
        existing = await self.get_by_name(name, missing_ok=True)
        if existing is not None:
            raise CallerExistsError(name)
        now = datetime.now(UTC)
        await self._session.execute(
            callers.insert().values(
                name=name,
                api_key_hash=api_key_hash,
                api_key_prefix=api_key_prefix,
                policy_path=policy_path,
                created_at=now,
                revoked_at=None,
            )
        )
        return Caller(
            name=name,
            api_key_hash=api_key_hash,
            api_key_prefix=api_key_prefix,
            policy_path=policy_path,
            created_at=now,
            revoked_at=None,
        )

    async def get_by_name(self, name: str, *, missing_ok: bool = False) -> Caller | None:
        result = await self._session.execute(select(callers).where(callers.c.name == name))
        row = result.first()
        if row is None:
            if missing_ok:
                return None
            raise CallerNotFoundError(name)
        return Caller(
            name=row.name,
            api_key_hash=row.api_key_hash,
            api_key_prefix=row.api_key_prefix,
            policy_path=row.policy_path,
            created_at=row.created_at,
            revoked_at=row.revoked_at,
        )

    async def list_by_prefix_active(self, prefix: str) -> list[Caller]:
        """Return all NON-REVOKED callers with the given api_key_prefix.

        Used by require_caller's fast path. Multiple matches are rare
        (8-char prefix collision); the caller iterates and argon2-verifies
        each.
        """
        result = await self._session.execute(
            select(callers).where(
                (callers.c.api_key_prefix == prefix) & (callers.c.revoked_at.is_(None))
            )
        )
        return [
            Caller(
                name=row.name,
                api_key_hash=row.api_key_hash,
                api_key_prefix=row.api_key_prefix,
                policy_path=row.policy_path,
                created_at=row.created_at,
                revoked_at=row.revoked_at,
            )
            for row in result
        ]

    async def list_all(self, *, include_revoked: bool = True) -> list[Caller]:
        """Admin operation. Returns all callers (revoked or not).

        Used by `clifwd callers list` and `GET /v1/admin/callers`.
        """
        stmt = select(callers).order_by(callers.c.created_at.desc())
        if not include_revoked:
            stmt = stmt.where(callers.c.revoked_at.is_(None))
        result = await self._session.execute(stmt)
        return [
            Caller(
                name=row.name,
                api_key_hash=row.api_key_hash,
                api_key_prefix=row.api_key_prefix,
                policy_path=row.policy_path,
                created_at=row.created_at,
                revoked_at=row.revoked_at,
            )
            for row in result
        ]

    async def revoke(self, name: str) -> Caller:
        existing = await self.get_by_name(name)
        assert existing is not None  # raises CallerNotFoundError otherwise
        if existing.revoked_at is not None:
            raise CallerAlreadyRevokedError(name)
        now = datetime.now(UTC)
        await self._session.execute(
            callers.update().where(callers.c.name == name).values(revoked_at=now)
        )
        return Caller(
            name=existing.name,
            api_key_hash=existing.api_key_hash,
            api_key_prefix=existing.api_key_prefix,
            policy_path=existing.policy_path,
            created_at=existing.created_at,
            revoked_at=now,
        )
