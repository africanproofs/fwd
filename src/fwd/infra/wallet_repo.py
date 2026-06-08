"""Async repository for the wallets table.

Schema mirrors architecture.md § SQLite schema:
  wallets(name PK, address, privkey_ciphertext, vault_master_key,
          policy_path, created_at)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, overload

from sqlalchemy import Column, DateTime, MetaData, String, Table, select

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

metadata = MetaData()

wallets = Table(
    "wallets",
    metadata,
    Column("name", String, primary_key=True),
    Column("address", String, nullable=False),
    Column("privkey_ciphertext", String, nullable=False),
    Column("vault_master_key", String, nullable=False),
    Column("policy_path", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)


@dataclass(frozen=True)
class Wallet:
    name: str
    address: str
    privkey_ciphertext: str
    vault_master_key: str
    policy_path: str
    created_at: datetime


class WalletExistsError(Exception):
    """Raised when INSERT would violate the name PK."""


class WalletNotFoundError(Exception):
    """Raised when a get() finds no row."""


class WalletRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        name: str,
        address: str,
        privkey_ciphertext: str,
        vault_master_key: str,
        policy_path: str,
    ) -> Wallet:
        existing = await self.get_by_name(name, missing_ok=True)
        if existing is not None:
            raise WalletExistsError(name)
        now = datetime.now(UTC)
        await self._session.execute(
            wallets.insert().values(
                name=name,
                address=address,
                privkey_ciphertext=privkey_ciphertext,
                vault_master_key=vault_master_key,
                policy_path=policy_path,
                created_at=now,
            )
        )
        return Wallet(
            name=name,
            address=address,
            privkey_ciphertext=privkey_ciphertext,
            vault_master_key=vault_master_key,
            policy_path=policy_path,
            created_at=now,
        )

    @overload
    async def get_by_name(self, name: str, *, missing_ok: Literal[False] = ...) -> Wallet: ...
    @overload
    async def get_by_name(self, name: str, *, missing_ok: Literal[True]) -> Wallet | None: ...

    async def get_by_name(self, name: str, *, missing_ok: bool = False) -> Wallet | None:
        result = await self._session.execute(select(wallets).where(wallets.c.name == name))
        row = result.first()
        if row is None:
            if missing_ok:
                return None
            raise WalletNotFoundError(name)
        return Wallet(
            name=row.name,
            address=row.address,
            privkey_ciphertext=row.privkey_ciphertext,
            vault_master_key=row.vault_master_key,
            policy_path=row.policy_path,
            created_at=row.created_at,
        )

    async def list_all(self) -> list[Wallet]:
        """Return every wallet ordered by created_at (oldest first).

        Admin-only consumer (GET /v1/admin/wallets). Caller-facing
        endpoints (Phase 7) will filter by policy.yaml's wallet_allowlist.
        """
        result = await self._session.execute(select(wallets).order_by(wallets.c.created_at))
        return [
            Wallet(
                name=row.name,
                address=row.address,
                privkey_ciphertext=row.privkey_ciphertext,
                vault_master_key=row.vault_master_key,
                policy_path=row.policy_path,
                created_at=row.created_at,
            )
            for row in result
        ]
