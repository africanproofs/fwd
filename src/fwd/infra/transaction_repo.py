"""Async repository for the transactions, transaction_hashes, and
transaction_attempts tables.

Schema mirrors architecture.md § SQLite schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, select, update

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

metadata = MetaData()

transactions = Table(
    "transactions",
    metadata,
    Column("tx_id", String, primary_key=True),
    Column("wallet", String, nullable=False),
    Column("chain", Integer, nullable=False),
    Column("caller", String, nullable=False),
    Column("nonce", Integer, nullable=False),
    Column("contract_address", String, nullable=False),
    Column("method_name", String, nullable=False),
    Column("value_wei", String, nullable=False),
    Column("idempotency_key", String, nullable=True),
    Column("request_json", String, nullable=False),
    Column("signed_raw", String, nullable=True),
    Column("status", String, nullable=False),
    Column("submitted_at", DateTime(timezone=True), nullable=True),
    Column("confirmed_at", DateTime(timezone=True), nullable=True),
    Column("receipt_json", String, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("reserved_at", DateTime(timezone=True), nullable=True),
)

transaction_hashes = Table(
    "transaction_hashes",
    metadata,
    Column("tx_id", String, nullable=False, primary_key=True),
    Column("sequence_num", Integer, nullable=False, primary_key=True),
    Column("hash_hex", String, nullable=False),
    Column("submitted_at", DateTime(timezone=True), nullable=False),
)

transaction_attempts = Table(
    "transaction_attempts",
    metadata,
    Column("tx_id", String, nullable=False, primary_key=True),
    Column("sequence_num", Integer, nullable=False, primary_key=True),
    Column("gas", Integer, nullable=False),
    Column("max_fee_per_gas", Integer, nullable=False),
    Column("max_priority_fee_per_gas", Integer, nullable=False),
    Column("signed_raw", String, nullable=False),
    Column("hash", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

_VALID_STATUSES = frozenset({"pending", "submitted", "mined", "failed", "dropped", "reverted"})


@dataclass(frozen=True)
class Transaction:
    tx_id: str
    wallet: str
    chain: int
    caller: str
    nonce: int
    contract_address: str
    method_name: str
    value_wei: str
    idempotency_key: str | None
    request_json: str
    signed_raw: str | None
    status: str
    submitted_at: datetime | None
    confirmed_at: datetime | None
    receipt_json: str | None
    created_at: datetime
    reserved_at: datetime | None = None


@dataclass(frozen=True)
class TransactionHash:
    tx_id: str
    sequence_num: int
    hash_hex: str
    submitted_at: datetime


@dataclass(frozen=True)
class TransactionAttempt:
    tx_id: str
    sequence_num: int
    gas: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int
    signed_raw: str
    hash: str
    created_at: datetime


class TransactionExistsError(Exception):
    """Raised when INSERT would violate the tx_id PK."""


class TransactionNotFoundError(Exception):
    """Raised when get_by_id finds no row."""


class TransactionRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        tx_id: str,
        wallet: str,
        chain: int,
        caller: str,
        nonce: int,
        contract_address: str,
        method_name: str,
        value_wei: str,
        request_json: str,
        signed_raw: str | None,
        status: str,
        submitted_at: datetime | None,
        idempotency_key: str | None = None,
        reserved_at: datetime | None = None,
    ) -> Transaction:
        assert status in _VALID_STATUSES, f"invalid status: {status}"
        existing = await self.get_by_id(tx_id, missing_ok=True)
        if existing is not None:
            raise TransactionExistsError(tx_id)
        now = datetime.now(UTC)
        await self._session.execute(
            transactions.insert().values(
                tx_id=tx_id,
                wallet=wallet,
                chain=chain,
                caller=caller,
                nonce=nonce,
                contract_address=contract_address,
                method_name=method_name,
                value_wei=value_wei,
                idempotency_key=idempotency_key,
                request_json=request_json,
                signed_raw=signed_raw,
                status=status,
                submitted_at=submitted_at,
                confirmed_at=None,
                receipt_json=None,
                created_at=now,
                reserved_at=reserved_at,
            )
        )
        return Transaction(
            tx_id=tx_id,
            wallet=wallet,
            chain=chain,
            caller=caller,
            nonce=nonce,
            contract_address=contract_address,
            method_name=method_name,
            value_wei=value_wei,
            idempotency_key=idempotency_key,
            request_json=request_json,
            signed_raw=signed_raw,
            status=status,
            submitted_at=submitted_at,
            confirmed_at=None,
            receipt_json=None,
            created_at=now,
            reserved_at=reserved_at,
        )

    async def get_by_idempotency_key(
        self,
        caller: str,
        key: str,
    ) -> Transaction | None:
        """Return the transaction for a given (caller, idempotency_key) pair, or None.

        The partial-unique index idx_tx_idempotency (caller, idempotency_key)
        guarantees at most one result. Per-caller scope: same key from a
        different caller is NOT a match.
        """
        result = await self._session.execute(
            select(transactions).where(
                transactions.c.caller == caller,
                transactions.c.idempotency_key == key,
            )
        )
        row = result.first()
        if row is None:
            return None
        return Transaction(
            tx_id=row.tx_id,
            wallet=row.wallet,
            chain=row.chain,
            caller=row.caller,
            nonce=row.nonce,
            contract_address=row.contract_address,
            method_name=row.method_name,
            value_wei=row.value_wei,
            idempotency_key=row.idempotency_key,
            request_json=row.request_json,
            signed_raw=row.signed_raw,
            status=row.status,
            submitted_at=row.submitted_at,
            confirmed_at=row.confirmed_at,
            receipt_json=row.receipt_json,
            created_at=row.created_at,
            reserved_at=row.reserved_at,
        )

    async def add_hash(
        self,
        tx_id: str,
        hash_hex: str,
        sequence_num: int = 1,
    ) -> TransactionHash:
        now = datetime.now(UTC)
        await self._session.execute(
            transaction_hashes.insert().values(
                tx_id=tx_id,
                sequence_num=sequence_num,
                hash_hex=hash_hex,
                submitted_at=now,
            )
        )
        return TransactionHash(
            tx_id=tx_id,
            sequence_num=sequence_num,
            hash_hex=hash_hex,
            submitted_at=now,
        )

    async def get_by_id(
        self,
        tx_id: str,
        *,
        missing_ok: bool = False,
    ) -> Transaction | None:
        result = await self._session.execute(
            select(transactions).where(transactions.c.tx_id == tx_id)
        )
        row = result.first()
        if row is None:
            if missing_ok:
                return None
            raise TransactionNotFoundError(tx_id)
        return Transaction(
            tx_id=row.tx_id,
            wallet=row.wallet,
            chain=row.chain,
            caller=row.caller,
            nonce=row.nonce,
            contract_address=row.contract_address,
            method_name=row.method_name,
            value_wei=row.value_wei,
            idempotency_key=row.idempotency_key,
            request_json=row.request_json,
            signed_raw=row.signed_raw,
            status=row.status,
            submitted_at=row.submitted_at,
            confirmed_at=row.confirmed_at,
            receipt_json=row.receipt_json,
            created_at=row.created_at,
            reserved_at=row.reserved_at,
        )

    async def list_hashes_by_tx(self, tx_id: str) -> list[TransactionHash]:
        result = await self._session.execute(
            select(transaction_hashes)
            .where(transaction_hashes.c.tx_id == tx_id)
            .order_by(transaction_hashes.c.sequence_num)
        )
        return [
            TransactionHash(
                tx_id=row.tx_id,
                sequence_num=row.sequence_num,
                hash_hex=row.hash_hex,
                submitted_at=row.submitted_at,
            )
            for row in result
        ]

    async def list_by_status(self, status: str) -> list[Transaction]:
        """Return all transactions with the given status, ordered by created_at.

        Used by the receipt watcher (v0.4.0a6) to enumerate pending
        ('submitted') txs each tick.
        """
        assert status in _VALID_STATUSES, f"invalid status: {status}"
        result = await self._session.execute(
            select(transactions)
            .where(transactions.c.status == status)
            .order_by(transactions.c.created_at)
        )
        return [
            Transaction(
                tx_id=row.tx_id,
                wallet=row.wallet,
                chain=row.chain,
                caller=row.caller,
                nonce=row.nonce,
                contract_address=row.contract_address,
                method_name=row.method_name,
                value_wei=row.value_wei,
                idempotency_key=row.idempotency_key,
                request_json=row.request_json,
                signed_raw=row.signed_raw,
                status=row.status,
                submitted_at=row.submitted_at,
                confirmed_at=row.confirmed_at,
                receipt_json=row.receipt_json,
                created_at=row.created_at,
                reserved_at=row.reserved_at,
            )
            for row in result
        ]

    async def list_stale_reservations(self, older_than: datetime) -> list[Transaction]:
        """Return pending transactions whose reserved_at is older than *older_than*.

        These are orphan candidates: signed but never reported broadcast.
        """
        result = await self._session.execute(
            select(transactions)
            .where(
                transactions.c.status == "pending",
                transactions.c.reserved_at.isnot(None),
                transactions.c.reserved_at < older_than,
            )
            .order_by(transactions.c.reserved_at)
        )
        return [
            Transaction(
                tx_id=row.tx_id,
                wallet=row.wallet,
                chain=row.chain,
                caller=row.caller,
                nonce=row.nonce,
                contract_address=row.contract_address,
                method_name=row.method_name,
                value_wei=row.value_wei,
                idempotency_key=row.idempotency_key,
                request_json=row.request_json,
                signed_raw=row.signed_raw,
                status=row.status,
                submitted_at=row.submitted_at,
                confirmed_at=row.confirmed_at,
                receipt_json=row.receipt_json,
                created_at=row.created_at,
                reserved_at=row.reserved_at,
            )
            for row in result
        ]

    async def update_status(
        self,
        tx_id: str,
        status: str,
        *,
        confirmed_at: datetime | None = None,
        receipt_json: str | None = None,
        signed_raw: str | None = None,
        submitted_at: datetime | None = None,
    ) -> None:
        assert status in _VALID_STATUSES, f"invalid status: {status}"
        values: dict[str, object] = {"status": status}
        if confirmed_at is not None:
            values["confirmed_at"] = confirmed_at
        if receipt_json is not None:
            values["receipt_json"] = receipt_json
        if signed_raw is not None:
            values["signed_raw"] = signed_raw
        if submitted_at is not None:
            values["submitted_at"] = submitted_at
        await self._session.execute(
            update(transactions).where(transactions.c.tx_id == tx_id).values(**values)
        )


class TransactionAttemptRepo:
    """Repository for the transaction_attempts table.

    Records every signed attempt (original = seq 1, each replacement = seq N+1).
    Mirrors the transaction_hashes style (same file, same session).
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_attempt(
        self,
        tx_id: str,
        sequence_num: int,
        gas: int,
        max_fee_per_gas: int,
        max_priority_fee_per_gas: int,
        signed_raw: str,
        hash: str,
        created_at: datetime,
    ) -> TransactionAttempt:
        await self._session.execute(
            transaction_attempts.insert().values(
                tx_id=tx_id,
                sequence_num=sequence_num,
                gas=gas,
                max_fee_per_gas=max_fee_per_gas,
                max_priority_fee_per_gas=max_priority_fee_per_gas,
                signed_raw=signed_raw,
                hash=hash,
                created_at=created_at,
            )
        )
        return TransactionAttempt(
            tx_id=tx_id,
            sequence_num=sequence_num,
            gas=gas,
            max_fee_per_gas=max_fee_per_gas,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            signed_raw=signed_raw,
            hash=hash,
            created_at=created_at,
        )

    async def latest_attempt(self, tx_id: str) -> TransactionAttempt | None:
        """Return the attempt with the highest sequence_num for tx_id, or None."""
        result = await self._session.execute(
            select(transaction_attempts)
            .where(transaction_attempts.c.tx_id == tx_id)
            .order_by(transaction_attempts.c.sequence_num.desc())
            .limit(1)
        )
        row = result.first()
        if row is None:
            return None
        return TransactionAttempt(
            tx_id=row.tx_id,
            sequence_num=row.sequence_num,
            gas=row.gas,
            max_fee_per_gas=row.max_fee_per_gas,
            max_priority_fee_per_gas=row.max_priority_fee_per_gas,
            signed_raw=row.signed_raw,
            hash=row.hash,
            created_at=row.created_at,
        )

    async def list_attempts(self, tx_id: str) -> list[TransactionAttempt]:
        """Return all attempts for tx_id in ascending sequence_num order."""
        result = await self._session.execute(
            select(transaction_attempts)
            .where(transaction_attempts.c.tx_id == tx_id)
            .order_by(transaction_attempts.c.sequence_num)
        )
        return [
            TransactionAttempt(
                tx_id=row.tx_id,
                sequence_num=row.sequence_num,
                gas=row.gas,
                max_fee_per_gas=row.max_fee_per_gas,
                max_priority_fee_per_gas=row.max_priority_fee_per_gas,
                signed_raw=row.signed_raw,
                hash=row.hash,
                created_at=row.created_at,
            )
            for row in result
        ]
