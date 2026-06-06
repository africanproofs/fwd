"""Async repository for the audit_log hash-chained table.

Implements decisions.md D16: SHA-256 canonical-JSON hash chain, one row per
fwd operation, append-only. The table is owned by Alembic migration 0004
(no migration here). This module's `audit_metadata` + `audit_log` Table exist
only for `create_all` in tests — Alembic governs the production schema.

TZ invariant: SQLite DateTime(timezone=True) drops tzinfo on round-trip.
`_as_utc()` coerces naive datetimes to UTC-aware before feeding to
`_row_hash()`. Both `append()` (writer) and `verify()` + read paths (reader)
call `_as_utc()` so `ts.isoformat()` is byte-identical on both sides of the
round-trip. See Phase-0 finding #2 in the canonical prompt.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, func, select
from sqlalchemy.engine import CursorResult

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

audit_metadata = MetaData()

audit_log = Table(
    "audit_log",
    audit_metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column(
        "ts",
        DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
    ),
    Column("caller", String, nullable=True),
    Column("action", String, nullable=False),
    Column("request_json", String, nullable=True),
    Column("decision", String, nullable=False),
    Column("decision_reason", String, nullable=True),
    Column("outcome", String, nullable=True),
    Column("prev_hash", String, nullable=False),
    Column("row_hash", String, nullable=False),
)

# ---------------------------------------------------------------------------
# Canonical JSON + hash helpers
# ---------------------------------------------------------------------------

GENESIS_PREV_HASH = "0" * 64


def _canonical_json(obj: object) -> str:
    """Serialize *obj* to compact, key-sorted, non-ASCII-escaped JSON (D16)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _as_utc(ts: datetime) -> datetime:
    """Return *ts* as a UTC-aware datetime.

    SQLite drops tzinfo on round-trip. Callers that read ts back from the DB
    get a naive datetime; this helper reattaches UTC without converting, so
    the isoformat() string is identical to what was computed on write.
    """
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


def _row_hash(
    *,
    prev_hash: str,
    ts: datetime,
    caller: str | None,
    action: str,
    request_json: str | None,
    decision: str,
    decision_reason: str | None,
    outcome: str | None,
) -> str:
    """Compute the SHA-256 row hash per D16.

    *ts* MUST be UTC-aware (call `_as_utc` first). The canonical JSON of the
    row dict is hashed; `ts.isoformat(timespec="microseconds")` is the key
    field that must be identical at append-time and verify-time.
    """
    row_dict = {
        "prev_hash": prev_hash,
        "ts": ts.isoformat(timespec="microseconds"),
        "caller": caller,
        "action": action,
        "request_json": request_json,
        "decision": decision,
        "decision_reason": decision_reason,
        "outcome": outcome,
    }
    canonical = _canonical_json(row_dict)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Valid-value frozensets (mirrors transaction_repo _VALID_STATUSES pattern)
# ---------------------------------------------------------------------------

_VALID_ACTIONS = frozenset(
    {
        "sign-transaction",
        "sign-transaction-duplicate",
        "wallet-create",
        "wallet-import",
        "caller-create",
        "caller-revoke",
        "policy-load",
        "audit-verify-failure",
        "fsp-sign-message",
        "nonce-init",
        "nonce-sync",
        "tx-broadcast-result",
        "tx-receipt",
        "tx-replacement",
    }
)

_VALID_DECISIONS = frozenset({"approved", "denied", "error"})


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditRow:
    """Immutable representation of one audit_log row."""

    seq: int
    ts: datetime
    caller: str | None
    action: str
    request_json: str | None
    decision: str
    decision_reason: str | None
    outcome: str | None
    prev_hash: str
    row_hash: str


@dataclass(frozen=True)
class VerifyResult:
    """Result of a chain-verify walk."""

    ok: bool
    rows_checked: int
    first_break_seq: int | None
    detail: str
    # Set when a windowed walk (from_seq > table minimum) detects that the
    # anchor row at (from_seq - 1) exists but its stored row_hash does not
    # match the first walked row's prev_hash — indicating chain tampering
    # upstream of the requested range start.
    upstream_break: bool = False
    upstream_break_seq: int | None = None


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuditError(Exception):
    """Base exception for audit_repo errors."""


class AuditChainError(AuditError):
    """Reserved — raised for unexpected chain errors (not for detected breaks;
    detected breaks are returned as VerifyResult(ok=False, ...))."""


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


class AuditRepo:
    """Async repository for the append-only, hash-chained audit_log table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def commit(self) -> None:
        """Commit the underlying session.

        Forensic-row durability (D16 / Core invariant #5): a `denied` or
        `error` sign-transaction audit row is appended on the shared
        RequestScope session and then the operation raises. That exception
        propagates through `session_scope`, whose `except Exception:` arm
        ROLLS BACK — discarding the just-appended forensic row (the exact
        defect class as the v0.5.0a6 main.py SystemExit bug). The caller
        commits via this method BEFORE re-raising so the refusal/failure
        record survives (the trailing session_scope rollback is then a
        no-op on an already-committed, empty transaction). The explicit
        nonce/rate releases on the pre-sign path run before this
        commit, so the committed operational state is correct (net-zero).
        """
        await self._session.commit()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _last_row_hash(self) -> str:
        """Return the row_hash of the most-recent row, or GENESIS_PREV_HASH."""
        result = await self._session.execute(
            select(audit_log.c.row_hash).order_by(audit_log.c.seq.desc()).limit(1)
        )
        row_hash = result.scalar()
        return row_hash if row_hash is not None else GENESIS_PREV_HASH

    async def _min_seq(self) -> int | None:
        """Return the minimum seq in the table, or None if empty."""
        result = await self._session.execute(select(func.min(audit_log.c.seq)))
        return cast(int | None, result.scalar())

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def append(
        self,
        *,
        action: str,
        decision: str,
        caller: str | None = None,
        request_json: str | None = None,
        decision_reason: str | None = None,
        outcome: str | None = None,
        ts: datetime | None = None,
    ) -> AuditRow:
        """Append a new row to the audit chain and return the completed AuditRow.

        The `ts` is coerced to UTC-aware before hashing so that the isoformat
        string is stable across the SQLite tz-drop round-trip.
        """
        if action not in _VALID_ACTIONS:
            raise ValueError(f"invalid action: {action!r}")
        if decision not in _VALID_DECISIONS:
            raise ValueError(f"invalid decision: {decision!r}")

        ts = _as_utc(ts or datetime.now(UTC))
        prev_hash = await self._last_row_hash()
        rh = _row_hash(
            prev_hash=prev_hash,
            ts=ts,
            caller=caller,
            action=action,
            request_json=request_json,
            decision=decision,
            decision_reason=decision_reason,
            outcome=outcome,
        )

        cursor_result = cast(
            CursorResult,  # type: ignore[type-arg]
            await self._session.execute(
                audit_log.insert().values(
                    ts=ts,
                    caller=caller,
                    action=action,
                    request_json=request_json,
                    decision=decision,
                    decision_reason=decision_reason,
                    outcome=outcome,
                    prev_hash=prev_hash,
                    row_hash=rh,
                )
            ),
        )
        if cursor_result.lastrowid is None:
            raise RuntimeError("INSERT did not return a lastrowid")
        seq = cursor_result.lastrowid

        return AuditRow(
            seq=seq,
            ts=ts,
            caller=caller,
            action=action,
            request_json=request_json,
            decision=decision,
            decision_reason=decision_reason,
            outcome=outcome,
            prev_hash=prev_hash,
            row_hash=rh,
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get(self, seq: int) -> AuditRow | None:
        """Return the AuditRow at *seq*, or None if absent."""
        result = await self._session.execute(select(audit_log).where(audit_log.c.seq == seq))
        row = result.first()
        if row is None:
            return None
        return AuditRow(
            seq=row.seq,
            ts=_as_utc(row.ts),
            caller=row.caller,
            action=row.action,
            request_json=row.request_json,
            decision=row.decision,
            decision_reason=row.decision_reason,
            outcome=row.outcome,
            prev_hash=row.prev_hash,
            row_hash=row.row_hash,
        )

    async def tail(self, n: int = 20) -> list[AuditRow]:
        """Return the last *n* rows in ascending seq order."""
        result = await self._session.execute(
            select(audit_log).order_by(audit_log.c.seq.desc()).limit(n)
        )
        rows = [
            AuditRow(
                seq=row.seq,
                ts=_as_utc(row.ts),
                caller=row.caller,
                action=row.action,
                request_json=row.request_json,
                decision=row.decision,
                decision_reason=row.decision_reason,
                outcome=row.outcome,
                prev_hash=row.prev_hash,
                row_hash=row.row_hash,
            )
            for row in result
        ]
        rows.reverse()
        return rows

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    async def find_sign_transaction_seq(self, tx_id: str) -> int | None:
        """Return the seq of the approved sign-transaction audit row for *tx_id*, or None.

        Substring-match on the compact outcome JSON.

        Returns None when:
          - No matching row.
          - tx_id is unknown.
        """
        result = await self._session.execute(
            select(audit_log.c.seq)
            .where(
                audit_log.c.action == "sign-transaction",
                audit_log.c.decision == "approved",
                audit_log.c.outcome.like(f'%"tx_id":"{tx_id}"%'),
            )
            .order_by(audit_log.c.seq.asc())
            .limit(1)
        )
        return result.scalar()

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    async def verify(
        self,
        *,
        from_seq: int | None = None,
        to_seq: int | None = None,
    ) -> VerifyResult:
        """Walk the chain and verify hash integrity.

        Full walk (no from_seq/to_seq): the first row's prev_hash must be
        GENESIS_PREV_HASH and each subsequent row's prev_hash must equal the
        previous row's stored row_hash; AND every row's recomputed _row_hash()
        must equal its stored row_hash.

        Windowed walk (from_seq and/or to_seq): anchors the first walked row's
        expected prev_hash. If the first walked row is the table minimum, the
        expected prev is GENESIS; otherwise we fetch the row_hash of the
        immediately-preceding row (seq = first_walked_seq - 1). If that anchor
        row is missing, that is itself a break.

        Returns VerifyResult(ok=False, ...) on the first mismatch; never raises
        on a detected break. Unexpected DB errors may propagate.
        """
        # Build query
        stmt = select(audit_log).order_by(audit_log.c.seq.asc())
        if from_seq is not None:
            stmt = stmt.where(audit_log.c.seq >= from_seq)
        if to_seq is not None:
            stmt = stmt.where(audit_log.c.seq <= to_seq)

        result = await self._session.execute(stmt)
        db_rows = result.fetchall()

        if not db_rows:
            return VerifyResult(ok=True, rows_checked=0, first_break_seq=None, detail="empty chain")

        # Determine the expected prev_hash for the first row in the walk.
        first_seq = db_rows[0].seq
        table_min = await self._min_seq()

        # upstream_break is set when a windowed walk's anchor row exists but
        # its stored hash does not match the first walked row's prev_hash.
        _upstream_break: bool = False
        _upstream_break_seq: int | None = None

        if table_min is not None and first_seq == table_min:
            # This is the very first row in the table — prev must be genesis.
            expected_prev = GENESIS_PREV_HASH
        else:
            # Windowed walk starting mid-chain — anchor on the preceding row.
            anchor_result = await self._session.execute(
                select(audit_log.c.row_hash).where(audit_log.c.seq == first_seq - 1)
            )
            anchor_hash = anchor_result.scalar()
            if anchor_hash is None:
                return VerifyResult(
                    ok=False,
                    rows_checked=1,
                    first_break_seq=first_seq,
                    detail=(
                        f"missing anchor row at seq={first_seq - 1}; "
                        f"cannot verify window starting at seq={first_seq}"
                    ),
                )
            # Check whether the anchor's stored hash matches the first row's
            # prev_hash. A mismatch means the chain was tampered upstream of
            # this window's start — flag it explicitly.
            first_row_prev = db_rows[0].prev_hash
            if anchor_hash != first_row_prev:
                _upstream_break = True
                _upstream_break_seq = first_seq - 1
            expected_prev = anchor_hash

        rows_checked = 0
        for row in db_rows:
            rows_checked += 1
            ts_utc = _as_utc(row.ts)

            # 1. Linkage check: stored prev_hash must equal expected_prev.
            if row.prev_hash != expected_prev:
                return VerifyResult(
                    ok=False,
                    rows_checked=rows_checked,
                    first_break_seq=row.seq,
                    detail=(
                        f"seq={row.seq}: linkage mismatch: "
                        f"expected prev_hash={expected_prev!r}, "
                        f"got prev_hash={row.prev_hash!r}"
                    ),
                )

            # 2. Recompute check: stored row_hash must match recomputed hash.
            recomputed = _row_hash(
                prev_hash=row.prev_hash,
                ts=ts_utc,
                caller=row.caller,
                action=row.action,
                request_json=row.request_json,
                decision=row.decision,
                decision_reason=row.decision_reason,
                outcome=row.outcome,
            )
            if recomputed != row.row_hash:
                return VerifyResult(
                    ok=False,
                    rows_checked=rows_checked,
                    first_break_seq=row.seq,
                    detail=(
                        f"seq={row.seq}: recompute mismatch: "
                        f"stored row_hash={row.row_hash!r}, "
                        f"recomputed={recomputed!r}"
                    ),
                )

            # Advance the expected prev for the next iteration.
            expected_prev = row.row_hash

        if _upstream_break:
            return VerifyResult(
                ok=False,
                rows_checked=rows_checked,
                first_break_seq=_upstream_break_seq,
                detail=(
                    f"upstream break at seq={_upstream_break_seq}: "
                    f"anchor row_hash does not match seq={first_seq} prev_hash; "
                    f"chain was tampered upstream of the requested window"
                ),
                upstream_break=True,
                upstream_break_seq=_upstream_break_seq,
            )
        return VerifyResult(
            ok=True,
            rows_checked=rows_checked,
            first_break_seq=None,
            detail=f"chain intact: {rows_checked} rows",
        )
