"""Tests for infra/audit_repo.py.

Covers: canonical JSON helper, genesis/linkage/determinism, _as_utc,
the TZ round-trip regression (the critical one), verify clean/empty/
tampered/broken-link/tampered-genesis/windowed, append validation,
policy-load shape, get/tail, and row uniqueness.

Uses a file-based tmp SQLite session (mirrors rate_repo/nonce_repo pattern).
The TZ round-trip test commits through the real engine and calls verify() to
exercise the _as_utc coercion symmetrically.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.infra.audit_repo import (
    GENESIS_PREV_HASH,
    AuditRepo,
    _as_utc,
    _canonical_json,
    _row_hash,
    audit_metadata,
)

# ---------------------------------------------------------------------------
# Session fixture (file-based SQLite, mirrors rate_repo test pattern)
# ---------------------------------------------------------------------------


@pytest.fixture()
async def session(tmp_path):  # type: ignore[no-untyped-def]
    db = tmp_path / "test_audit.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(audit_metadata.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


# ---------------------------------------------------------------------------
# _canonical_json — exactness
# ---------------------------------------------------------------------------


def test_canonical_json_sorted_and_compact() -> None:
    result = _canonical_json({"b": 1, "a": "x"})
    assert result == '{"a":"x","b":1}'


def test_canonical_json_non_ascii_not_escaped() -> None:
    """ensure_ascii=False: non-ASCII chars pass through verbatim."""
    result = _canonical_json({"k": "é"})
    assert result == '{"k":"é"}'


def test_canonical_json_none_values_preserved() -> None:
    result = _canonical_json({"x": None, "y": 1})
    assert result == '{"x":null,"y":1}'


# ---------------------------------------------------------------------------
# _as_utc
# ---------------------------------------------------------------------------


def test_as_utc_naive_becomes_utc_aware() -> None:
    naive = datetime(2026, 5, 16, 12, 0, 0, 123456)
    result = _as_utc(naive)
    assert result.tzinfo is not None
    assert result.tzinfo == UTC
    # Value unchanged — just tzinfo attached.
    assert result.year == naive.year
    assert result.hour == naive.hour
    assert result.microsecond == naive.microsecond


def test_as_utc_aware_unchanged() -> None:
    aware = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)
    result = _as_utc(aware)
    assert result is aware


def test_as_utc_utc_tz_unchanged() -> None:
    """An already-aware datetime with UTC zone passes through unchanged (identity check)."""
    aware = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)
    result = _as_utc(aware)
    assert result is aware


# ---------------------------------------------------------------------------
# _row_hash — determinism
# ---------------------------------------------------------------------------


def test_row_hash_deterministic() -> None:
    kwargs = {
        "prev_hash": GENESIS_PREV_HASH,
        "ts": datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC),
        "caller": "test-caller",
        "action": "sign-transaction",
        "request_json": None,
        "decision": "approved",
        "decision_reason": None,
        "outcome": None,
    }
    h1 = _row_hash(**kwargs)  # type: ignore[arg-type]
    h2 = _row_hash(**kwargs)  # type: ignore[arg-type]
    assert h1 == h2
    assert len(h1) == 64
    assert all(c in "0123456789abcdef" for c in h1)


# ---------------------------------------------------------------------------
# genesis + linkage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_genesis_prev_hash(session: AsyncSession) -> None:
    """First appended row must have prev_hash == GENESIS_PREV_HASH."""
    repo = AuditRepo(session)
    row = await repo.append(action="policy-load", decision="approved")
    await session.commit()
    assert row.prev_hash == GENESIS_PREV_HASH
    assert len(row.row_hash) == 64


@pytest.mark.asyncio
async def test_linkage_three_rows(session: AsyncSession) -> None:
    """row2.prev_hash == row1.row_hash; row3.prev_hash == row2.row_hash."""
    repo = AuditRepo(session)
    r1 = await repo.append(action="wallet-create", decision="approved", caller="alice")
    await session.commit()
    r2 = await repo.append(action="sign-transaction", decision="approved", caller="alice")
    await session.commit()
    r3 = await repo.append(action="caller-create", decision="approved")
    await session.commit()

    assert r2.prev_hash == r1.row_hash
    assert r3.prev_hash == r2.row_hash


# ---------------------------------------------------------------------------
# TZ ROUND-TRIP REGRESSION (the critical test — must exercise real SQLite)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tz_roundtrip_verify_ok(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The TZ hazard: SQLite drops tzinfo on round-trip.

    append() stores an aware ts; verify() reads it back as naive from SQLite.
    Without _as_utc coercion on the read side, isoformat() strings differ
    ("+00:00" vs no suffix) and _row_hash() produces a different hash, making
    verify() false-fail.

    This test exercises the REAL SQLite round-trip (via commit + new session).
    It must pass to confirm _as_utc is applied symmetrically.
    """
    db = tmp_path / "tz_regression.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(audit_metadata.create_all)

    # Write two rows in one session, then commit.
    async with AsyncSession(engine) as write_session:
        repo = AuditRepo(write_session)
        await repo.append(action="policy-load", decision="approved", caller=None)
        await repo.append(action="wallet-create", decision="approved", caller="bob")
        await write_session.commit()

    # Read and verify in a fresh session (simulates real round-trip tz loss).
    async with AsyncSession(engine) as read_session:
        repo = AuditRepo(read_session)
        result = await repo.verify()

    await engine.dispose()

    assert result.ok is True, f"TZ round-trip verification failed: {result.detail}"
    assert result.rows_checked == 2


# ---------------------------------------------------------------------------
# verify — clean chain, empty, tampered field, broken link, tampered genesis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_clean_chain(session: AsyncSession) -> None:
    repo = AuditRepo(session)
    n = 5
    for i in range(n):
        await repo.append(action="sign-transaction", decision="approved", caller=f"c{i}")
        await session.commit()

    result = await repo.verify()
    assert result.ok is True
    assert result.rows_checked == n
    assert result.first_break_seq is None
    assert str(n) in result.detail


@pytest.mark.asyncio
async def test_verify_empty_table(session: AsyncSession) -> None:
    repo = AuditRepo(session)
    result = await repo.verify()
    assert result.ok is True
    assert result.rows_checked == 0
    assert "empty" in result.detail


@pytest.mark.asyncio
async def test_verify_detects_tampered_field(session: AsyncSession) -> None:
    """Mutate row2's decision_reason in-place (leaving row_hash unchanged).

    verify() should detect the recompute mismatch at row2.
    """
    from fwd.infra.audit_repo import audit_log

    repo = AuditRepo(session)
    await repo.append(action="sign-transaction", decision="approved")
    await session.commit()
    r2 = await repo.append(action="wallet-create", decision="approved")
    await session.commit()
    await repo.append(action="caller-create", decision="approved")
    await session.commit()

    # Tamper row2's decision_reason without updating its row_hash.
    await session.execute(
        update(audit_log).where(audit_log.c.seq == r2.seq).values(decision_reason="tampered")
    )
    await session.commit()

    result = await repo.verify()
    assert result.ok is False
    assert result.first_break_seq == r2.seq
    assert "recompute mismatch" in result.detail


@pytest.mark.asyncio
async def test_verify_detects_broken_link(session: AsyncSession) -> None:
    """Mutate row2's stored prev_hash — linkage mismatch should be detected."""
    from fwd.infra.audit_repo import audit_log

    repo = AuditRepo(session)
    await repo.append(action="sign-transaction", decision="approved")
    await session.commit()
    r2 = await repo.append(action="wallet-create", decision="approved")
    await session.commit()

    # Replace r2's prev_hash with garbage.
    bad_prev = "a" * 64
    await session.execute(
        update(audit_log).where(audit_log.c.seq == r2.seq).values(prev_hash=bad_prev)
    )
    await session.commit()

    result = await repo.verify()
    assert result.ok is False
    assert result.first_break_seq == r2.seq
    assert "linkage mismatch" in result.detail


@pytest.mark.asyncio
async def test_verify_detects_tampered_genesis(session: AsyncSession) -> None:
    """Mutate row1's prev_hash away from GENESIS — must be caught at row1."""
    from fwd.infra.audit_repo import audit_log

    repo = AuditRepo(session)
    r1 = await repo.append(action="policy-load", decision="approved")
    await session.commit()

    # Replace the genesis marker with junk.
    await session.execute(
        update(audit_log).where(audit_log.c.seq == r1.seq).values(prev_hash="b" * 64)
    )
    await session.commit()

    result = await repo.verify()
    assert result.ok is False
    assert result.first_break_seq == r1.seq


# ---------------------------------------------------------------------------
# verify — windowed walk
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_windowed_clean_subrange(session: AsyncSession) -> None:
    """A windowed verify over a clean sub-range returns ok=True.

    Anchor semantics: the window starts after the genesis row (seq 1), so
    verify() fetches the row_hash of seq 1 as the anchor and checks from
    seq 2 onwards. The sub-range is clean so verification passes.
    """
    repo = AuditRepo(session)
    rows = []
    for i in range(5):
        r = await repo.append(action="sign-transaction", decision="approved", caller=f"c{i}")
        await session.commit()
        rows.append(r)

    # Verify only rows 2-4 (1-indexed by seq; rows[1] = seq 2).
    result = await repo.verify(from_seq=rows[1].seq, to_seq=rows[3].seq)
    assert result.ok is True
    assert result.rows_checked == 3


@pytest.mark.asyncio
async def test_verify_windowed_intact_anchor(session: AsyncSession) -> None:
    """A window whose preceding row (anchor) exists and has a valid hash passes.

    Documented anchor semantics: the anchor is the row at seq = from_seq - 1;
    if that row is present and its hash is stored correctly, the window is
    anchored and verification proceeds normally for the sub-range.
    """
    repo = AuditRepo(session)
    rows = []
    for _ in range(4):
        r = await repo.append(action="wallet-import", decision="approved")
        await session.commit()
        rows.append(r)

    # Window starting at row 2 — anchor is row 1 which is intact.
    result = await repo.verify(from_seq=rows[1].seq)
    assert result.ok is True
    assert result.rows_checked == 3


@pytest.mark.asyncio
async def test_verify_windowed_upstream_break_subrange_clean(session: AsyncSession) -> None:
    """A window starting after a real upstream break verifies its sub-range.

    Documented semantics: the windowed verify anchors on the row at from_seq-1.
    If that row's stored hash is intact, the sub-range verification passes
    even if rows before from_seq-1 were corrupted. The window is an honest
    view of the sub-range it was asked to verify.
    """
    from fwd.infra.audit_repo import audit_log

    repo = AuditRepo(session)
    r1 = await repo.append(action="sign-transaction", decision="approved")
    await session.commit()
    r2 = await repo.append(action="wallet-create", decision="approved")
    await session.commit()
    await repo.append(action="caller-create", decision="approved")
    await session.commit()

    # Tamper r1 (genesis break) — row r1's decision_reason mutated, row_hash left stale.
    await session.execute(
        update(audit_log).where(audit_log.c.seq == r1.seq).values(decision_reason="upstream-tamper")
    )
    await session.commit()

    # Full verify must fail at r1.
    full_result = await repo.verify()
    assert full_result.ok is False
    assert full_result.first_break_seq == r1.seq

    # Window from r2 onward: r2's stored prev_hash is intact (it was computed
    # from r1's original row_hash before we mutated r1). The anchor is r1.row_hash
    # as stored in r2.prev_hash — still correct. Window verify must pass.
    windowed_result = await repo.verify(from_seq=r2.seq)
    assert windowed_result.ok is True


# ---------------------------------------------------------------------------
# append validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_append_rejects_unknown_action(session: AsyncSession) -> None:
    repo = AuditRepo(session)
    with pytest.raises(AssertionError):
        await repo.append(action="not-a-real-action", decision="approved")


@pytest.mark.asyncio
async def test_append_rejects_unknown_decision(session: AsyncSession) -> None:
    repo = AuditRepo(session)
    with pytest.raises(AssertionError):
        await repo.append(action="policy-load", decision="maybe")


# ---------------------------------------------------------------------------
# policy-load shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_policy_load_shape_roundtrips(session: AsyncSession) -> None:
    """policy-load row: caller=None, request_json=None, outcome is canonical JSON."""
    repo = AuditRepo(session)
    outcome_obj = {
        "policy_yaml_path": "/etc/fwd/policy.yaml",
        "callers_count": 3,
        "fwd_version": "0.5.0a5",
    }
    outcome_str = _canonical_json(outcome_obj)
    appended = await repo.append(
        action="policy-load",
        decision="approved",
        caller=None,
        request_json=None,
        outcome=outcome_str,
    )
    await session.commit()

    fetched = await repo.get(appended.seq)
    assert fetched is not None
    assert fetched.caller is None
    assert fetched.request_json is None
    assert fetched.outcome == outcome_str


# ---------------------------------------------------------------------------
# get + tail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_missing_seq_returns_none(session: AsyncSession) -> None:
    repo = AuditRepo(session)
    result = await repo.get(99999)
    assert result is None


@pytest.mark.asyncio
async def test_tail_returns_last_n_ascending(session: AsyncSession) -> None:
    """tail(2) on a 5-row chain returns the last 2 rows in ascending seq order."""
    repo = AuditRepo(session)
    appended = []
    for i in range(5):
        r = await repo.append(action="sign-transaction", decision="approved", caller=f"c{i}")
        await session.commit()
        appended.append(r)

    tail = await repo.tail(2)
    assert len(tail) == 2
    # Must be ascending seq order.
    assert tail[0].seq < tail[1].seq
    # Must be the LAST 2.
    assert tail[0].seq == appended[3].seq
    assert tail[1].seq == appended[4].seq


@pytest.mark.asyncio
async def test_get_existing_row_roundtrip(session: AsyncSession) -> None:
    """get() returns the correct AuditRow with all fields intact."""
    repo = AuditRepo(session)
    appended = await repo.append(
        action="caller-revoke",
        decision="approved",
        caller="alice",
        request_json='{"name":"alice"}',
        decision_reason="admin-revocation",
        outcome='{"ok":true}',
    )
    await session.commit()

    fetched = await repo.get(appended.seq)
    assert fetched is not None
    assert fetched.seq == appended.seq
    assert fetched.action == "caller-revoke"
    assert fetched.decision == "approved"
    assert fetched.caller == "alice"
    assert fetched.request_json == '{"name":"alice"}'
    assert fetched.decision_reason == "admin-revocation"
    assert fetched.outcome == '{"ok":true}'
    assert fetched.prev_hash == appended.prev_hash
    assert fetched.row_hash == appended.row_hash
