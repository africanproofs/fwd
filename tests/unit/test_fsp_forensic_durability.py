"""Core invariant #19 enforcement for the THREE FSP forensic arms (J4).

Drives the REAL fwd.infra.db.session_scope rollback (NOT a mocked session)
to prove each FSP arm's forensic row is committed before re-raising, and
therefore survives the session_scope exception-arm rollback.

Each arm has a WITH-commit case (the fix: row must persist) and a
WITHOUT-commit control (proves the harness detects the defect class —
if the control passes without the commit, the test would not catch a
regression).

Arms under test:
  ARM 1 — policy-deny:         denied row committed, rate NOT released.
  ARM 2 — build-malformed:     error row committed, rate released (net zero).
  ARM 3 — sign/decrypt-fail:   error row committed, rate released (net zero).

Why a sibling module: the existing test_db.py forensic test is structurally
sign_and_send-specific (it uses sign-and-send action names and the
sign_and_send path's exact error flow). The FSP arms are a distinct
orchestrator with its own rate substrate (fsp_rate_buckets) and a 3-arm
(not 4-arm) structure; forcing them into that test would require coupling
two unrelated subsystems, increasing the risk that a future sign_and_send
refactor breaks the FSP gate and vice versa. Sibling module = independent,
self-contained, easier to read, zero cross-coupling. (Per J4 spec: "If
that enforcement test's structure does not generalize cleanly, add a
sibling test module.")
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from fwd import settings as settings_mod
from fwd.infra import db as db_mod
from fwd.infra.audit_repo import AuditRepo, audit_log, audit_metadata
from fwd.infra.caller_repo import Caller
from fwd.infra.rate_repo import RateRepo, fsp_rate_buckets, rate_metadata
from fwd.infra.sealed_master import SealError

if TYPE_CHECKING:
    from pathlib import Path

_KAT_PRIVKEY_HEX = "11" * 32
_CALLER_NAME = "fsp-dur-caller"
_WALLET_NAME = "fsp-dur-wallet"
_POLICY_PATH = "fsp/dur"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _caller() -> Caller:
    return Caller(
        name=_CALLER_NAME,
        api_key_hash="h",
        api_key_prefix="p",
        policy_path=_POLICY_PATH,
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _policy_with_rate(per_hour: int = 10):  # type: ignore[return]
    from fwd.domain.policy import Policy
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {_CALLER_NAME: {"policy_path": _POLICY_PATH}},
            "permissions": {},
            "fsp_permissions": {
                _POLICY_PATH: {
                    "message_types": ["UPTIME"],
                    "wallet_allowlist": [_WALLET_NAME],
                    "rate": {"per_hour": per_hour},
                }
            },
            "wallet_constraints": {},
        }
    )


def _policy_no_fsp():  # type: ignore[return]
    """Policy where caller exists but has NO fsp_permissions -> deny step 2."""
    from fwd.domain.policy import Policy
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {_CALLER_NAME: {"policy_path": _POLICY_PATH}},
            "permissions": {},
            "fsp_permissions": {},
            "wallet_constraints": {},
        }
    )


def _make_request(message_type: str = "UPTIME"):  # type: ignore[return]
    from fwd.app.sign_fsp_message import SignFspMessageRequest
    return SignFspMessageRequest(
        wallet=_WALLET_NAME,
        caller=_CALLER_NAME,
        message_type=message_type,
        reward_epoch_id=0,
    )


@pytest.fixture()
def fresh_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Patch DATABASE_URL + reset caches so each test gets a clean tmp engine."""
    db = tmp_path / "fsp_forensic.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db}")
    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()
    return db


async def _create_tables(fresh_db: Path) -> None:
    engine = db_mod.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(audit_metadata.create_all)
        await conn.run_sync(rate_metadata.create_all)


async def _all_audit_rows(fresh_db: Path) -> list[dict]:  # type: ignore[return]
    async with db_mod.session_scope() as session:
        result = await session.execute(select(audit_log).order_by(audit_log.c.seq.asc()))
        return [dict(row._mapping) for row in result]


async def _fsp_rate_counters(fresh_db: Path) -> list[int]:
    async with db_mod.session_scope() as session:
        result = await session.execute(
            select(fsp_rate_buckets.c.counter).where(
                fsp_rate_buckets.c.caller == _CALLER_NAME,
                fsp_rate_buckets.c.wallet == _WALLET_NAME,
                fsp_rate_buckets.c.message_type == "UPTIME",
            )
        )
        return [row[0] for row in result]


# ---------------------------------------------------------------------------
# ARM 1 — policy-deny (deny row committed, rate NOT released)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_arm1_deny_row_survives_rollback(fresh_db: Path) -> None:
    """ARM 1: policy deny -> forensic 'denied' row committed before raise;
    survives session_scope rollback. WITH-commit control proves persistence;
    WITHOUT-commit control proves the harness would catch a regression."""
    from fwd.app.policy_gate import PolicyDenied
    from fwd.app.sign_fsp_message import sign_fsp_message

    await _create_tables(fresh_db)

    policy = _policy_no_fsp()  # -> deny step 2 (no fsp_permissions block)
    caller = _caller()
    request = _make_request()

    # WITH commit: use the real orchestrator -> denied row committed before raise.
    signer_mock = AsyncMock()
    signer_mock.address.return_value = "0x" + "aa" * 20

    with pytest.raises(PolicyDenied):
        async with db_mod.session_scope() as session:
            rate_repo = RateRepo(session)
            audit_repo = AuditRepo(session)
            await sign_fsp_message(
                request, signer_mock,
                caller=caller, policy=policy,
                rate_repo=rate_repo, audit_repo=audit_repo,
            )

    rows = await _all_audit_rows(fresh_db)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1, (
        "ARM 1: committed forensic 'denied' row did NOT survive session_scope rollback"
    )

    # WITHOUT-commit control: append without commit -> should NOT persist.
    with pytest.raises(RuntimeError, match="control-raise"):
        async with db_mod.session_scope() as session:
            ar = AuditRepo(session)
            await ar.append(
                action="fsp-sign-message",
                decision="denied",
                caller=_CALLER_NAME,
                decision_reason="control: no commit before raise",
            )
            raise RuntimeError("control-raise")  # no commit — row should be lost

    rows_after = await _all_audit_rows(fresh_db)
    control_rows = [
        r for r in rows_after
        if r.get("decision_reason") and "control" in str(r["decision_reason"])
    ]
    assert len(control_rows) == 0, (
        "ARM 1 control: un-committed row unexpectedly persisted — "
        "harness would miss a regression of the commit-before-raise fix"
    )

    await db_mod.get_engine().dispose()


# ---------------------------------------------------------------------------
# ARM 2 — build-malformed (error row committed, rate net-zero)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_arm2_malformed_row_survives_rollback(fresh_db: Path) -> None:
    """ARM 2: build_fsp_message returns None (malformed) ->
    error row committed before raise; rate net-zero after."""
    from unittest.mock import patch

    from fwd.app.sign_fsp_message import FspMessageMalformed, sign_fsp_message

    await _create_tables(fresh_db)

    policy = _policy_with_rate()
    caller = _caller()
    request = _make_request()

    signer_mock = AsyncMock()
    signer_mock.address.return_value = "0x" + "aa" * 20

    with pytest.raises(FspMessageMalformed):
        async with db_mod.session_scope() as session:
            rate_repo = RateRepo(session)
            audit_repo = AuditRepo(session)
            # Patch build_fsp_message to return None (malformed).
            with patch("fwd.app.sign_fsp_message.build_fsp_message", return_value=None):
                await sign_fsp_message(
                    request, signer_mock,
                    caller=caller, policy=policy,
                    rate_repo=rate_repo, audit_repo=audit_repo,
                )

    rows = await _all_audit_rows(fresh_db)
    error_rows = [r for r in rows if r["decision"] == "error"]
    assert len(error_rows) >= 1, (
        "ARM 2: committed forensic 'error' row did NOT survive session_scope rollback"
    )

    # Rate must be net-zero (incremented in gate, then released by release_fsp_rate_after_failure).
    counters = await _fsp_rate_counters(fresh_db)
    for c in counters:
        assert c == 0, (
            f"ARM 2: fsp_rate_buckets counter should be 0 (net-zero) but got {c}"
        )

    # WITHOUT-commit control.
    with pytest.raises(RuntimeError, match="arm2-control"):
        async with db_mod.session_scope() as session:
            ar = AuditRepo(session)
            await ar.append(
                action="fsp-sign-message",
                decision="error",
                caller=_CALLER_NAME,
                decision_reason="arm2-control: no commit",
            )
            raise RuntimeError("arm2-control")

    rows_after = await _all_audit_rows(fresh_db)
    control_rows = [
        r for r in rows_after
        if r.get("decision_reason") and "arm2-control" in str(r["decision_reason"])
    ]
    assert len(control_rows) == 0, (
        "ARM 2 control: un-committed row persisted — harness would miss a regression"
    )

    await db_mod.get_engine().dispose()


# ---------------------------------------------------------------------------
# ARM 3 — sign/decrypt-fail (error row committed, rate net-zero)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_arm3_sign_fail_row_survives_rollback(fresh_db: Path) -> None:
    """ARM 3: SealError from sign_fsp_eip191 ->
    error row committed before raise; rate net-zero after."""
    from fwd.app.sign_fsp_message import VaultUnavailableError, sign_fsp_message

    await _create_tables(fresh_db)

    policy = _policy_with_rate()
    caller = _caller()
    request = _make_request()

    signer_mock = AsyncMock()
    signer_mock.address.return_value = "0x" + "aa" * 20
    signer_mock.sign_fsp_eip191.side_effect = SealError("test decrypt failure")

    with pytest.raises(VaultUnavailableError):
        async with db_mod.session_scope() as session:
            rate_repo = RateRepo(session)
            audit_repo = AuditRepo(session)
            await sign_fsp_message(
                request, signer_mock,
                caller=caller, policy=policy,
                rate_repo=rate_repo, audit_repo=audit_repo,
            )

    rows = await _all_audit_rows(fresh_db)
    error_rows = [r for r in rows if r["decision"] == "error"]
    assert len(error_rows) >= 1, (
        "ARM 3: committed forensic 'error' row did NOT survive session_scope rollback"
    )

    # Rate must be net-zero (gate incremented, then released on sign failure).
    counters = await _fsp_rate_counters(fresh_db)
    for c in counters:
        assert c == 0, (
            f"ARM 3: fsp_rate_buckets counter should be 0 (net-zero) but got {c}"
        )

    # WITHOUT-commit control.
    with pytest.raises(RuntimeError, match="arm3-control"):
        async with db_mod.session_scope() as session:
            ar = AuditRepo(session)
            await ar.append(
                action="fsp-sign-message",
                decision="error",
                caller=_CALLER_NAME,
                decision_reason="arm3-control: no commit",
            )
            raise RuntimeError("arm3-control")

    rows_after = await _all_audit_rows(fresh_db)
    control_rows = [
        r for r in rows_after
        if r.get("decision_reason") and "arm3-control" in str(r["decision_reason"])
    ]
    assert len(control_rows) == 0, (
        "ARM 3 control: un-committed row persisted — harness would miss a regression"
    )

    await db_mod.get_engine().dispose()
