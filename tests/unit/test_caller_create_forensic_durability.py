"""Core invariant #19 enforcement for the caller-create forensic arm.

Drives the REAL fwd.infra.db.session_scope rollback (NOT a mocked session) to
prove the CallerExistsError forensic row — carrying the new `capability_id`
(ADR-0001 §3) — is committed before re-raising and therefore SURVIVES the
session_scope exception-arm rollback.

A mocked session is structurally blind to this (it cannot roll back), so the
mock test in test_caller_create.py proves the commit-call + the id-in-request_json
cheaply; THIS sibling proves durability against a real rollback, with a
self-validating WITHOUT-commit control (omit the commit-before-raise ⇒ the row
is lost ⇒ proves the harness catches the regression). Mirrors
test_fsp_forensic_durability.py.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import select

from fwd import settings as settings_mod
from fwd.app.caller_create import CallerCreateRequest, CallerNameTaken, create_caller
from fwd.infra import db as db_mod
from fwd.infra.audit_repo import AuditRepo, audit_log, audit_metadata
from fwd.infra.caller_repo import CallerRepo
from fwd.infra.caller_repo import metadata as caller_metadata

if TYPE_CHECKING:
    from pathlib import Path

_CALLER_NAME = "clif-claim"
_POLICY_PATH = "perm/claim-songbird"
_CAPABILITY_ID = "clif/songbird/claim"


@pytest.fixture()
def fresh_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Patch DATABASE_URL + reset caches so the test gets a clean tmp engine."""
    db = tmp_path / "caller_create_forensic.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db}")
    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()
    return db


async def _create_tables() -> None:
    engine = db_mod.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(caller_metadata.create_all)
        await conn.run_sync(audit_metadata.create_all)


async def _all_audit_rows() -> list[dict]:  # type: ignore[type-arg]
    async with db_mod.session_scope() as session:
        result = await session.execute(select(audit_log).order_by(audit_log.c.seq.asc()))
        return [dict(row._mapping) for row in result]


@pytest.mark.asyncio
async def test_caller_create_rejected_forensic_row_survives_rollback(fresh_db: Path) -> None:
    """Core #19: the CallerExistsError forensic row (with capability_id) is
    committed before raise and survives the real session_scope rollback; the
    WITHOUT-commit control proves the harness would catch a regression."""
    await _create_tables()

    # Pre-create the ACTIVE caller so the second create raises CallerExistsError.
    async with db_mod.session_scope() as session:
        await CallerRepo(session).create(
            name=_CALLER_NAME,
            api_key_hash="hash",
            api_key_prefix="prefix00",
            policy_path=_POLICY_PATH,
        )
        await session.commit()

    # WITH commit-before-raise (the real arm): drive create_caller's error path
    # on the shared session_scope; the exception unwinds the scope (rollback),
    # but the forensic row was already committed.
    with pytest.raises(CallerNameTaken):
        async with db_mod.session_scope() as session:
            await create_caller(
                CallerCreateRequest(
                    name=_CALLER_NAME,
                    policy_path=_POLICY_PATH,
                    capability_id=_CAPABILITY_ID,
                ),
                CallerRepo(session),
                audit_repo=AuditRepo(session),
            )

    rows = await _all_audit_rows()
    error_rows = [r for r in rows if r["decision"] == "error"]
    assert len(error_rows) >= 1, (
        "committed forensic 'error' row did NOT survive the session_scope rollback "
        "(Core #19 commit-before-raise regression)"
    )
    request_json = json.loads(error_rows[0]["request_json"])
    assert request_json["capability_id"] == _CAPABILITY_ID
    # NEVER a key/hash in the forensic row.
    assert "api_key" not in request_json
    assert "hash" not in error_rows[0]["request_json"].lower()

    # WITHOUT-commit control: append a forensic row, raise WITHOUT committing ->
    # the session_scope rollback must discard it (else the harness is blind).
    with pytest.raises(RuntimeError, match="cc-control"):
        async with db_mod.session_scope() as session:
            await AuditRepo(session).append(
                action="caller-create",
                decision="error",
                caller=None,
                decision_reason="cc-control: no commit before raise",
            )
            raise RuntimeError("cc-control")

    rows_after = await _all_audit_rows()
    control_rows = [
        r
        for r in rows_after
        if r.get("decision_reason") and "cc-control" in str(r["decision_reason"])
    ]
    assert len(control_rows) == 0, (
        "control: un-committed row persisted — the harness would MISS a regression "
        "of the commit-before-raise fix"
    )

    await db_mod.get_engine().dispose()
