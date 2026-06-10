"""create_caller use case unit tests.

v0.5.0a7: create_caller gained keyword-only audit_repo param. All calls
updated to pass a mock AuditRepo (append is AsyncMock).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest  # noqa: TC002

from fwd.app.caller_create import CallerCreateRequest, CallerNameTaken, create_caller
from fwd.infra.caller_repo import Caller, CallerExistsError


def _mock_caller(name: str) -> Caller:
    return Caller(
        name=name,
        api_key_hash="argon2hash",
        api_key_prefix="abcd1234",
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _mock_audit_repo() -> MagicMock:
    """Minimal mock AuditRepo: append and commit are AsyncMock."""
    repo = MagicMock()
    repo.append = AsyncMock(return_value=None)
    repo.commit = AsyncMock(return_value=None)
    return repo


@pytest.mark.asyncio
async def test_create_caller_happy_path() -> None:
    repo = MagicMock()
    repo.create = AsyncMock(return_value=_mock_caller("test"))

    result = await create_caller(
        CallerCreateRequest(name="test", policy_path="policies/test.yaml"),
        repo,
        audit_repo=_mock_audit_repo(),
    )

    assert result.name == "test"
    assert result.api_key.startswith("fwd_live_")
    assert len(result.api_key) == 52
    # The prefix passed to repo.create must be derived from the generated key.
    prefix_passed = repo.create.call_args.kwargs["api_key_prefix"]
    assert prefix_passed == result.api_key[len("fwd_live_") : len("fwd_live_") + 8]


@pytest.mark.asyncio
async def test_create_caller_name_taken_raises() -> None:
    repo = MagicMock()
    repo.create = AsyncMock(side_effect=CallerExistsError("dup"))

    with pytest.raises(CallerNameTaken):
        await create_caller(
            CallerCreateRequest(name="dup", policy_path="policies/test.yaml"),
            repo,
            audit_repo=_mock_audit_repo(),
        )


@pytest.mark.asyncio
async def test_create_caller_result_has_policy_path() -> None:
    repo = MagicMock()
    repo.create = AsyncMock(return_value=_mock_caller("svc"))

    result = await create_caller(
        CallerCreateRequest(name="svc", policy_path="policies/svc.yaml"),
        repo,
        audit_repo=_mock_audit_repo(),
    )

    assert result.policy_path == "policies/test.yaml"  # from mocked Caller


@pytest.mark.asyncio
async def test_create_caller_api_key_not_in_repo_call() -> None:
    """The plaintext api_key must NEVER be passed to repo.create — only the hash."""
    repo = MagicMock()
    repo.create = AsyncMock(return_value=_mock_caller("svc"))

    await create_caller(
        CallerCreateRequest(name="svc", policy_path="policies/svc.yaml"),
        repo,
        audit_repo=_mock_audit_repo(),
    )

    call_kwargs = repo.create.call_args.kwargs
    assert "api_key" not in call_kwargs
    assert "api_key_hash" in call_kwargs
    assert not call_kwargs["api_key_hash"].startswith("fwd_live_")


@pytest.mark.asyncio
async def test_create_caller_threads_replace_true_to_repo() -> None:
    """create_caller threads replace=True into repo.create and includes it in audit request_json."""
    import json

    repo = MagicMock()
    repo.create = AsyncMock(return_value=_mock_caller("rotating"))
    audit = _mock_audit_repo()

    await create_caller(
        CallerCreateRequest(name="rotating", policy_path="policies/rotating.yaml", replace=True),
        repo,
        audit_repo=audit,
    )

    # repo received replace=True
    call_kwargs = repo.create.call_args.kwargs
    assert call_kwargs["replace"] is True

    # audit request_json includes "replace"
    audit_call_kwargs = audit.append.call_args.kwargs
    request_json = json.loads(audit_call_kwargs["request_json"])
    assert "replace" in request_json
    assert request_json["replace"] is True


@pytest.mark.asyncio
async def test_create_caller_threads_capability_id_into_request_json_and_result() -> None:
    """capability_id is threaded into repo-call-free audit request_json + the result."""
    import json

    repo = MagicMock()
    repo.create = AsyncMock(return_value=_mock_caller("clif-claim"))
    audit = _mock_audit_repo()

    result = await create_caller(
        CallerCreateRequest(
            name="clif-claim",
            policy_path="perm/claim-songbird",
            capability_id="clif/songbird/claim",
        ),
        repo,
        audit_repo=audit,
    )

    # capability_id is NOT a repo.create kwarg (no custody-DB column / Alembic).
    assert "capability_id" not in repo.create.call_args.kwargs
    # It IS in the audit request_json and echoed on the result.
    request_json = json.loads(audit.append.call_args.kwargs["request_json"])
    assert request_json["capability_id"] == "clif/songbird/claim"
    assert result.capability_id == "clif/songbird/claim"
    # NEVER the key/hash in any audit field.
    assert "api_key" not in request_json
    assert result.api_key not in audit.append.call_args.kwargs["request_json"]


@pytest.mark.asyncio
async def test_create_caller_capability_id_defaults_none() -> None:
    """Back-compat: a name-only grant carries capability_id=None (request_json null)."""
    import json

    repo = MagicMock()
    repo.create = AsyncMock(return_value=_mock_caller("legacy"))
    audit = _mock_audit_repo()

    result = await create_caller(
        CallerCreateRequest(name="legacy", policy_path="policies/legacy.yaml"),
        repo,
        audit_repo=audit,
    )

    assert result.capability_id is None
    request_json = json.loads(audit.append.call_args.kwargs["request_json"])
    assert request_json["capability_id"] is None


@pytest.mark.asyncio
async def test_create_caller_rejected_forensic_row_carries_capability_id() -> None:
    """Core #19: the CallerExistsError forensic row carries capability_id and is
    committed BEFORE the raise (commit-before-raise on the shared session)."""
    import json

    repo = MagicMock()
    repo.create = AsyncMock(side_effect=CallerExistsError("dup"))
    audit = _mock_audit_repo()

    with pytest.raises(CallerNameTaken):
        await create_caller(
            CallerCreateRequest(
                name="dup",
                policy_path="perm/claim-songbird",
                capability_id="clif/songbird/claim",
            ),
            repo,
            audit_repo=audit,
        )

    # The forensic (error) row was appended with the capability_id ...
    err_kwargs = audit.append.call_args.kwargs
    assert err_kwargs["decision"] == "error"
    request_json = json.loads(err_kwargs["request_json"])
    assert request_json["capability_id"] == "clif/songbird/claim"
    # ... and committed before the raise (Core #19 — survives the rollback).
    audit.commit.assert_awaited()
