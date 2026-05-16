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
    """Minimal mock AuditRepo: append is AsyncMock."""
    repo = MagicMock()
    repo.append = AsyncMock(return_value=None)
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
