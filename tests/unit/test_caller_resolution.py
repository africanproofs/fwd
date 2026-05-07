"""resolve_caller use case unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from fwd.app.caller_resolution import resolve_caller
from fwd.infra.api_key import generate_api_key
from fwd.infra.caller_repo import Caller


def _active_caller(name: str, api_key_hash: str, api_key_prefix: str) -> Caller:
    return Caller(
        name=name,
        api_key_hash=api_key_hash,
        api_key_prefix=api_key_prefix,
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


@pytest.mark.asyncio
async def test_resolve_returns_caller_on_valid_key() -> None:
    g = generate_api_key()
    caller = _active_caller("alice", g.key_hash, g.key_prefix)
    repo = MagicMock()
    repo.list_by_prefix_active = AsyncMock(return_value=[caller])

    result = await resolve_caller(g.key, repo)

    assert result is not None
    assert result.name == "alice"


@pytest.mark.asyncio
async def test_resolve_returns_none_on_bad_shape() -> None:
    repo = MagicMock()
    repo.list_by_prefix_active = AsyncMock(return_value=[])

    result = await resolve_caller("not-a-key", repo)

    assert result is None
    repo.list_by_prefix_active.assert_not_called()


@pytest.mark.asyncio
async def test_resolve_returns_none_when_no_prefix_match() -> None:
    g = generate_api_key()
    repo = MagicMock()
    repo.list_by_prefix_active = AsyncMock(return_value=[])

    result = await resolve_caller(g.key, repo)

    assert result is None


@pytest.mark.asyncio
async def test_resolve_returns_none_on_wrong_key() -> None:
    g1 = generate_api_key()
    g2 = generate_api_key()
    # Present g2's key, but hash is for g1 (same prefix — extremely unlikely; force it)
    caller = _active_caller("bob", g1.key_hash, g2.key_prefix)
    repo = MagicMock()
    repo.list_by_prefix_active = AsyncMock(return_value=[caller])

    result = await resolve_caller(g2.key, repo)

    assert result is None


@pytest.mark.asyncio
async def test_resolve_picks_correct_caller_among_prefix_collisions() -> None:
    g1 = generate_api_key()
    g2 = generate_api_key()
    # Two callers that share the SAME prefix (synthetic collision).
    shared_prefix = g1.key_prefix
    caller1 = _active_caller("alice", g1.key_hash, shared_prefix)
    caller2 = _active_caller("bob", g2.key_hash, shared_prefix)
    repo = MagicMock()
    repo.list_by_prefix_active = AsyncMock(return_value=[caller1, caller2])

    result = await resolve_caller(g2.key, repo)

    assert result is not None
    assert result.name == "bob"
