"""require_caller middleware unit tests.

Uses FastAPI TestClient with a dummy endpoint; repo is injected via
dependency_overrides so no real DB is needed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest  # noqa: TC002
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fwd.api.caller_auth import caller_required
from fwd.app.dependencies import get_caller_repo
from fwd.infra.api_key import generate_api_key
from fwd.infra.caller_repo import Caller


def _active_caller(name: str, key_hash: str, key_prefix: str) -> Caller:
    return Caller(
        name=name,
        api_key_hash=key_hash,
        api_key_prefix=key_prefix,
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _make_app(resolved_caller: Caller | None) -> FastAPI:
    """Build a minimal test app with require_caller injected."""
    test_app = FastAPI()

    # Build a fake CallerRepoCM whose context manager yields a mock repo.
    mock_repo = MagicMock()
    mock_repo.list_by_prefix_active = AsyncMock(
        return_value=[resolved_caller] if resolved_caller else []
    )
    mock_repo.get_by_name = AsyncMock(return_value=resolved_caller)

    class _FakeRepoCM:
        async def __aenter__(self) -> MagicMock:
            return mock_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    test_app.dependency_overrides[get_caller_repo] = lambda: _FakeRepoCM()

    @test_app.get("/probe")
    async def _probe(caller: Caller = caller_required) -> dict[str, str]:  # type: ignore[assignment]
        return {"name": caller.name}

    return test_app


def test_401_when_no_authorization_header() -> None:
    g = generate_api_key()
    caller = _active_caller("alice", g.key_hash, g.key_prefix)
    client = TestClient(_make_app(caller), raise_server_exceptions=False)
    r = client.get("/probe")
    assert r.status_code == 401


def test_401_when_not_bearer() -> None:
    g = generate_api_key()
    caller = _active_caller("alice", g.key_hash, g.key_prefix)
    client = TestClient(_make_app(caller), raise_server_exceptions=False)
    r = client.get("/probe", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401


def test_401_when_wrong_token() -> None:
    client = TestClient(_make_app(None), raise_server_exceptions=False)
    r = client.get("/probe", headers={"Authorization": "Bearer fwd_live_" + "x" * 43})
    assert r.status_code == 401


def test_200_when_valid_token() -> None:
    g = generate_api_key()
    caller = _active_caller("alice", g.key_hash, g.key_prefix)
    # Patch resolve_caller so the argon2id verify runs against the real hash.
    with patch("fwd.api.caller_auth.resolve_caller", new=AsyncMock(return_value=caller)):
        client = TestClient(_make_app(caller), raise_server_exceptions=False)
        r = client.get("/probe", headers={"Authorization": f"Bearer {g.key}"})
    assert r.status_code == 200
    assert r.json() == {"name": "alice"}


@pytest.mark.asyncio
async def test_caller_stashed_on_request_state() -> None:
    """require_caller sets request.state.caller for downstream handlers."""
    from fwd.api.caller_auth import require_caller

    g = generate_api_key()
    caller = _active_caller("state-check", g.key_hash, g.key_prefix)

    mock_repo = MagicMock()
    mock_repo.list_by_prefix_active = AsyncMock(return_value=[caller])

    class _FakeRepoCM:
        async def __aenter__(self) -> MagicMock:
            return mock_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/state-probe",
        "query_string": b"",
        "headers": [],
    }
    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(scope)

    result = await require_caller(
        request=request,
        authorization=f"Bearer {g.key}",
        caller_repo_cm=_FakeRepoCM(),  # type: ignore[arg-type]
    )

    assert result.name == "state-check"
    assert request.state.caller.name == "state-check"
