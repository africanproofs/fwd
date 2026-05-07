"""POST/DELETE/GET /v1/admin/callers endpoint tests."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest  # noqa: TC002
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fwd import settings as settings_mod
from fwd.api.callers import router
from fwd.app.caller_create import CallerCreateResult, CallerNameTaken
from fwd.app.caller_revoke import CallerAlreadyRevoked, CallerNotFound
from fwd.app.dependencies import get_caller_repo
from fwd.infra.caller_repo import Caller


def _caller_summary(name: str) -> Caller:
    return Caller(
        name=name,
        api_key_hash="hash",
        api_key_prefix="abcd1234",
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _make_client(
    monkeypatch: pytest.MonkeyPatch,
    create_side_effect: object = None,
    revoke_side_effect: object = None,
    list_return: list[Caller] | None = None,
) -> TestClient:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    mock_repo = MagicMock()
    mock_repo.list_all = AsyncMock(return_value=list_return or [])

    if create_side_effect is not None:
        mock_repo.create = AsyncMock(side_effect=create_side_effect)
    else:
        mock_repo.create = AsyncMock(return_value=_caller_summary("new-caller"))

    if revoke_side_effect is not None:
        mock_repo.revoke = AsyncMock(side_effect=revoke_side_effect)
    else:
        mock_repo.revoke = AsyncMock(return_value=_caller_summary("alice"))

    class _FakeRepoCM:
        async def __aenter__(self) -> MagicMock:
            return mock_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_caller_repo] = lambda: _FakeRepoCM()
    return TestClient(app, raise_server_exceptions=False)


_ADMIN_HDR = {"Authorization": "Bearer admin-secret"}


# --- POST /v1/admin/callers -------------------------------------------------


def test_post_callers_201(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch

    result = CallerCreateResult(
        name="new-caller",
        api_key="fwd_live_" + "a" * 43,
        api_key_prefix="aaaaaaaa",
        policy_path="policies/new.yaml",
    )
    with patch("fwd.api.callers.create_caller", new=AsyncMock(return_value=result)):
        client = _make_client(monkeypatch)
        r = client.post(
            "/v1/admin/callers",
            json={"name": "new-caller", "policy_path": "policies/new.yaml"},
            headers=_ADMIN_HDR,
        )
    assert r.status_code == 201
    body = r.json()
    assert body["name"] == "new-caller"
    assert "api_key" in body
    assert "api_key_prefix" in body


def test_post_callers_400_bad_name(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_client(monkeypatch)
    r = client.post(
        "/v1/admin/callers",
        json={"name": "UPPER-CASE", "policy_path": "policies/x.yaml"},
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_name"


def test_post_callers_409_name_taken(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch

    with patch("fwd.api.callers.create_caller", new=AsyncMock(side_effect=CallerNameTaken("dup"))):
        client = _make_client(monkeypatch)
        r = client.post(
            "/v1/admin/callers",
            json={"name": "dup", "policy_path": "policies/x.yaml"},
            headers=_ADMIN_HDR,
        )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "caller_exists"


def test_post_callers_401_no_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_client(monkeypatch)
    r = client.post(
        "/v1/admin/callers",
        json={"name": "x", "policy_path": "policies/x.yaml"},
    )
    assert r.status_code == 401


# --- DELETE /v1/admin/callers/{name} ----------------------------------------


def test_delete_caller_204(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch

    with patch("fwd.api.callers.revoke_caller", new=AsyncMock(return_value=None)):
        client = _make_client(monkeypatch)
        r = client.delete("/v1/admin/callers/alice", headers=_ADMIN_HDR)
    assert r.status_code == 204


def test_delete_caller_404(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch

    with patch(
        "fwd.api.callers.revoke_caller", new=AsyncMock(side_effect=CallerNotFound("nobody"))
    ):
        client = _make_client(monkeypatch)
        r = client.delete("/v1/admin/callers/nobody", headers=_ADMIN_HDR)
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "caller_not_found"


def test_delete_caller_409_already_revoked(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch

    with patch(
        "fwd.api.callers.revoke_caller",
        new=AsyncMock(side_effect=CallerAlreadyRevoked("alice")),
    ):
        client = _make_client(monkeypatch)
        r = client.delete("/v1/admin/callers/alice", headers=_ADMIN_HDR)
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "caller_already_revoked"


# --- GET /v1/admin/callers --------------------------------------------------


def test_list_callers_200(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch

    callers = [_caller_summary("alice"), _caller_summary("bob")]
    with patch("fwd.api.callers.list_callers", new=AsyncMock(return_value=callers)):
        client = _make_client(monkeypatch, list_return=callers)
        r = client.get("/v1/admin/callers", headers=_ADMIN_HDR)
    assert r.status_code == 200
    body = r.json()
    assert "callers" in body
    assert len(body["callers"]) == 2
    for item in body["callers"]:
        assert "api_key_hash" not in item
