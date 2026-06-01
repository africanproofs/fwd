"""POST/DELETE/GET /v1/admin/callers endpoint tests.

v0.5.0a7: POST + DELETE handlers switched to AdminScopeCM. Write-handler
tests override get_admin_scope to inject a fake AdminScope; use-case calls
are patched at the module level as before. GET (list) handler is unchanged.
"""

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
from fwd.app.dependencies import AdminScope, get_admin_scope, get_caller_repo
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


def _fake_admin_scope() -> AdminScope:
    """Build an AdminScope backed by AsyncMock components (no Vault needed)."""
    signer = MagicMock()
    caller_repo = MagicMock()
    audit_repo = MagicMock()
    audit_repo.append = AsyncMock(return_value=None)
    nonce_repo = MagicMock()
    return AdminScope(signer=signer, caller_repo=caller_repo, audit_repo=audit_repo, nonce_repo=nonce_repo)


class _FakeAdminScopeCM:
    """Async CM that yields a fake AdminScope without touching Vault or DB."""

    def __init__(self) -> None:
        self._scope = _fake_admin_scope()

    async def __aenter__(self) -> AdminScope:
        return self._scope

    async def __aexit__(self, *args: object) -> None:
        pass


def _make_client(
    monkeypatch: pytest.MonkeyPatch,
    list_return: list[Caller] | None = None,
) -> TestClient:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    mock_repo = MagicMock()
    mock_repo.list_all = AsyncMock(return_value=list_return or [])

    class _FakeRepoCM:
        async def __aenter__(self) -> MagicMock:
            return mock_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    app = FastAPI()
    app.include_router(router)
    # GET (list) still uses CallerRepoCM.
    app.dependency_overrides[get_caller_repo] = lambda: _FakeRepoCM()
    # Write handlers (POST/DELETE) use AdminScopeCM — override to avoid Vault.
    app.dependency_overrides[get_admin_scope] = lambda: _FakeAdminScopeCM()
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


# --- POST /v1/admin/callers with replace ------------------------------------


def test_post_callers_replace_after_revoke_201(monkeypatch: pytest.MonkeyPatch) -> None:
    """POST {"replace": true} after revoking the same name → 201 with fresh api_key."""
    from unittest.mock import patch

    result = CallerCreateResult(
        name="rotating-caller",
        api_key="fwd_live_" + "b" * 43,
        api_key_prefix="bbbbbbbb",
        policy_path="policies/rotating.yaml",
    )
    with patch("fwd.api.callers.create_caller", new=AsyncMock(return_value=result)):
        client = _make_client(monkeypatch)
        r = client.post(
            "/v1/admin/callers",
            json={"name": "rotating-caller", "policy_path": "policies/rotating.yaml", "replace": True},
            headers=_ADMIN_HDR,
        )
    assert r.status_code == 201
    body = r.json()
    assert "api_key" in body
    assert body["name"] == "rotating-caller"


def test_post_callers_replace_false_after_revoke_409(monkeypatch: pytest.MonkeyPatch) -> None:
    """POST without replace (or replace:false) after revoke → 409 caller_exists."""
    from unittest.mock import patch

    with patch("fwd.api.callers.create_caller", new=AsyncMock(side_effect=CallerNameTaken("dup"))):
        client = _make_client(monkeypatch)
        r = client.post(
            "/v1/admin/callers",
            json={"name": "dup", "policy_path": "policies/x.yaml", "replace": False},
            headers=_ADMIN_HDR,
        )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "caller_exists"


def test_post_callers_active_name_409_even_with_replace(monkeypatch: pytest.MonkeyPatch) -> None:
    """POST replace:true on an ACTIVE name → 409 (repo raises CallerExistsError → 409)."""
    from unittest.mock import patch

    with patch("fwd.api.callers.create_caller", new=AsyncMock(side_effect=CallerNameTaken("active"))):
        client = _make_client(monkeypatch)
        r = client.post(
            "/v1/admin/callers",
            json={"name": "active", "policy_path": "policies/x.yaml", "replace": True},
            headers=_ADMIN_HDR,
        )
    assert r.status_code == 409


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
