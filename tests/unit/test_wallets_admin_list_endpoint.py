"""GET /v1/admin/wallets endpoint tests.

Mirrors test_callers_endpoint.py for the list case. Closes audit
deferral F7.2 + D11 bright-line spot check on the new endpoint.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest  # noqa: TC002
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fwd import settings as settings_mod
from fwd.api.wallets import router
from fwd.app.dependencies import get_wallet_repo
from fwd.infra.wallet_repo import Wallet


def _wallet(name: str, address: str | None = None, policy: str = "policies/test.yaml") -> Wallet:
    return Wallet(
        name=name,
        address=address or "0x" + "11" * 20,
        privkey_ciphertext="seal:v1:CIPHERTEXT_SHOULD_NEVER_LEAK",
        vault_master_key="fwd-master",
        policy_path=policy,
        created_at=datetime.now(UTC),
    )


def _make_client(
    monkeypatch: pytest.MonkeyPatch,
    list_return: list[Wallet] | None = None,
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
    app.dependency_overrides[get_wallet_repo] = lambda: _FakeRepoCM()
    return TestClient(app, raise_server_exceptions=False)


_ADMIN_HDR = {"Authorization": "Bearer admin-secret"}


def test_get_admin_wallets_returns_200_with_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: admin token + 2 wallets in repo -> 200 with summary list.

    Defense-in-depth: the response body MUST NOT contain the strings
    'privkey_ciphertext' or 'vault_master_key' under any circumstance.
    """
    wallets = [
        _wallet("alice", "0x" + "aa" * 20, "policies/alice.yaml"),
        _wallet("bob", "0x" + "bb" * 20, "policies/bob.yaml"),
    ]
    client = _make_client(monkeypatch, list_return=wallets)

    r = client.get("/v1/admin/wallets", headers=_ADMIN_HDR)
    assert r.status_code == 200
    body = r.json()
    assert "wallets" in body
    assert len(body["wallets"]) == 2

    names = {w["name"] for w in body["wallets"]}
    assert names == {"alice", "bob"}

    for item in body["wallets"]:
        assert set(item.keys()) == {"name", "address", "policy_path", "created_at"}
        assert "privkey_ciphertext" not in item
        assert "vault_master_key" not in item

    # Defense-in-depth: scan the raw body bytes for secret-field names.
    raw = r.content.decode()
    assert "privkey_ciphertext" not in raw
    assert "vault_master_key" not in raw
    # Sanity: the actual ciphertext value must not leak either.
    assert "CIPHERTEXT_SHOULD_NEVER_LEAK" not in raw


def test_get_admin_wallets_returns_empty_array_when_no_wallets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _make_client(monkeypatch, list_return=[])
    r = client.get("/v1/admin/wallets", headers=_ADMIN_HDR)
    assert r.status_code == 200
    assert r.json() == {"wallets": []}


def test_get_admin_wallets_no_auth_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_client(monkeypatch)
    r = client.get("/v1/admin/wallets")
    assert r.status_code == 401


def test_get_admin_wallets_bad_admin_token_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _make_client(monkeypatch)
    r = client.get(
        "/v1/admin/wallets",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 401


def test_get_admin_wallets_caller_token_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D11 bright line on the new endpoint: a valid caller token must NOT
    open the admin door. require_admin is FWD_ADMIN_KEY-keyed; any non-admin
    token (including a well-formed caller key) returns 401.
    """
    client = _make_client(monkeypatch)
    caller_key = "fwd_live_" + "c" * 43
    r = client.get(
        "/v1/admin/wallets",
        headers={"Authorization": f"Bearer {caller_key}"},
    )
    assert r.status_code == 401, (
        f"D11 VIOLATION: caller token accepted on GET /v1/admin/wallets (got {r.status_code}); "
        f"body: {r.text[:200]}"
    )


def test_get_admin_wallets_503_when_admin_key_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail-closed contract on require_admin: empty FWD_ADMIN_KEY -> 503."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "")
    settings_mod.get_settings.cache_clear()

    mock_repo = MagicMock()
    mock_repo.list_all = AsyncMock(return_value=[])

    class _FakeRepoCM:
        async def __aenter__(self) -> MagicMock:
            return mock_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_wallet_repo] = lambda: _FakeRepoCM()
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/v1/admin/wallets", headers={"Authorization": "Bearer anything"})
    assert r.status_code == 503


def test_get_admin_wallets_no_secret_strings_anywhere(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Belt-and-suspenders: even with many wallets and unusual content,
    no secret-field name OR value appears in the response payload."""
    wallets = [_wallet(f"w{i}", "0x" + f"{i:02x}" * 20, f"policies/w{i}.yaml") for i in range(5)]
    client = _make_client(monkeypatch, list_return=wallets)
    r = client.get("/v1/admin/wallets", headers=_ADMIN_HDR)
    raw = r.content.decode()
    for forbidden in ("privkey_ciphertext", "vault_master_key", "CIPHERTEXT_SHOULD_NEVER_LEAK"):
        assert forbidden not in raw
    # Parsed shape is also clean.
    parsed = json.loads(raw)
    for item in parsed["wallets"]:
        assert set(item.keys()) == {"name", "address", "policy_path", "created_at"}
