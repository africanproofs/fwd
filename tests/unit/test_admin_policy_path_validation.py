"""Tests for admin-endpoint policy_path validation (D14).

POST /v1/admin/callers and POST /v1/admin/wallets validate the supplied
policy_path against the loaded policy:
- If a policy IS loaded: unknown path → 400 unknown_policy_path.
- If NO policy is loaded: skip the check (bootstrap order).

Uses FastAPI TestClient with dependency overrides. Stubs app.state.policy
directly via a small Policy fixture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fwd import settings as settings_mod
from fwd.api.callers import router as callers_router
from fwd.api.wallets import router as wallets_router
from fwd.app.caller_create import CallerCreateResult
from fwd.app.dependencies import AdminScope, get_admin_scope
from fwd.domain.policy import Policy

if TYPE_CHECKING:
    import pytest

POLICY_PATH_VALID_CALLER = "perm/main"
POLICY_PATH_VALID_WALLET = "wc/main"
WALLET_NAME_TEST = "my-wallet"
CALLER_NAME_TEST = "my-caller"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_minimal_policy() -> Policy:
    """A small Policy with one caller permission and one wallet constraint."""
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {CALLER_NAME_TEST: {"policy_path": POLICY_PATH_VALID_CALLER}},
            "wallets": {WALLET_NAME_TEST: {"policy_path": POLICY_PATH_VALID_WALLET}},
            "permissions": {
                POLICY_PATH_VALID_CALLER: {
                    "contracts": {},
                    "wallet_allowlist": [],
                }
            },
            "wallet_constraints": {POLICY_PATH_VALID_WALLET: {}},
        }
    )


def _fake_admin_scope() -> AdminScope:
    signer = MagicMock()
    caller_repo = MagicMock()
    audit_repo = MagicMock()
    audit_repo.append = AsyncMock(return_value=None)
    nonce_repo = MagicMock()
    return AdminScope(signer=signer, caller_repo=caller_repo, audit_repo=audit_repo, nonce_repo=nonce_repo)


class _FakeAdminScopeCM:
    async def __aenter__(self) -> AdminScope:
        return _fake_admin_scope()

    async def __aexit__(self, *args: object) -> None:
        pass


def _make_callers_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    policy: Policy | None,
) -> TestClient:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    fast_app = FastAPI()
    fast_app.include_router(callers_router)
    fast_app.dependency_overrides[get_admin_scope] = lambda: _FakeAdminScopeCM()

    if policy is not None:
        fast_app.state.policy = policy
    # When policy is None, app.state has no 'policy' attribute — simulates
    # bootstrap mode where no policy file has been loaded yet.

    return TestClient(fast_app, raise_server_exceptions=False)


def _make_wallets_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    policy: Policy | None,
) -> TestClient:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    fast_app = FastAPI()
    fast_app.include_router(wallets_router)
    fast_app.dependency_overrides[get_admin_scope] = lambda: _FakeAdminScopeCM()

    if policy is not None:
        fast_app.state.policy = policy

    return TestClient(fast_app, raise_server_exceptions=False)


_ADMIN_HDR = {"Authorization": "Bearer admin-secret"}


# ---------------------------------------------------------------------------
# Caller endpoint policy_path validation
# ---------------------------------------------------------------------------


def test_post_callers_unknown_policy_path_returns_400(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """policy_path not in policy.permissions → 400 unknown_policy_path."""
    policy = _make_minimal_policy()
    client = _make_callers_client(monkeypatch, policy=policy)

    r = client.post(
        "/v1/admin/callers",
        json={"name": "svc", "policy_path": "perm/does-not-exist"},
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["detail"]["error"] == "unknown_policy_path"


def test_post_callers_valid_policy_path_passes_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid policy_path in policy.permissions → past the 400 check.

    We assert it gets past the 400; the actual use case is mocked via
    patching create_caller so we don't need Vault/DB. If the policy check
    passes, the use case will be invoked (mocked to succeed).
    """
    from unittest.mock import patch

    policy = _make_minimal_policy()
    create_result = CallerCreateResult(
        name="svc",
        api_key="fwd_live_" + "a" * 43,
        api_key_prefix="aaaaaaaa",
        policy_path=POLICY_PATH_VALID_CALLER,
    )

    with patch("fwd.api.callers.create_caller", new=AsyncMock(return_value=create_result)):
        client = _make_callers_client(monkeypatch, policy=policy)
        r = client.post(
            "/v1/admin/callers",
            json={"name": "svc", "policy_path": POLICY_PATH_VALID_CALLER},
            headers=_ADMIN_HDR,
        )
    # Policy check passes → 201 from the (mocked) use case.
    assert r.status_code == 201, r.text


# ---------------------------------------------------------------------------
# Wallet endpoint policy_path validation
# ---------------------------------------------------------------------------


def test_post_wallets_unknown_policy_path_returns_400(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """policy_path not in policy.wallet_constraints → 400 unknown_policy_path."""
    policy = _make_minimal_policy()
    client = _make_wallets_client(monkeypatch, policy=policy)

    r = client.post(
        "/v1/admin/wallets",
        json={"name": "mywallet", "policy_path": "wc/does-not-exist"},
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["detail"]["error"] == "unknown_policy_path"


def test_post_callers_no_policy_skips_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When app.state has no 'policy' attribute (bootstrap), the check is skipped.

    The request must NOT receive a 400 unknown_policy_path. It will fail at
    the use-case level (AdminScopeCM is faked; create_caller is not patched)
    — that's fine; we only care it gets past the 400 guard.
    """
    from unittest.mock import patch

    # policy=None → app.state has no 'policy' set (bootstrap mode).
    create_result = CallerCreateResult(
        name="svc",
        api_key="fwd_live_" + "a" * 43,
        api_key_prefix="aaaaaaaa",
        policy_path="perm/anything",
    )

    with patch("fwd.api.callers.create_caller", new=AsyncMock(return_value=create_result)):
        client = _make_callers_client(monkeypatch, policy=None)
        r = client.post(
            "/v1/admin/callers",
            json={"name": "svc", "policy_path": "perm/anything-goes"},
            headers=_ADMIN_HDR,
        )
    # Must not be 400 unknown_policy_path when no policy is loaded.
    assert r.status_code != 400 or (
        r.status_code == 400 and r.json()["detail"].get("error") != "unknown_policy_path"
    ), f"Unexpected unknown_policy_path 400 in bootstrap mode: {r.text}"
    # Actually it should be 201 since create_caller is mocked.
    assert r.status_code == 201, r.text
