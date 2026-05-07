"""D11 bright-line attestation: admin auth and caller auth are fully isolated.

Per decisions.md D11: api/caller_auth.py is a SEPARATE module from
api/admin_auth.py. It does NOT import from admin_auth. There is NO
fallback bridge: an admin token presented to a caller endpoint returns
401 exactly as a forged token would.

These tests are the canonical enforcement point for D11.  If ANY of
these tests fail, the bright line has been broken and the ship is
unsound — STOP and fix before any other verification proceeds.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest  # noqa: TC002
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fwd import settings as settings_mod

# ---------------------------------------------------------------------------
# Structural checks (import-graph)
# ---------------------------------------------------------------------------


def _ast_imports(module_path: Path) -> list[str]:
    """Return all module names imported (directly or from) by the file at path."""
    tree = ast.parse(module_path.read_text())
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    return imports


def test_caller_auth_does_not_import_admin_auth() -> None:
    """D11: api/caller_auth.py must NOT import from api/admin_auth at the AST level."""
    src_root = Path(__file__).parent.parent.parent / "src" / "fwd" / "api"
    caller_auth_path = src_root / "caller_auth.py"
    imports = _ast_imports(caller_auth_path)
    forbidden = [m for m in imports if "admin_auth" in m]
    assert (
        forbidden == []
    ), f"D11 VIOLATION: api/caller_auth.py imports from admin_auth: {forbidden}"


def test_caller_auth_does_not_import_admin_auth_transitively() -> None:
    """D11: the loaded module must not have admin_auth in its namespace at all."""
    if "fwd.api.caller_auth" in sys.modules:
        del sys.modules["fwd.api.caller_auth"]
    mod = importlib.import_module("fwd.api.caller_auth")
    members = dict(inspect.getmembers(mod))
    admin_auth_leak = [
        name
        for name, obj in members.items()
        if hasattr(obj, "__module__") and "admin_auth" in (obj.__module__ or "")
    ]
    assert (
        admin_auth_leak == []
    ), f"D11 VIOLATION: api/caller_auth.py exposes admin_auth symbols: {admin_auth_leak}"


def test_admin_auth_does_not_import_caller_auth() -> None:
    """Symmetric: api/admin_auth.py must NOT import from api/caller_auth."""
    src_root = Path(__file__).parent.parent.parent / "src" / "fwd" / "api"
    admin_auth_path = src_root / "admin_auth.py"
    imports = _ast_imports(admin_auth_path)
    forbidden = [m for m in imports if "caller_auth" in m]
    assert (
        forbidden == []
    ), f"D11 VIOLATION: api/admin_auth.py imports from caller_auth: {forbidden}"


# ---------------------------------------------------------------------------
# Behavioural check: admin token on caller endpoint → 401
# ---------------------------------------------------------------------------


def _make_sign_app() -> tuple[FastAPI, str]:
    """Return a minimal app wiring require_caller and an admin key."""
    from fwd.api.caller_auth import caller_required
    from fwd.app.dependencies import get_caller_repo
    from fwd.infra.caller_repo import Caller  # noqa: TC001

    # Resolve always returns None (simulates no matching caller).
    class _FakeRepoCM:
        async def __aenter__(self) -> MagicMock:
            mock_repo = MagicMock()
            mock_repo.list_by_prefix_active = AsyncMock(return_value=[])
            return mock_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    app = FastAPI()
    app.dependency_overrides[get_caller_repo] = lambda: _FakeRepoCM()

    @app.get("/v1/sign-and-send")
    async def _probe(caller: Caller = caller_required) -> dict[str, str]:  # type: ignore[assignment]
        return {"ok": "yes"}

    return app, "my-admin-token"


def test_admin_token_on_caller_endpoint_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D11 live: presenting the admin token to a caller-auth endpoint returns 401.

    The admin token is correct (accepted by require_admin on admin/* routes),
    but must be rejected by require_caller as if it were a forged key.
    """
    admin_key = "my-admin-token"
    monkeypatch.setenv("FWD_ADMIN_KEY", admin_key)
    settings_mod.get_settings.cache_clear()

    app, _ = _make_sign_app()

    with patch("fwd.api.caller_auth.resolve_caller", new=AsyncMock(return_value=None)):
        client = TestClient(app, raise_server_exceptions=False)
        r = client.get(
            "/v1/sign-and-send",
            headers={"Authorization": f"Bearer {admin_key}"},
        )

    assert (
        r.status_code == 401
    ), f"D11 VIOLATION: admin token accepted by caller-auth endpoint (got {r.status_code})"


def test_no_bearer_on_caller_endpoint_returns_401() -> None:
    """D11 baseline: missing auth also returns 401 (not 403 or 500)."""
    app, _ = _make_sign_app()
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/v1/sign-and-send")
    assert r.status_code == 401


def test_caller_token_on_admin_endpoint_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Symmetric D11: a valid caller bearer token must be rejected on admin/* routes.

    Admin routes use require_admin (FWD_ADMIN_KEY hmac check). A caller
    token is NOT the admin key, so it returns 401.
    """
    monkeypatch.setenv("FWD_ADMIN_KEY", "real-admin-key")
    settings_mod.get_settings.cache_clear()

    from fastapi import Depends

    from fwd.api.admin_auth import require_admin

    app = FastAPI()

    @app.get("/v1/admin/probe", dependencies=[Depends(require_admin)])
    def _admin_probe() -> dict[str, str]:
        return {"ok": "yes"}

    caller_key = "fwd_live_" + "c" * 43
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/v1/admin/probe", headers={"Authorization": f"Bearer {caller_key}"})
    assert (
        r.status_code == 401
    ), f"D11 VIOLATION: caller token accepted on admin endpoint (got {r.status_code})"
