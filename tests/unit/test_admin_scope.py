"""Unit tests for AdminScope / AdminScopeCM.

Verifies that AdminScopeCM yields an AdminScope with signer, caller_repo,
and audit_repo all backed by the same session (D16 atomicity requirement).

We mock VaultClient to avoid needing a live Vault in unit tests — the same
pattern used by test_sign_and_send.py for RequestScopeCM.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from fwd.app.dependencies import AdminScope, AdminScopeCM


def _make_mock_vault_client() -> MagicMock:
    """Return a mock VaultClient that acts as a working async context manager."""
    vault = MagicMock()
    vault.__aenter__ = AsyncMock(return_value=vault)
    vault.__aexit__ = AsyncMock(return_value=None)
    return vault


@pytest.mark.asyncio
async def test_admin_scope_cm_yields_admin_scope(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """AdminScopeCM yields an AdminScope dataclass with the three expected fields."""
    db = tmp_path / "test_admin_scope.db"

    mock_vault = _make_mock_vault_client()

    with (
        patch("fwd.app.dependencies.VaultClient", return_value=mock_vault),
        patch(
            "fwd.app.dependencies.session_scope",
            return_value=_make_mock_session_cm(db),
        ),
    ):
        cm = AdminScopeCM()
        async with cm as scope:
            assert isinstance(scope, AdminScope)
            assert scope.signer is not None
            assert scope.caller_repo is not None
            assert scope.audit_repo is not None


@pytest.mark.asyncio
async def test_admin_scope_caller_repo_and_audit_repo_share_session(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """caller_repo and audit_repo must share the same underlying session.

    We verify this by inspecting that both repos were constructed with the
    same session object (same identity). This is the D16 atomicity guarantee:
    both the use-case mutation and the audit row commit atomically under one
    BEGIN IMMEDIATE per AdminScopeCM.
    """
    from fwd.infra.audit_repo import AuditRepo
    from fwd.infra.caller_repo import CallerRepo

    db = tmp_path / "test_admin_scope_shared.db"
    captured_sessions: list[object] = []

    original_caller_repo_init = CallerRepo.__init__
    original_audit_repo_init = AuditRepo.__init__

    def _capturing_caller_repo_init(self: CallerRepo, session: object) -> None:
        captured_sessions.append(("caller_repo", session))
        original_caller_repo_init(self, session)  # type: ignore[arg-type]

    def _capturing_audit_repo_init(self: AuditRepo, session: object) -> None:
        captured_sessions.append(("audit_repo", session))
        original_audit_repo_init(self, session)  # type: ignore[arg-type]

    mock_vault = _make_mock_vault_client()

    with (
        patch("fwd.app.dependencies.VaultClient", return_value=mock_vault),
        patch("fwd.app.dependencies.session_scope", return_value=_make_mock_session_cm(db)),
        patch.object(CallerRepo, "__init__", _capturing_caller_repo_init),
        patch.object(AuditRepo, "__init__", _capturing_audit_repo_init),
    ):
        async with AdminScopeCM():
            pass

    # Both repos must have been initialised.
    assert len(captured_sessions) >= 2
    caller_sessions = [s for label, s in captured_sessions if label == "caller_repo"]
    audit_sessions = [s for label, s in captured_sessions if label == "audit_repo"]
    assert caller_sessions, "CallerRepo was not constructed"
    assert audit_sessions, "AuditRepo was not constructed"
    # They share the same session object.
    assert caller_sessions[0] is audit_sessions[0], (
        "caller_repo and audit_repo were constructed with DIFFERENT sessions — "
        "D16 atomicity violated"
    )


@pytest.mark.asyncio
async def test_get_admin_scope_returns_admin_scope_cm() -> None:
    """get_admin_scope() is the DI factory; it must return an AdminScopeCM."""
    from fwd.app.dependencies import get_admin_scope

    result = get_admin_scope()
    assert isinstance(result, AdminScopeCM)


# ---------------------------------------------------------------------------
# Helper: minimal async context-manager that returns a real (tmp) session
# ---------------------------------------------------------------------------


def _make_mock_session_cm(db_path: object) -> MagicMock:
    """Return a mock that mimics session_scope() by yielding a real AsyncSession.

    We use a real engine so CallerRepo / AuditRepo / WalletRepo table
    accesses don't explode during init (they're lazy; construction itself
    just stores the session).
    """
    from sqlalchemy.ext.asyncio import AsyncSession

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    session = AsyncSession(engine)

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm
