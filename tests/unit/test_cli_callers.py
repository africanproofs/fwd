"""CLI unit tests for clifwd callers create | list | revoke.

Uses typer.testing.CliRunner. HTTP calls mocked via unittest.mock.patch
at the cli.callers module's httpx attribute.

Closes audit deferral F6.3 (CLI test coverage) for callers commands.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest  # noqa: TC002
from typer.testing import CliRunner

from fwd.cli.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# clifwd callers create
# ---------------------------------------------------------------------------


def test_callers_create_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    api_key = "fwd_live_" + "z" * 43
    fake = MagicMock(
        status_code=201,
        json=lambda: {
            "name": "ftso-fee-claimer-prod",
            "policy_path": "policies/ftso.yaml",
            "api_key_prefix": "fwd_live",
            "api_key": api_key,
        },
    )
    with patch("fwd.cli.callers.httpx.post", return_value=fake):
        result = runner.invoke(
            app,
            [
                "callers",
                "create",
                "--name",
                "ftso-fee-claimer-prod",
                "--policy",
                "policies/ftso.yaml",
            ],
        )
    assert result.exit_code == 0
    # API key is printed to stdout for shell capture.
    assert api_key in result.stdout


def test_callers_create_missing_admin_key_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FWD_ADMIN_KEY", raising=False)
    # Even though FWD_ADMIN_KEY is missing, cli/callers.py reads it inside
    # _admin_headers() which is called as part of httpx.post(headers=...)
    # before the request is made. Patch httpx.post to a sentinel so we can
    # confirm the call never happens.
    with patch("fwd.cli.callers.httpx.post") as mock_post:
        result = runner.invoke(
            app,
            ["callers", "create", "--name", "x", "--policy", "p"],
        )
    assert result.exit_code == 2
    mock_post.assert_not_called()


def test_callers_create_409_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=409, text='{"error": "caller_exists"}')
    with patch("fwd.cli.callers.httpx.post", return_value=fake):
        result = runner.invoke(
            app,
            ["callers", "create", "--name", "dup", "--policy", "p"],
        )
    assert result.exit_code == 3


def test_callers_create_unreachable_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    with patch(
        "fwd.cli.callers.httpx.post",
        side_effect=httpx.ConnectError("nope"),
    ):
        result = runner.invoke(
            app,
            ["callers", "create", "--name", "x", "--policy", "p"],
        )
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# clifwd callers list
# ---------------------------------------------------------------------------


def test_callers_list_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(
        status_code=200,
        json=lambda: {
            "callers": [
                {
                    "name": "alice",
                    "api_key_prefix": "fwd_live",
                    "policy_path": "policies/a.yaml",
                    "created_at": "2026-05-12T00:00:00+00:00",
                    "revoked_at": None,
                },
                {
                    "name": "bob",
                    "api_key_prefix": "fwd_live",
                    "policy_path": "policies/b.yaml",
                    "created_at": "2026-05-12T00:01:00+00:00",
                    "revoked_at": "2026-05-12T00:05:00+00:00",
                },
            ]
        },
    )
    with patch("fwd.cli.callers.httpx.get", return_value=fake):
        result = runner.invoke(app, ["callers", "list"])
    assert result.exit_code == 0
    assert "alice" in result.stdout
    assert "active" in result.stdout
    assert "REVOKED" in result.stdout


def test_callers_list_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=200, json=lambda: {"callers": []})
    with patch("fwd.cli.callers.httpx.get", return_value=fake):
        result = runner.invoke(app, ["callers", "list"])
    assert result.exit_code == 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "(no callers)" in combined


def test_callers_list_missing_admin_key_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FWD_ADMIN_KEY", raising=False)
    with patch("fwd.cli.callers.httpx.get") as mock_get:
        result = runner.invoke(app, ["callers", "list"])
    assert result.exit_code == 2
    mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# clifwd callers revoke
# ---------------------------------------------------------------------------


def test_callers_revoke_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=204)
    with patch("fwd.cli.callers.httpx.delete", return_value=fake):
        result = runner.invoke(app, ["callers", "revoke", "--name", "alice"])
    assert result.exit_code == 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "revoked" in combined.lower()


def test_callers_revoke_404_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=404, text='{"error": "caller_not_found"}')
    with patch("fwd.cli.callers.httpx.delete", return_value=fake):
        result = runner.invoke(app, ["callers", "revoke", "--name", "nobody"])
    assert result.exit_code == 4


def test_callers_revoke_409_exits_5(monkeypatch: pytest.MonkeyPatch) -> None:
    """Caller already revoked -> exit 5."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=409, text='{"error": "caller_already_revoked"}')
    with patch("fwd.cli.callers.httpx.delete", return_value=fake):
        result = runner.invoke(app, ["callers", "revoke", "--name", "alice"])
    assert result.exit_code == 5
