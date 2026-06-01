"""CLI unit tests for clifwd nonce init.

Mirrors the harness in test_cli_wallets.py:
- typer.testing.CliRunner
- HTTP calls mocked via unittest.mock.patch at fwd.cli.nonce.httpx.post.
- FWD_ADMIN_KEY set/unset via monkeypatch.

asyncio_mode = "auto" (set in pyproject.toml).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import httpx
from typer.testing import CliRunner

from fwd.cli.main import app

if TYPE_CHECKING:
    import pytest

runner = CliRunner()

_NONCE_INIT_CMD = ["nonce", "init", "--wallet", "alice", "--chain", "114", "--starting-nonce", "0"]


# ---------------------------------------------------------------------------
# clifwd nonce init
# ---------------------------------------------------------------------------


def test_nonce_init_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """201 response → exit code 0; correct JSON body + Bearer header posted."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    fake = MagicMock(
        status_code=201,
        text='{"wallet":"alice","chain":114,"next_nonce":0}',
    )
    with patch("fwd.cli.nonce.httpx.post", return_value=fake) as mock_post:
        result = runner.invoke(app, _NONCE_INIT_CMD)

    assert result.exit_code == 0, result.stdout + (result.stderr or "")

    # Verify the correct URL + payload + auth header.
    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert call_kwargs.args[0] == "http://127.0.0.1:8080/v1/admin/nonce-init"
    sent_json = call_kwargs.kwargs["json"]
    assert sent_json["wallet"] == "alice"
    assert sent_json["chain"] == 114
    assert sent_json["starting_nonce"] == 0
    sent_headers = call_kwargs.kwargs["headers"]
    assert sent_headers["Authorization"] == "Bearer admin-key"


def test_nonce_init_missing_admin_key_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset FWD_ADMIN_KEY → exit code 2, no HTTP call made."""
    monkeypatch.delenv("FWD_ADMIN_KEY", raising=False)
    with patch("fwd.cli.nonce.httpx.post") as mock_post:
        result = runner.invoke(app, _NONCE_INIT_CMD)

    assert result.exit_code == 2
    mock_post.assert_not_called()

    # stderr should mention the env var.
    combined = (result.stdout or "") + (result.stderr or "")
    assert "FWD_ADMIN_KEY" in combined


def test_nonce_init_non_201_response_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    """409 (already_initialized) → exit code 1."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(
        status_code=409,
        text='{"detail":{"error":"nonce_already_initialized","message":"..."}}',
    )
    with patch("fwd.cli.nonce.httpx.post", return_value=fake):
        result = runner.invoke(app, _NONCE_INIT_CMD)

    assert result.exit_code == 1


def test_nonce_init_unreachable_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Network error → exit code 2."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    with patch(
        "fwd.cli.nonce.httpx.post",
        side_effect=httpx.ConnectError("connection refused"),
    ):
        result = runner.invoke(app, _NONCE_INIT_CMD)

    assert result.exit_code == 2


def test_nonce_init_force_flag_sends_force_true_in_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """--force sends force: true in the JSON body."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    fake = MagicMock(
        status_code=201,
        text='{"wallet":"alice","chain":114,"next_nonce":0}',
    )
    with patch("fwd.cli.nonce.httpx.post", return_value=fake) as mock_post:
        result = runner.invoke(
            app, ["nonce", "init", "--wallet", "alice", "--chain", "114", "--starting-nonce", "0", "--force"]
        )

    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    mock_post.assert_called_once()
    sent_json = mock_post.call_args.kwargs["json"]
    assert sent_json["force"] is True


def test_nonce_init_no_force_flag_sends_force_false_in_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """Omitting --force sends force: false in the JSON body."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    fake = MagicMock(
        status_code=201,
        text='{"wallet":"alice","chain":114,"next_nonce":0}',
    )
    with patch("fwd.cli.nonce.httpx.post", return_value=fake) as mock_post:
        result = runner.invoke(app, _NONCE_INIT_CMD)

    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    mock_post.assert_called_once()
    sent_json = mock_post.call_args.kwargs["json"]
    assert sent_json["force"] is False
