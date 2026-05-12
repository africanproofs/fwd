"""CLI unit tests for clifwd version + health subcommands.

Uses typer.testing.CliRunner. HTTP calls mocked via unittest.mock.patch.
Closes audit deferral F6.3 (CLI test coverage) for the top-level commands.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest  # noqa: TC002
from typer.testing import CliRunner

from fwd.cli.main import app
from fwd.version import __version__

runner = CliRunner()


def test_version_prints_version_string() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_health_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    fake = MagicMock(
        status_code=200,
        text='{"fwd": "ok", "vault": "ok", "rpc": "ok"}',
    )
    with patch("fwd.cli.main.httpx.get", return_value=fake):
        result = runner.invoke(app, ["health"])
    assert result.exit_code == 0
    assert "ok" in result.stdout


def test_health_unreachable_exits_nonzero() -> None:
    with patch("fwd.cli.main.httpx.get", side_effect=httpx.ConnectError("nope")):
        result = runner.invoke(app, ["health"])
    assert result.exit_code != 0


def test_health_5xx_exits_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    fake = MagicMock(status_code=503, text='{"vault": "sealed"}')
    with patch("fwd.cli.main.httpx.get", return_value=fake):
        result = runner.invoke(app, ["health"])
    # cli/main.py exits 0 only on 200; non-200 -> exit 1.
    assert result.exit_code == 1


def test_health_uses_fwd_url_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """When FWD_URL is set, the GET call targets that URL/healthz."""
    monkeypatch.setenv("FWD_URL", "http://example.test:9000")
    fake = MagicMock(status_code=200, text="{}")
    with patch("fwd.cli.main.httpx.get", return_value=fake) as mock_get:
        runner.invoke(app, ["health"])
    # First positional arg is the URL.
    args, _ = mock_get.call_args
    assert args[0] == "http://example.test:9000/healthz"
