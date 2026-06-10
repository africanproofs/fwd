"""CLI unit tests for clifwd callers create | list | revoke.

Uses typer.testing.CliRunner. HTTP calls mocked via unittest.mock.patch
at the cli.callers module's httpx attribute.

Closes audit deferral F6.3 (CLI test coverage) for callers commands.
"""

from __future__ import annotations

import json
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


def test_callers_list_json_is_parseable_and_secretless(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--json emits the raw /v1/admin/callers JSON: parseable, no key/hash.

    api_key_prefix is the public prefix and IS allowed; the full api_key and
    any *hash* field are NEVER present (CallerSummary excludes them, Core #12).
    """
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    raw = (
        '{"callers": [{"name": "alice", "api_key_prefix": "fwd_live", '
        '"policy_path": "policies/a.yaml", '
        '"created_at": "2026-05-12T00:00:00+00:00", "revoked_at": null}]}'
    )
    fake = MagicMock(status_code=200, text=raw, json=lambda: json.loads(raw))
    with patch("fwd.cli.callers.httpx.get", return_value=fake):
        result = runner.invoke(app, ["callers", "list", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["callers"][0]["name"] == "alice"
    assert parsed["callers"][0]["api_key_prefix"] == "fwd_live"
    # No secret: full key field absent, no hash anywhere (prefix is allowed).
    assert '"api_key"' not in result.stdout
    assert "hash" not in result.stdout.lower()
    for c in parsed["callers"]:
        assert "api_key" not in c
        assert not any("hash" in k.lower() for k in c)


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


# ---------------------------------------------------------------------------
# clifwd callers create --replace
# ---------------------------------------------------------------------------


def test_callers_create_replace_sends_replace_true(monkeypatch: pytest.MonkeyPatch) -> None:
    """create --replace sends "replace": true in the POST body."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    api_key = "fwd_live_" + "c" * 43
    fake = MagicMock(
        status_code=201,
        json=lambda: {
            "name": "rotating-caller",
            "policy_path": "policies/ftso.yaml",
            "api_key_prefix": "cccccccc",
            "api_key": api_key,
        },
    )
    with patch("fwd.cli.callers.httpx.post", return_value=fake) as mock_post:
        result = runner.invoke(
            app,
            [
                "callers",
                "create",
                "--name",
                "rotating-caller",
                "--policy",
                "policies/ftso.yaml",
                "--replace",
            ],
        )
    assert result.exit_code == 0
    sent_json = mock_post.call_args.kwargs["json"]
    assert sent_json["replace"] is True


def test_callers_create_capability_id_sent_in_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """create --capability-id sends capability_id in the POST body (default None when omitted)."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    api_key = "fwd_live_" + "e" * 43
    fake = MagicMock(
        status_code=201,
        json=lambda: {
            "name": "clif-claim",
            "policy_path": "perm/claim-songbird",
            "api_key_prefix": "eeeeeeee",
            "api_key": api_key,
            "capability_id": "clif/songbird/claim",
        },
    )
    with patch("fwd.cli.callers.httpx.post", return_value=fake) as mock_post:
        result = runner.invoke(
            app,
            [
                "callers",
                "create",
                "--name",
                "clif-claim",
                "--policy",
                "perm/claim-songbird",
                "--capability-id",
                "clif/songbird/claim",
            ],
        )
    assert result.exit_code == 0
    assert mock_post.call_args.kwargs["json"]["capability_id"] == "clif/songbird/claim"


def test_callers_create_no_capability_id_sends_null(monkeypatch: pytest.MonkeyPatch) -> None:
    """Omitting --capability-id sends capability_id=None (back-compat)."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    api_key = "fwd_live_" + "f" * 43
    fake = MagicMock(
        status_code=201,
        json=lambda: {
            "name": "legacy",
            "policy_path": "policies/legacy.yaml",
            "api_key_prefix": "ffffffff",
            "api_key": api_key,
            "capability_id": None,
        },
    )
    with patch("fwd.cli.callers.httpx.post", return_value=fake) as mock_post:
        result = runner.invoke(
            app,
            ["callers", "create", "--name", "legacy", "--policy", "policies/legacy.yaml"],
        )
    assert result.exit_code == 0
    assert mock_post.call_args.kwargs["json"]["capability_id"] is None


def test_callers_create_no_replace_flag_sends_replace_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omitting --replace sends "replace": false in the POST body."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    api_key = "fwd_live_" + "d" * 43
    fake = MagicMock(
        status_code=201,
        json=lambda: {
            "name": "normal-caller",
            "policy_path": "policies/ftso.yaml",
            "api_key_prefix": "dddddddd",
            "api_key": api_key,
        },
    )
    with patch("fwd.cli.callers.httpx.post", return_value=fake) as mock_post:
        result = runner.invoke(
            app,
            [
                "callers",
                "create",
                "--name",
                "normal-caller",
                "--policy",
                "policies/ftso.yaml",
            ],
        )
    assert result.exit_code == 0
    sent_json = mock_post.call_args.kwargs["json"]
    assert sent_json["replace"] is False
