"""CLI tests for `clifwd bundle compose` (stdin tuples -> stdout bundle JSON)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from fwd.cli.main import app

runner = CliRunner()

_TOKEN = "fwd_live_" + "a" * 43


def _line(cid: str, env: str, token: str, wallet: str) -> str:
    return "\t".join([cid, env, token, wallet])


def test_bundle_compose_emits_v1_json() -> None:
    stdin = (
        _line("clif/songbird/claim", "FWD_CALLER_TOKEN", _TOKEN, "claimer-songbird") + "\n"
    )
    result = runner.invoke(app, ["bundle", "compose", "--network", "songbird"], input=stdin)
    assert result.exit_code == 0, result.output
    bundle = json.loads(result.stdout)
    assert bundle["version"] == 1
    assert bundle["consumer"] == "clif"
    assert bundle["network"] == "songbird"
    assert bundle["capabilities"][0]["capability_id"] == "clif/songbird/claim"
    assert bundle["capabilities"][0]["caller_token"] == _TOKEN


def test_bundle_compose_empty_wallet_becomes_null() -> None:
    stdin = _line("clif/songbird/fsp-sign", "FSP_SIGN_CALLER_TOKEN", _TOKEN, "") + "\n"
    result = runner.invoke(app, ["bundle", "compose", "--network", "songbird"], input=stdin)
    assert result.exit_code == 0
    assert json.loads(result.stdout)["capabilities"][0]["wallet_name"] is None


def test_bundle_compose_malformed_line_exits_2_without_leaking_token() -> None:
    # 3 fields instead of 4.
    stdin = "clif/songbird/claim\tFWD_CALLER_TOKEN\t" + _TOKEN + "\n"
    result = runner.invoke(app, ["bundle", "compose", "--network", "songbird"], input=stdin)
    assert result.exit_code == 2
    combined = (result.stdout or "") + (result.stderr or "")
    assert _TOKEN not in combined  # the offending line (with the token) is never echoed


def test_bundle_compose_empty_stdin_exits_2() -> None:
    result = runner.invoke(app, ["bundle", "compose", "--network", "songbird"], input="")
    assert result.exit_code == 2


def test_bundle_compose_private_key_refused_core7() -> None:
    stdin = _line("clif/songbird/claim", "FWD_PRIVATE_KEY", _TOKEN, "w") + "\n"
    result = runner.invoke(app, ["bundle", "compose", "--network", "songbird"], input=stdin)
    assert result.exit_code == 2
    assert "PRIVATE_KEY" in ((result.stdout or "") + (result.stderr or ""))
