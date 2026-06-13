"""CLI tests for `clifwd capability {grant,list}`.

`grant`: render path needs no daemon; the --approve mint path mocks httpx.post at
the cli.capability module. Verifies default-deny (no mint without --approve), the
re-rendered custody diff, capability_id threaded into each mint, and no token
value leaking anywhere except the documented return-once stdout line.

`list`: the read-only doctor 'fwd=granted' leg (admin-gated GET
/v1/admin/capabilities; --json scrape; no token value).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest  # noqa: TC002
from typer.testing import CliRunner

from fwd.cli.main import app

runner = CliRunner()

_SPEC = json.dumps(
    {
        "consumer": "clif",
        "network": "songbird",
        "compat": {"fwd_contract_expected": "v1.1.0a69", "fwd_client": "0.1.0", "clif": "0.5.37"},
        "capabilities": [
            {
                "capability_id": "clif/songbird/claim",
                "role": "claim",
                "endpoint": "/v1/sign-transaction",
                "caller_token_env": "FWD_CALLER_TOKEN",
                "wallet_env": "FWD_WALLET_NAME",
                "wallet_name": "claimer-songbird",
                "contract": "0xE26AD68b17224951b5740F33926Cc438764eB9a7",
                "contract_name": "RewardManager",
                "method": "claim(address,address,uint24,bool,(bytes32[],(uint24,bytes20,uint120,uint8))[])",
                "value_wei": "0",
                "recipient_pinned": "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294",
                "suggested_rate": "8/day",
            }
        ],
    }
)


def _combined(result: object) -> str:
    return (getattr(result, "stdout", "") or "") + (getattr(result, "stderr", "") or "")


def test_grant_render_only_default_deny() -> None:
    """No --approve: renders the diff + plan, mints nothing (default-deny)."""
    with patch("fwd.cli.capability.httpx.post") as mock_post:
        result = runner.invoke(app, ["capability", "grant"], input=_SPEC)
    assert result.exit_code == 0
    out = _combined(result)
    assert "clif/songbird/claim" in out
    assert "approve / reject" in out
    assert "review-only" in out
    mock_post.assert_not_called()


def test_grant_invalid_spec_exits_2() -> None:
    result = runner.invoke(app, ["capability", "grant"], input="{not json")
    assert result.exit_code == 2
    assert "INVALID spec" in _combined(result)


def test_grant_empty_stdin_exits_2() -> None:
    result = runner.invoke(app, ["capability", "grant"], input="")
    assert result.exit_code == 2


def test_grant_approve_mints_with_capability_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    token = "fwd_live_" + "a" * 43
    fake = MagicMock(
        status_code=201,
        json=lambda: {"name": "claim-songbird", "api_key_prefix": "aaaaaaaa", "api_key": token},
    )
    with patch("fwd.cli.capability.httpx.post", return_value=fake) as mock_post:
        result = runner.invoke(app, ["capability", "grant", "--approve"], input=_SPEC)
    assert result.exit_code == 0
    # capability_id + derived name/policy_path threaded into the mint.
    sent = mock_post.call_args.kwargs["json"]
    assert sent["capability_id"] == "clif/songbird/claim"
    assert sent["name"] == "claim-songbird"
    assert sent["policy_path"] == "perm/claim-songbird"
    # The return-once token is emitted to stdout as <env>=<token> for capture.
    assert f"FWD_CALLER_TOKEN={token}" in result.stdout


def test_grant_approve_409_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=409, text='{"error":"caller_exists"}')
    with patch("fwd.cli.capability.httpx.post", return_value=fake):
        result = runner.invoke(app, ["capability", "grant", "--approve"], input=_SPEC)
    assert result.exit_code == 1
    assert "exists" in _combined(result)


def test_grant_approve_missing_admin_key_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FWD_ADMIN_KEY", raising=False)
    with patch("fwd.cli.capability.httpx.post") as mock_post:
        result = runner.invoke(app, ["capability", "grant", "--approve"], input=_SPEC)
    assert result.exit_code == 2
    mock_post.assert_not_called()


def test_grant_emit_bundle_writes_0600_no_stdout_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """--approve --emit-bundle: token -> 0600 bundle, NEVER stdout; --replace threaded."""
    import stat
    from pathlib import Path

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    token = "fwd_live_" + "a" * 43
    fake = MagicMock(
        status_code=201,
        json=lambda: {"name": "claim-songbird", "api_key_prefix": "aaaaaaaa", "api_key": token},
    )
    out = Path(str(tmp_path)) / ".fwd-bundle.songbird.json"
    with patch("fwd.cli.capability.httpx.post", return_value=fake) as mock_post:
        result = runner.invoke(
            app,
            [
                "capability", "grant", "--approve", "--replace",
                "--emit-bundle", str(out), "--config", "NETWORK=songbird",
            ],
            input=_SPEC,
        )
    assert result.exit_code == 0, result.output
    assert token not in (result.stdout or "")  # NEVER on stdout
    assert out.is_file()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    bundle = json.loads(out.read_text())
    assert bundle["capabilities"][0]["caller_token"] == token
    assert bundle["network"] == "songbird"
    assert mock_post.call_args.kwargs["json"]["replace"] is True


def test_grant_emit_bundle_partial_failure_writes_no_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """Fail-closed: a 409 on any capability ⇒ no (partial) bundle, exit 1."""
    from pathlib import Path

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=409, text='{"error":"caller_exists"}')
    out = Path(str(tmp_path)) / ".fwd-bundle.songbird.json"
    with patch("fwd.cli.capability.httpx.post", return_value=fake):
        result = runner.invoke(
            app,
            [
                "capability", "grant", "--approve",
                "--emit-bundle", str(out), "--config", "NETWORK=songbird",
            ],
            input=_SPEC,
        )
    assert result.exit_code == 1
    assert not out.exists()


_SPEC_NULL_WALLET = json.dumps(
    {
        "consumer": "clif",
        "network": "songbird",
        "compat": {"fwd_contract_expected": "v1.1.0a69", "fwd_client": "0.1.0", "clif": "0.5.37"},
        "capabilities": [
            {
                "capability_id": "clif/songbird/claim",
                "role": "claim",
                "endpoint": "/v1/sign-transaction",
                "caller_token_env": "FWD_CALLER_TOKEN",
                "wallet_env": "FWD_WALLET_NAME",
                "wallet_name": None,  # not yet configured
                "contract": "0xE26AD68b17224951b5740F33926Cc438764eB9a7",
                "contract_name": "RewardManager",
                "method": "claim(address,address,uint24,bool,(bytes32[],(uint24,bytes20,uint120,uint8))[])",
                "value_wei": "0",
                "recipient_pinned": "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294",
                "suggested_rate": "8/day",
            }
        ],
    }
)


def test_grant_emit_bundle_v2_full_config_and_wallets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """--emit-bundle with --config NETWORK + another key → conformant v2 bundle."""
    from pathlib import Path

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    token = "fwd_live_" + "a" * 43
    fake = MagicMock(
        status_code=201,
        json=lambda: {"name": "claim-songbird", "api_key_prefix": "aaaaaaaa", "api_key": token},
    )
    out = Path(str(tmp_path)) / ".fwd-bundle.songbird.json"
    with patch("fwd.cli.capability.httpx.post", return_value=fake):
        result = runner.invoke(
            app,
            [
                "capability", "grant", "--approve", "--emit-bundle", str(out),
                "--config", "NETWORK=songbird",
                "--config", "FWD_ENDPOINT=http://fwd:8080",
            ],
            input=_SPEC,
        )
    assert result.exit_code == 0, result.output
    bundle = json.loads(out.read_text())
    assert bundle["version"] == 2
    assert bundle["config"] == {"NETWORK": "songbird", "FWD_ENDPOINT": "http://fwd:8080"}
    assert all(c["wallet_name"] for c in bundle["capabilities"])


def test_grant_emit_bundle_missing_network_refused_pre_mint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """No --config NETWORK → exit 2 BEFORE any mint (the pre-mint conformance gate)."""
    from pathlib import Path

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    out = Path(str(tmp_path)) / ".fwd-bundle.songbird.json"
    with patch("fwd.cli.capability.httpx.post") as mock_post:
        result = runner.invoke(
            app,
            ["capability", "grant", "--approve", "--emit-bundle", str(out)],
            input=_SPEC,
        )
    assert result.exit_code == 2
    assert "NETWORK=songbird is required" in _combined(result)
    mock_post.assert_not_called()  # refused before minting (tokens are return-once)
    assert not out.exists()


def test_grant_emit_bundle_network_contradiction_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """--config NETWORK disagreeing with the spec's network → exit 2, 'contradicts'."""
    from pathlib import Path

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    out = Path(str(tmp_path)) / ".fwd-bundle.songbird.json"
    with patch("fwd.cli.capability.httpx.post") as mock_post:
        result = runner.invoke(
            app,
            [
                "capability", "grant", "--approve", "--emit-bundle", str(out),
                "--config", "NETWORK=flare",
            ],
            input=_SPEC,
        )
    assert result.exit_code == 2
    assert "contradicts" in _combined(result)
    mock_post.assert_not_called()


def test_grant_emit_bundle_null_wallet_refused_pre_mint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """A spec capability with a null wallet_name → exit 2 BEFORE any mint."""
    from pathlib import Path

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    out = Path(str(tmp_path)) / ".fwd-bundle.songbird.json"
    with patch("fwd.cli.capability.httpx.post") as mock_post:
        result = runner.invoke(
            app,
            [
                "capability", "grant", "--approve", "--emit-bundle", str(out),
                "--config", "NETWORK=songbird",
            ],
            input=_SPEC_NULL_WALLET,
        )
    assert result.exit_code == 2
    assert "no configured wallet" in _combined(result)
    mock_post.assert_not_called()
    assert not out.exists()


def test_grant_emit_bundle_private_key_config_refused_by_guard(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """A *PRIVATE_KEY* config key trips the Core-#7 guard in compose_bundle (no bundle)."""
    from pathlib import Path

    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    token = "fwd_live_" + "a" * 43
    fake = MagicMock(
        status_code=201,
        json=lambda: {"name": "claim-songbird", "api_key_prefix": "aaaaaaaa", "api_key": token},
    )
    out = Path(str(tmp_path)) / ".fwd-bundle.songbird.json"
    with patch("fwd.cli.capability.httpx.post", return_value=fake):
        result = runner.invoke(
            app,
            [
                "capability", "grant", "--approve", "--emit-bundle", str(out),
                "--config", "NETWORK=songbird",
                "--config", "SOME_PRIVATE_KEY=0xdead",
            ],
            input=_SPEC,
        )
    assert result.exit_code != 0
    assert not out.exists()  # the guard refuses to WRITE a secret


def test_grant_malformed_config_item_exits_2() -> None:
    """A --config item without '=' → exit 2."""
    result = runner.invoke(
        app,
        ["capability", "grant", "--approve", "--emit-bundle", "/tmp/x", "--config", "NOEQUALS"],
        input=_SPEC,
    )
    assert result.exit_code == 2
    assert "malformed --config" in _combined(result)


# --- capability list (the doctor fwd=granted leg) ---------------------------

_CAPS_BODY = {
    "capabilities": [
        {
            "capability_id": "clif/songbird/claim",
            "caller_name": "claim-songbird",
            "policy_path": "perm/claim-songbird",
            "status": "active",
            "granted_at": "2026-01-01T00:00:00+00:00",
            "revoked_at": None,
        }
    ]
}


def test_capability_list_human_table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=200, json=lambda: _CAPS_BODY)
    with patch("fwd.cli.capability.httpx.get", return_value=fake):
        result = runner.invoke(app, ["capability", "list"])
    assert result.exit_code == 0
    assert "clif/songbird/claim" in result.stdout
    assert "active" in result.stdout


def test_capability_list_json_parseable_and_secretless(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    raw = json.dumps(_CAPS_BODY)
    fake = MagicMock(status_code=200, text=raw, json=lambda: _CAPS_BODY)
    with patch("fwd.cli.capability.httpx.get", return_value=fake):
        result = runner.invoke(app, ["capability", "list", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["capabilities"][0]["capability_id"] == "clif/songbird/claim"
    assert "hash" not in result.stdout.lower()
    assert "api_key" not in result.stdout
    assert "fwd_live_" not in result.stdout


def test_capability_list_missing_admin_key_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FWD_ADMIN_KEY", raising=False)
    with patch("fwd.cli.capability.httpx.get") as mock_get:
        result = runner.invoke(app, ["capability", "list"])
    assert result.exit_code == 2
    mock_get.assert_not_called()


def test_capability_list_http_error_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=500, text='{"error":"internal"}')
    with patch("fwd.cli.capability.httpx.get", return_value=fake):
        result = runner.invoke(app, ["capability", "list"])
    assert result.exit_code == 1


def test_capability_list_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=200, json=lambda: {"capabilities": []})
    with patch("fwd.cli.capability.httpx.get", return_value=fake):
        result = runner.invoke(app, ["capability", "list"])
    assert result.exit_code == 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "(no granted capabilities)" in combined
