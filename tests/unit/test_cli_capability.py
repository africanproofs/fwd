"""CLI tests for `clifwd capability grant`.

Render path needs no daemon; the --approve mint path mocks httpx.post at the
cli.capability module. Verifies default-deny (no mint without --approve), the
re-rendered custody diff, capability_id threaded into each mint, and no token
value leaking anywhere except the documented return-once stdout line.
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
