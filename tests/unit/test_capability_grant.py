"""Unit tests for app/capability_grant.py — parse + validate + re-render + plan.

The spec under test mirrors clif's real `spec --json` shape (consumer-contract-v1
§2.1): top-level consumer/network/compat/capabilities[], 12 keys per capability,
capability_ids clif/<net>/{claim,fsp-sign,fsp-submit}.
"""

from __future__ import annotations

import json

import pytest

from fwd.app.capability_grant import (
    CapabilitySpecError,
    parse_spec,
    provisioning_plan,
    render_custody_diff,
)

_VALID_SPEC = {
    "consumer": "claim",
    "network": "songbird",
    "compat": {"fwd_contract_expected": "v1.1.0a69", "fwd_client": "0.1.0", "claim": "0.5.37"},
    "capabilities": [
        {
            "capability_id": "claim/songbird/ftso-reward-claim",
            "role": "ftso-reward-claim",
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
        },
        {
            "capability_id": "claim/songbird/uptime-vote-sign",
            "role": "uptime-vote-sign",
            "endpoint": "/v1/sign-fsp-message",
            "caller_token_env": "FSP_SIGN_CALLER_TOKEN",
            "wallet_env": "FSP_SIGNING_WALLET_NAME",
            "wallet_name": "fsp-signing-songbird",
            "contract": None,
            "contract_name": None,
            "method": "signUptimeVote / signRewards",
            "value_wei": None,
            "recipient_pinned": None,
            "suggested_rate": "16/day",
        },
        {
            "capability_id": "claim/songbird/uptime-vote-submit",
            "role": "uptime-vote-submit",
            "endpoint": "/v1/sign-transaction",
            "caller_token_env": "FSP_SUBMIT_CALLER_TOKEN",
            "wallet_env": "FSP_SENDER_WALLET_NAME",
            "wallet_name": "fsp-sender-songbird",
            "contract": "0x421c69E22f48e14Fc2d2Ee3812c59bfb81c38516",
            "contract_name": "FlareSystemsManager",
            "method": "signUptimeVote / signRewards",
            "value_wei": "0",
            "recipient_pinned": None,
            "suggested_rate": "16/day",
        },
    ],
}


def _spec_text(overrides: dict | None = None) -> str:
    import copy

    spec = copy.deepcopy(_VALID_SPEC)
    if overrides:
        spec.update(overrides)
    return json.dumps(spec)


# --- parse_spec --------------------------------------------------------------


def test_parse_valid_spec() -> None:
    spec = parse_spec(_spec_text())
    assert spec.consumer == "claim"
    assert spec.network == "songbird"
    assert [c.capability_id for c in spec.capabilities] == [
        "claim/songbird/ftso-reward-claim",
        "claim/songbird/uptime-vote-sign",
        "claim/songbird/uptime-vote-submit",
    ]


def test_parse_malformed_json_raises() -> None:
    with pytest.raises(CapabilitySpecError, match="not valid JSON"):
        parse_spec("{not json")


def test_parse_non_object_raises() -> None:
    with pytest.raises(CapabilitySpecError, match="JSON object"):
        parse_spec("[1, 2, 3]")


def test_parse_missing_required_key_raises() -> None:
    spec = json.loads(_spec_text())
    del spec["capabilities"][0]["wallet_name"]  # a required (nullable) key
    with pytest.raises(CapabilitySpecError, match="well-formed"):
        parse_spec(json.dumps(spec))


def test_parse_bad_capability_id_pattern_raises() -> None:
    spec = json.loads(_spec_text())
    spec["capabilities"][0]["capability_id"] = "BAD ID"
    with pytest.raises(CapabilitySpecError):
        parse_spec(json.dumps(spec))


def test_parse_join_mismatch_raises() -> None:
    """capability_id must equal <consumer>/<network>/<role> (ADR Inv #4)."""
    spec = json.loads(_spec_text())
    # claim capability_id says songbird but we flip the network → mismatch.
    spec["network"] = "flare"
    with pytest.raises(CapabilitySpecError, match="join mismatch"):
        parse_spec(json.dumps(spec))


def test_parse_empty_capabilities_raises() -> None:
    with pytest.raises(CapabilitySpecError):
        parse_spec(json.dumps({**_VALID_SPEC, "capabilities": []}))


# --- render_custody_diff (D3) ------------------------------------------------


def test_render_diff_contains_ids_envs_and_approve() -> None:
    diff = render_custody_diff(parse_spec(_spec_text()))
    for cid in ("claim/songbird/ftso-reward-claim", "claim/songbird/uptime-vote-sign", "claim/songbird/uptime-vote-submit"):
        assert cid in diff
    assert "FWD_CALLER_TOKEN" in diff  # env NAME only
    assert "approve / reject" in diff
    assert "RewardManager" in diff


def test_render_diff_carries_no_token_value() -> None:
    """The spec carries only env NAMES; the diff must never contain a token value."""
    diff = render_custody_diff(parse_spec(_spec_text()))
    assert "fwd_live_" not in diff
    # the value-not-shown caveat is present
    assert "never shown" in diff


# --- provisioning_plan -------------------------------------------------------


def test_plan_derives_clif_convention() -> None:
    plan = provisioning_plan(parse_spec(_spec_text()))
    by_id = {g.capability_id: g for g in plan}
    assert by_id["claim/songbird/ftso-reward-claim"].caller_name == "claim-songbird"
    assert by_id["claim/songbird/ftso-reward-claim"].policy_path == "perm/claim-songbird"
    assert by_id["claim/songbird/uptime-vote-sign"].caller_name == "uptime-vote-sign-songbird"
    assert by_id["claim/songbird/uptime-vote-sign"].policy_path == "fsp/uptime-songbird"
    assert by_id["claim/songbird/uptime-vote-submit"].caller_name == "uptime-vote-submit-songbird"
    assert by_id["claim/songbird/uptime-vote-submit"].policy_path == "perm/uptime-submit-songbird"


def test_plan_unknown_role_left_underived() -> None:
    spec = json.loads(_spec_text())
    spec["capabilities"] = [
        {
            **spec["capabilities"][0],
            "capability_id": "claim/songbird/exotic",
            "role": "exotic",
        }
    ]
    plan = provisioning_plan(parse_spec(json.dumps(spec)))
    assert plan[0].caller_name is None
    assert plan[0].policy_path is None
