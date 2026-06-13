"""Tests for the `fsp-voter` capability in app/policy_init.generate_policy (1c-i).

fsp-voter emits the four sign-only fsp_permissions blocks for the message types
added in fwd a9ec8f2 + aede961 (SIGNING_POLICY, VOTER_REGISTRATION,
PROTOCOL_PAYLOAD, FAST_UPDATE). The binding assertions:
  - the generated blocks round-trip through the daemon's own load_policy +
    check_consistency (proves the loader's _valid_fsp_types now admits them);
  - least-privilege — one message_type per caller;
  - fsp-voter is sign-only — no wallet enters fsp_self_submit;
  - REGRESSION: clif's `claim,fsp` output is unaffected (no fsp-voter leakage).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from fwd.app.capability_grant import ConsumerSpec, provisioning_plan
from fwd.app.policy_init import generate_policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.policy_loader import check_consistency, load_policy

_ROOT = Path(__file__).resolve().parents[2]
ABIS_DIR = _ROOT / "config" / "abis"
NETWORKS_FILE = _ROOT / "config" / "networks.yaml"
RECIPIENT = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"

_SGB = 19  # songbird chain id

_VOTER_BLOCKS = {
    "fsp/signing-policy-songbird": "SIGNING_POLICY",
    "fsp/voter-registration-songbird": "VOTER_REGISTRATION",
    "fsp/protocol-message-songbird": "PROTOCOL_PAYLOAD",
    "fsp/fastupdate-sign-songbird": "FAST_UPDATE",
}


def _gen(capabilities: str, recipient: str | None = RECIPIENT) -> str:
    return generate_policy(
        networks=["songbird"],
        capabilities=capabilities.split(","),
        recipient=recipient,
        abis_dir=ABIS_DIR,
        networks_file=NETWORKS_FILE,
    )


def _roundtrip(tmp_path: Path, text: str) -> list[str]:
    p = tmp_path / "policy.yaml"
    p.write_text(text)
    policy = load_policy(p)
    registry = AbiRegistry.load(ABIS_DIR)
    return check_consistency(policy, [], [], registry)


def test_fsp_voter_emits_four_sign_blocks_and_roundtrips(tmp_path: Path) -> None:
    text = _gen("fsp-voter", recipient=None)  # fsp-voter does not need a recipient
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)

    # exactly the four voter sign blocks, each least-privilege (one message_type)
    fperms = doc["fsp_permissions"]
    assert set(fperms) == set(_VOTER_BLOCKS)
    for path, mt in _VOTER_BLOCKS.items():
        assert fperms[path]["message_types"] == [mt]
        assert fperms[path]["chain_ids"] == [_SGB]

    # signing-policy / voter-registration / protocol-message share the SIGNING_PK wallet;
    # fast-update is on its own sign-only wallet.
    for path in (
        "fsp/signing-policy-songbird",
        "fsp/voter-registration-songbird",
        "fsp/protocol-message-songbird",
    ):
        assert fperms[path]["wallet_allowlist"] == ["fsp-signing-songbird"]
    assert fperms["fsp/fastupdate-sign-songbird"]["wallet_allowlist"] == ["fastupdate-songbird"]

    # wallets + constraints exist
    assert "fastupdate-songbird" in doc["wallets"]
    assert "wc/fastupdate-songbird" in doc["wallet_constraints"]
    assert "fsp-signing-songbird" in doc["wallets"]

    # callers map 1:1 to the policy paths
    assert doc["callers"]["signing-policy-sign-songbird"]["policy_path"] == "fsp/signing-policy-songbird"
    assert doc["callers"]["voter-registration-sign-songbird"]["policy_path"] == "fsp/voter-registration-songbird"
    assert doc["callers"]["protocol-message-sign-songbird"]["policy_path"] == "fsp/protocol-message-songbird"
    assert doc["callers"]["fastupdate-sign-songbird"]["policy_path"] == "fsp/fastupdate-sign-songbird"

    # SIGN-ONLY: no fsp_self_submit carve-out, no EVM permissions
    assert "fsp_self_submit" not in doc or doc["fsp_self_submit"] == []
    assert doc["permissions"] == {}


def test_fsp_and_fsp_voter_compose(tmp_path: Path) -> None:
    text = _gen("fsp,fsp-voter")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    # uptime/reward (from fsp) AND the four voter blocks (from fsp-voter)
    assert {
        "fsp/uptime-songbird",
        "fsp/reward-songbird",
        "fsp/signing-policy-songbird",
        "fsp/voter-registration-songbird",
        "fsp/protocol-message-songbird",
        "fsp/fastupdate-sign-songbird",
    } <= set(doc["fsp_permissions"])
    # the shared signing wallet is defined once, identically
    assert doc["wallets"]["fsp-signing-songbird"] == {"policy_path": "wc/fsp-songbird"}


def test_claim_fsp_unaffected_by_fsp_voter(tmp_path: Path) -> None:
    """REGRESSION GUARD: clif's `claim,fsp` policy must carry NO fsp-voter keys."""
    text = _gen("claim,fsp")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    for leaked in _VOTER_BLOCKS:
        assert leaked not in doc.get("fsp_permissions", {}), f"fsp-voter block {leaked} leaked into claim,fsp"
    assert "fastupdate-songbird" not in doc["wallets"]
    for caller in (
        "signing-policy-sign-songbird",
        "voter-registration-sign-songbird",
        "protocol-message-sign-songbird",
        "fastupdate-sign-songbird",
    ):
        assert caller not in doc["callers"]


def test_capability_grant_derives_voter_roles() -> None:
    """The four new roles resolve through _ROLE_CONVENTION in the grant path."""
    roles = [
        "signing-policy-sign",
        "voter-registration-sign",
        "protocol-message-sign",
        "fastupdate-sign",
    ]
    spec = ConsumerSpec.model_validate(
        {
            "consumer": "fsp",
            "network": "songbird",
            "compat": {"fwd_contract_expected": "v1", "fwd_client": "0.1.0"},
            "capabilities": [
                {
                    "capability_id": f"fsp/songbird/{r}",
                    "role": r,
                    "endpoint": "/v1/sign-fsp-message",
                    "caller_token_env": f"{r.upper().replace('-', '_')}_TOKEN",
                    "wallet_env": "FSP_SIGNING_WALLET_NAME",
                    "wallet_name": "fsp-signing-songbird",
                    "contract": None,
                    "contract_name": None,
                    "method": None,
                    "value_wei": None,
                    "recipient_pinned": None,
                    "suggested_rate": None,
                }
                for r in roles
            ],
        }
    )
    by_id = {g.capability_id: g for g in provisioning_plan(spec)}
    assert by_id["fsp/songbird/signing-policy-sign"].policy_path == "fsp/signing-policy-songbird"
    assert by_id["fsp/songbird/voter-registration-sign"].caller_name == "voter-registration-sign-songbird"
    assert by_id["fsp/songbird/protocol-message-sign"].policy_path == "fsp/protocol-message-songbird"
    assert by_id["fsp/songbird/fastupdate-sign"].caller_name == "fastupdate-sign-songbird"
