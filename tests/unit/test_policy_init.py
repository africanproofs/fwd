"""Tests for app/policy_init.generate_policy.

The binding assertion: generated output round-trips through the daemon's OWN
startup checks — load_policy (schema) + check_consistency (against an empty DB +
the real ABI registry) → zero errors. That proves the generator emits the a29
schema (chains, allow_unconstrained_args, fsp_self_submit carve-out,
wallet_constraints) correctly, with method signatures that match the ABIs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from fwd.app.policy_init import PolicyInitError, generate_policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.policy_loader import check_consistency, load_policy

_ROOT = Path(__file__).resolve().parents[2]
ABIS_DIR = _ROOT / "config" / "abis"
NETWORKS_FILE = _ROOT / "config" / "networks.yaml"
RECIPIENT = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"


def _gen(networks: str, capabilities: str, recipient: str | None = RECIPIENT) -> str:
    return generate_policy(
        networks=networks.split(","),
        capabilities=capabilities.split(","),
        recipient=recipient,
        abis_dir=ABIS_DIR,
        networks_file=NETWORKS_FILE,
    )


def _roundtrip(tmp_path: Path, text: str) -> list[str]:
    """Write, load_policy (schema), check_consistency vs empty DB. Return errors."""
    p = tmp_path / "policy.yaml"
    p.write_text(text)
    policy = load_policy(p)  # raises PolicyLoadError on schema failure
    registry = AbiRegistry.load(ABIS_DIR)
    return check_consistency(policy, [], [], registry)


def test_claim_only_flare_roundtrips(tmp_path: Path) -> None:
    text = _gen("flare", "claim")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    cr = doc["permissions"]["perm/claim-flare"]["contracts"][
        "0xC8f55c5aA2C752eE285Bd872855C749f4ee6239B"
    ]
    assert cr["chains"] == [14]
    method = next(iter(cr["methods"].values()))
    assert method["allow_unconstrained_args"] is True
    assert method["arg_predicates"]["_recipient"] == RECIPIENT


def test_fsp_only_songbird_roundtrips_with_carveout(tmp_path: Path) -> None:
    text = _gen("songbird", "fsp")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    # carve-out: the signing wallet is opted into fsp_self_submit AND appears in
    # both an fsp_permissions and an EVM permissions allowlist.
    assert doc["fsp_self_submit"] == ["fsp-signing-songbird"]
    submit = doc["permissions"]["perm/fsp-submit-songbird"]
    assert submit["wallet_allowlist"] == ["fsp-signing-songbird", "fsp-sender"]
    assert submit["contracts"]["0x421c69E22f48e14Fc2d2Ee3812c59bfb81c38516"]["chains"] == [19]
    for m in submit["contracts"]["0x421c69E22f48e14Fc2d2Ee3812c59bfb81c38516"]["methods"].values():
        assert m["allow_unconstrained_args"] is True


def test_claim_and_fsp_multinetwork_roundtrips(tmp_path: Path) -> None:
    text = _gen("flare,songbird", "claim,fsp")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    # fsp-sender is shared across networks (one wallet, one constraint).
    assert doc["wallets"]["fsp-sender"]["policy_path"] == "wc/fsp-sender"
    assert sorted(doc["fsp_self_submit"]) == ["fsp-signing-flare", "fsp-signing-songbird"]


def test_claim_requires_recipient() -> None:
    with pytest.raises(PolicyInitError, match="recipient is required"):
        _gen("flare", "claim", recipient=None)


def test_unknown_network_rejected() -> None:
    with pytest.raises(PolicyInitError, match="unknown network"):
        _gen("ethereum", "claim")


def test_unknown_capability_rejected() -> None:
    with pytest.raises(PolicyInitError, match="unknown capabilities"):
        _gen("flare", "staking")
