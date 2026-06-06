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
    # claim(_proofs tuple[]) is non-scalar — allow_unconstrained_args must be True
    # to allow the claim to proceed; _recipient predicate pins the beneficiary.
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
    # default is now per-network: fsp-sender-songbird (not shared fsp-sender)
    assert submit["wallet_allowlist"] == ["fsp-signing-songbird", "fsp-sender-songbird"]
    assert submit["contracts"]["0x421c69E22f48e14Fc2d2Ee3812c59bfb81c38516"]["chains"] == [19]
    for m in submit["contracts"]["0x421c69E22f48e14Fc2d2Ee3812c59bfb81c38516"]["methods"].values():
        # signUptimeVote(tuple) and signRewards(tuple[], tuple) are non-scalar —
        # allow_unconstrained_args must be True; chain binding via fsp_permissions.chain_ids.
        assert m["allow_unconstrained_args"] is True
    # FSP-CROSSCHAIN-001: UPTIME requires chain_ids — generated policy must include them.
    fsp_perm = doc["fsp_permissions"]["fsp/songbird"]
    assert fsp_perm["chain_ids"] == [19]


def test_claim_and_fsp_multinetwork_roundtrips(tmp_path: Path) -> None:
    text = _gen("flare,songbird", "claim,fsp")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    # default is now per-network: fsp-sender-flare and fsp-sender-songbird (no shared fsp-sender)
    assert "fsp-sender-flare" in doc["wallets"]
    assert "fsp-sender-songbird" in doc["wallets"]
    assert "fsp-sender" not in doc["wallets"]
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


# ---------------------------------------------------------------------------
# fsp_sender_mode tests (capability 4)
# ---------------------------------------------------------------------------


def _gen_mode(networks: str, capabilities: str, fsp_sender_mode: str) -> str:
    return generate_policy(
        networks=networks.split(","),
        capabilities=capabilities.split(","),
        recipient=RECIPIENT,
        abis_dir=ABIS_DIR,
        networks_file=NETWORKS_FILE,
        fsp_sender_mode=fsp_sender_mode,
    )


def test_fsp_sender_mode_per_network_yields_per_net_wallet(tmp_path: Path) -> None:
    """fsp_sender_mode='per-network' → wallet key fsp-sender-<net>, constraint wc/fsp-sender-<net>."""
    text = _gen_mode("songbird", "fsp", "per-network")
    doc = yaml.safe_load(text)

    assert "fsp-sender-songbird" in doc["wallets"]
    assert "fsp-sender" not in doc["wallets"]
    assert doc["wallets"]["fsp-sender-songbird"]["policy_path"] == "wc/fsp-sender-songbird"
    assert "wc/fsp-sender-songbird" in doc["wallet_constraints"]

    # Submit permission wallet_allowlist includes fsp-sender-songbird.
    submit = doc["permissions"]["perm/fsp-submit-songbird"]
    assert "fsp-sender-songbird" in submit["wallet_allowlist"]

    # fsp-signing-songbird still present in fsp_self_submit.
    assert "fsp-signing-songbird" in doc["fsp_self_submit"]


def test_fsp_sender_mode_per_network_multinetwork(tmp_path: Path) -> None:
    """Per-network mode with flare+songbird → fsp-sender-flare and fsp-sender-songbird (no shared)."""
    text = _gen_mode("flare,songbird", "fsp", "per-network")
    doc = yaml.safe_load(text)

    assert "fsp-sender-flare" in doc["wallets"]
    assert "fsp-sender-songbird" in doc["wallets"]
    assert "fsp-sender" not in doc["wallets"]

    flare_submit = doc["permissions"]["perm/fsp-submit-flare"]
    assert "fsp-sender-flare" in flare_submit["wallet_allowlist"]

    sgb_submit = doc["permissions"]["perm/fsp-submit-songbird"]
    assert "fsp-sender-songbird" in sgb_submit["wallet_allowlist"]


def test_fsp_sender_mode_default_is_per_network(tmp_path: Path) -> None:
    """Default (no fsp_sender_mode) now yields fsp-sender-<net> and wc/fsp-sender-<net>."""
    text_default = _gen("songbird", "fsp")
    doc_default = yaml.safe_load(text_default)

    assert "fsp-sender-songbird" in doc_default["wallets"]
    assert "fsp-sender" not in doc_default["wallets"]
    assert doc_default["wallets"]["fsp-sender-songbird"]["policy_path"] == "wc/fsp-sender-songbird"
    assert _roundtrip(tmp_path, text_default) == []


def test_fsp_sender_mode_shared_explicit_still_works(tmp_path: Path) -> None:
    """Explicit fsp_sender_mode='shared' still yields fsp-sender and wc/fsp-sender."""
    text_explicit = _gen_mode("songbird", "fsp", "shared")
    doc_explicit = yaml.safe_load(text_explicit)

    assert "fsp-sender" in doc_explicit["wallets"]
    assert "fsp-sender-songbird" not in doc_explicit["wallets"]
    assert doc_explicit["wallets"]["fsp-sender"]["policy_path"] == "wc/fsp-sender"
    assert _roundtrip(tmp_path, text_explicit) == []


# ---------------------------------------------------------------------------
# additive merge — adding a network must NEVER remove an existing one
# ---------------------------------------------------------------------------

INERT = "# fwd INERT default-deny policy (installed). Empty on purpose.\nversion: 1\n"


def _gen_merge(
    networks: str, capabilities: str, merge_into: str, recipient: str | None = RECIPIENT
) -> str:
    return generate_policy(
        networks=networks.split(","),
        capabilities=capabilities.split(","),
        recipient=recipient,
        abis_dir=ABIS_DIR,
        networks_file=NETWORKS_FILE,
        merge_into=merge_into,
    )


def test_merge_into_inert_equals_fresh() -> None:
    """First onboard: merging a network into the inert default == a fresh generate."""
    fresh = yaml.safe_load(_gen("songbird", "claim,fsp"))
    merged = yaml.safe_load(_gen_merge("songbird", "claim,fsp", INERT))
    assert merged == fresh


def test_merge_adds_network_preserves_existing(tmp_path: Path) -> None:
    """Onboard songbird, then ADD flare via merge: both present, songbird byte-identical."""
    songbird = _gen("songbird", "claim,fsp")
    sb_doc = yaml.safe_load(songbird)
    merged = _gen_merge("flare", "claim,fsp", songbird)
    doc = yaml.safe_load(merged)

    # both networks present across every section
    assert {
        "claimer-songbird", "claimer-flare", "fsp-signing-songbird",
        "fsp-signing-flare", "fsp-sender-songbird", "fsp-sender-flare",
    } <= set(doc["wallets"])
    assert {
        "claim-songbird", "claim-flare", "fsp-sign-songbird", "fsp-sign-flare",
        "fsp-submit-songbird", "fsp-submit-flare",
    } <= set(doc["callers"])
    assert {"fsp/songbird", "fsp/flare"} <= set(doc["fsp_permissions"])
    assert sorted(doc["fsp_self_submit"]) == ["fsp-signing-flare", "fsp-signing-songbird"]

    # every songbird rule is byte-for-byte preserved (the flare run touched none)
    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        for key, val in sb_doc[section].items():
            assert doc[section][key] == val, f"songbird {section}/{key} changed"

    # and the merged policy still passes the daemon's own startup checks
    assert _roundtrip(tmp_path, merged) == []


def test_merge_same_network_is_idempotent() -> None:
    """Re-running the same network merges its own identical keys back — no growth/dups."""
    songbird = _gen("songbird", "claim,fsp")
    twice = _gen_merge("songbird", "claim,fsp", songbird)
    assert yaml.safe_load(twice) == yaml.safe_load(songbird)


def test_merge_rejects_non_mapping() -> None:
    with pytest.raises(PolicyInitError, match="not a policy mapping"):
        _gen_merge("flare", "claim", merge_into="- just\n- a\n- list\n")


def test_fsp_sender_mode_unknown_raises() -> None:
    """An unknown fsp_sender_mode raises PolicyInitError."""
    with pytest.raises(PolicyInitError, match="unknown fsp_sender_mode"):
        _gen_mode("flare", "fsp", "per-chain")
