"""Multi-network composition tests for the additive policy merge (a76).

DIMENSION: multinet. Adversarially exercise composing 2nd then 3rd networks
(songbird → +flare → +coston2) under claim-only / fsp-only / claim+fsp mixes,
and under per-network vs shared fsp-sender, asserting the SUPERSET invariant:

    for any existing policy P and any added network N, the merged policy is a
    SUPERSET of P — no caller/wallet/permission/constraint/fsp_permission that P
    had may be dropped or altered by adding N.

Style mirrors tests/unit/test_policy_init.py: generate_policy(...) +
load_policy + check_consistency round-trip, yaml.safe_load to inspect sections.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from fwd.app.policy_init import generate_policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.policy_loader import check_consistency, load_policy

_ROOT = Path(__file__).resolve().parents[2]
ABIS_DIR = _ROOT / "config" / "abis"
NETWORKS_FILE = _ROOT / "config" / "networks.yaml"
RECIPIENT = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"

# The five per-key-unioned dict sections (policy_init._MERGE_DICT_SECTIONS).
_DICT_SECTIONS = ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions")


def _gen(
    networks: str,
    capabilities: str,
    *,
    merge_into: str | None = None,
    fsp_sender_mode: str = "per-network",
    recipient: str | None = RECIPIENT,
) -> str:
    return generate_policy(
        networks=networks.split(","),
        capabilities=capabilities.split(","),
        recipient=recipient,
        abis_dir=ABIS_DIR,
        networks_file=NETWORKS_FILE,
        fsp_sender_mode=fsp_sender_mode,
        merge_into=merge_into,
    )


def _roundtrip(tmp_path: Path, text: str) -> list[str]:
    """Write, schema-load, consistency-check vs empty DB. Return error list."""
    p = tmp_path / "policy.yaml"
    p.write_text(text)
    policy = load_policy(p)
    registry = AbiRegistry.load(ABIS_DIR)
    return check_consistency(policy, [], [], registry)


def _assert_superset(prior_doc: dict, merged_doc: dict) -> None:
    """Every key/value in every dict section of prior_doc survives byte-identical
    in merged_doc, and every fsp_self_submit entry survives."""
    for section in _DICT_SECTIONS:
        for key, val in prior_doc.get(section, {}).items():
            assert key in merged_doc.get(section, {}), f"{section}/{key} DROPPED by merge"
            assert merged_doc[section][key] == val, f"{section}/{key} ALTERED by merge"
    for w in prior_doc.get("fsp_self_submit", []):
        assert w in merged_doc.get("fsp_self_submit", []), f"fsp_self_submit {w} DROPPED"


# ---------------------------------------------------------------------------
# Three-network composition: songbird → +flare → +coston2
# ---------------------------------------------------------------------------


def test_three_networks_claim_fsp_all_present(tmp_path: Path) -> None:
    """Compose songbird, then add flare, then add coston2 (claim,fsp each).
    Every network appears in every section after each add; the final policy
    round-trips through the daemon's own startup checks."""
    sb = _gen("songbird", "claim,fsp")
    sb_doc = yaml.safe_load(sb)

    plus_flare = _gen("flare", "claim,fsp", merge_into=sb)
    fl_doc = yaml.safe_load(plus_flare)
    _assert_superset(sb_doc, fl_doc)

    plus_c2 = _gen("coston2", "claim,fsp", merge_into=plus_flare)
    final = yaml.safe_load(plus_c2)
    _assert_superset(fl_doc, final)

    # all three networks present across every per-key section
    for net in ("songbird", "flare", "coston2"):
        assert f"claimer-{net}" in final["wallets"]
        assert f"fsp-signing-{net}" in final["wallets"]
        assert f"fsp-sender-{net}" in final["wallets"]
        assert f"claim-{net}" in final["callers"]
        assert f"uptime-vote-sign-{net}" in final["callers"]
        assert f"uptime-vote-submit-{net}" in final["callers"]
        assert f"perm/claim-{net}" in final["permissions"]
        assert f"perm/uptime-submit-{net}" in final["permissions"]
        assert f"wc/claimer-{net}" in final["wallet_constraints"]
        assert f"wc/fsp-{net}" in final["wallet_constraints"]
        assert f"wc/fsp-sender-{net}" in final["wallet_constraints"]
        assert f"fsp/uptime-{net}" in final["fsp_permissions"]
        assert f"fsp-signing-{net}" in final["fsp_self_submit"]

    assert sorted(final["fsp_self_submit"]) == [
        "fsp-signing-coston2",
        "fsp-signing-flare",
        "fsp-signing-songbird",
    ]
    assert _roundtrip(tmp_path, plus_c2) == []


def test_three_networks_order_independent(tmp_path: Path) -> None:
    """Composing the same three networks in a different add order yields the same
    set of keys per section (union is order-independent on the key set)."""
    a = _gen(
        "coston2",
        "claim,fsp",
        merge_into=_gen("flare", "claim,fsp", merge_into=_gen("songbird", "claim,fsp")),
    )
    b = _gen(
        "songbird",
        "claim,fsp",
        merge_into=_gen("coston2", "claim,fsp", merge_into=_gen("flare", "claim,fsp")),
    )
    da, db = yaml.safe_load(a), yaml.safe_load(b)
    for section in _DICT_SECTIONS:
        assert set(da.get(section, {})) == set(db.get(section, {})), f"{section} key set differs"
    assert set(da["fsp_self_submit"]) == set(db["fsp_self_submit"])
    # Per-key VALUES are also identical regardless of order (no cross-net coupling).
    for section in _DICT_SECTIONS:
        for key, val in da.get(section, {}).items():
            assert db[section][key] == val, f"{section}/{key} value depends on add order"


# ---------------------------------------------------------------------------
# Mixed capabilities across adds — claim-only / fsp-only / claim+fsp
# ---------------------------------------------------------------------------


def test_add_fsp_only_preserves_claim_only_network(tmp_path: Path) -> None:
    """songbird claim-only, then add flare fsp-only: songbird's claim rules
    survive untouched and flare's fsp rules appear. No claim keys for flare,
    no fsp keys for songbird."""
    sb = _gen("songbird", "claim")
    sb_doc = yaml.safe_load(sb)
    merged = _gen("flare", "fsp", merge_into=sb)
    doc = yaml.safe_load(merged)

    _assert_superset(sb_doc, doc)
    # songbird claim survives
    assert "claimer-songbird" in doc["wallets"]
    assert "perm/claim-songbird" in doc["permissions"]
    # flare fsp appears
    assert "fsp-signing-flare" in doc["wallets"]
    assert "perm/uptime-submit-flare" in doc["permissions"]
    assert "fsp/uptime-flare" in doc["fsp_permissions"]
    # songbird claim-only network gained NO fsp keys
    assert "fsp-signing-songbird" not in doc["wallets"]
    assert "fsp/uptime-songbird" not in doc.get("fsp_permissions", {})
    # flare fsp-only network gained NO claim keys
    assert "claimer-flare" not in doc["wallets"]
    assert "perm/claim-flare" not in doc["permissions"]
    assert _roundtrip(tmp_path, merged) == []


def test_add_claim_fsp_to_claim_only_network_same_net_unions(tmp_path: Path) -> None:
    """songbird claim-only, then re-onboard songbird with claim+fsp via merge:
    the existing claim keys survive AND fsp keys are added to the SAME network."""
    sb = _gen("songbird", "claim")
    sb_doc = yaml.safe_load(sb)
    merged = _gen("songbird", "claim,fsp", merge_into=sb)
    doc = yaml.safe_load(merged)

    # claim keys preserved byte-identical (claim sub-policy regenerates identically)
    _assert_superset(sb_doc, doc)
    # fsp keys now present for songbird
    assert "fsp-signing-songbird" in doc["wallets"]
    assert "fsp/uptime-songbird" in doc["fsp_permissions"]
    assert "perm/uptime-submit-songbird" in doc["permissions"]
    assert "fsp-signing-songbird" in doc["fsp_self_submit"]
    assert _roundtrip(tmp_path, merged) == []


def test_heterogeneous_three_net_mix(tmp_path: Path) -> None:
    """songbird claim+fsp, +flare claim-only, +coston2 fsp-only. Each network's
    own capability set is exactly what was requested; nothing leaks across nets;
    every prior network survives each add."""
    sb = _gen("songbird", "claim,fsp")
    sb_doc = yaml.safe_load(sb)

    plus_fl = _gen("flare", "claim", merge_into=sb)
    fl_doc = yaml.safe_load(plus_fl)
    _assert_superset(sb_doc, fl_doc)

    plus_c2 = _gen("coston2", "fsp", merge_into=plus_fl)
    doc = yaml.safe_load(plus_c2)
    _assert_superset(fl_doc, doc)

    # songbird: both caps
    assert "claimer-songbird" in doc["wallets"]
    assert "fsp-signing-songbird" in doc["wallets"]
    # flare: claim only, no fsp
    assert "claimer-flare" in doc["wallets"]
    assert "fsp-signing-flare" not in doc["wallets"]
    assert "fsp/uptime-flare" not in doc.get("fsp_permissions", {})
    # coston2: fsp only, no claim
    assert "fsp-signing-coston2" in doc["wallets"]
    assert "claimer-coston2" not in doc["wallets"]
    assert "perm/claim-coston2" not in doc["permissions"]

    # fsp_self_submit holds exactly the two fsp networks' signing wallets
    assert sorted(doc["fsp_self_submit"]) == ["fsp-signing-coston2", "fsp-signing-songbird"]
    assert _roundtrip(tmp_path, plus_c2) == []


# ---------------------------------------------------------------------------
# per-network vs shared fsp-sender across networks
# ---------------------------------------------------------------------------


def test_shared_fsp_sender_merges_without_collision(tmp_path: Path) -> None:
    """In shared fsp-sender mode the `fsp-sender` wallet + `wc/fsp-sender`
    constraint are NOT network-suffixed and so are re-emitted identically when a
    second network is added. The merge re-unions the identical key — the prior
    network's value is preserved (identical), and both networks' submit perms
    allowlist the shared sender."""
    sb = _gen("songbird", "fsp", fsp_sender_mode="shared")
    sb_doc = yaml.safe_load(sb)
    merged = _gen("flare", "fsp", merge_into=sb, fsp_sender_mode="shared")
    doc = yaml.safe_load(merged)

    _assert_superset(sb_doc, doc)
    # single shared sender wallet/constraint, no per-net variants
    assert "fsp-sender" in doc["wallets"]
    assert "fsp-sender-songbird" not in doc["wallets"]
    assert "fsp-sender-flare" not in doc["wallets"]
    assert "wc/fsp-sender" in doc["wallet_constraints"]
    # both networks' submit perms allowlist the shared sender
    assert "fsp-sender" in doc["permissions"]["perm/uptime-submit-songbird"]["wallet_allowlist"]
    assert "fsp-sender" in doc["permissions"]["perm/uptime-submit-flare"]["wallet_allowlist"]
    assert _roundtrip(tmp_path, merged) == []


def test_shared_sender_value_identical_across_nets(tmp_path: Path) -> None:
    """The shared `fsp-sender` wallet + `wc/fsp-sender` constraint emitted for a
    second network are byte-identical to the first, so re-unioning them cannot
    silently alter the prior network's binding (the SUPERSET invariant holds
    even though the key is shared, not suffixed)."""
    fresh_sb = yaml.safe_load(_gen("songbird", "fsp", fsp_sender_mode="shared"))
    fresh_fl = yaml.safe_load(_gen("flare", "fsp", fsp_sender_mode="shared"))
    assert fresh_sb["wallets"]["fsp-sender"] == fresh_fl["wallets"]["fsp-sender"]
    assert (
        fresh_sb["wallet_constraints"]["wc/fsp-sender"]
        == fresh_fl["wallet_constraints"]["wc/fsp-sender"]
    )


def test_three_net_shared_sender_single_sender(tmp_path: Path) -> None:
    """songbird → +flare → +coston2, all shared fsp-sender: exactly one shared
    sender wallet survives, every prior network preserved at each add, and all
    three submit-perms allowlist it."""
    sb = _gen("songbird", "fsp", fsp_sender_mode="shared")
    sb_doc = yaml.safe_load(sb)
    fl = _gen("flare", "fsp", merge_into=sb, fsp_sender_mode="shared")
    fl_doc = yaml.safe_load(fl)
    _assert_superset(sb_doc, fl_doc)
    c2 = _gen("coston2", "fsp", merge_into=fl, fsp_sender_mode="shared")
    doc = yaml.safe_load(c2)
    _assert_superset(fl_doc, doc)

    senders = [w for w in doc["wallets"] if w.startswith("fsp-sender")]
    assert senders == ["fsp-sender"], f"expected only the shared sender, got {senders}"
    for net in ("songbird", "flare", "coston2"):
        assert "fsp-sender" in doc["permissions"][f"perm/uptime-submit-{net}"]["wallet_allowlist"]
    assert _roundtrip(tmp_path, c2) == []


def test_mixed_sender_mode_per_net_then_shared(tmp_path: Path) -> None:
    """Adversarial: onboard songbird per-network sender, then add flare with the
    shared sender mode. The per-network `fsp-sender-songbird` MUST survive (it is
    suffixed, the flare run never touches it) and flare's shared `fsp-sender`
    coexists. This is a deliberately inconsistent operator action; the merge must
    still be a pure superset and the result must still round-trip."""
    sb = _gen("songbird", "fsp", fsp_sender_mode="per-network")
    sb_doc = yaml.safe_load(sb)
    merged = _gen("flare", "fsp", merge_into=sb, fsp_sender_mode="shared")
    doc = yaml.safe_load(merged)

    _assert_superset(sb_doc, doc)
    # songbird's per-net sender survives
    assert "fsp-sender-songbird" in doc["wallets"]
    assert "wc/fsp-sender-songbird" in doc["wallet_constraints"]
    # flare's shared sender added alongside
    assert "fsp-sender" in doc["wallets"]
    assert "wc/fsp-sender" in doc["wallet_constraints"]
    # songbird submit-perm still allowlists its OWN per-net sender (unaltered)
    assert doc["permissions"]["perm/uptime-submit-songbird"]["wallet_allowlist"] == [
        "fsp-signing-songbird",
        "fsp-sender-songbird",
    ]
    # flare submit-perm allowlists the shared sender
    assert "fsp-sender" in doc["permissions"]["perm/uptime-submit-flare"]["wallet_allowlist"]
    assert _roundtrip(tmp_path, merged) == []


# ---------------------------------------------------------------------------
# version + section presence across composition
# ---------------------------------------------------------------------------


def test_version_carried_through_three_adds() -> None:
    """version stays a valid policy version through repeated additive merges."""
    sb = _gen("songbird", "claim,fsp")
    fl = _gen("flare", "claim,fsp", merge_into=sb)
    c2 = _gen("coston2", "claim,fsp", merge_into=fl)
    assert yaml.safe_load(c2)["version"] == 1


def test_no_fsp_sections_when_all_nets_claim_only(tmp_path: Path) -> None:
    """Composing claim-only networks never introduces fsp_permissions /
    fsp_self_submit out of nowhere."""
    sb = _gen("songbird", "claim")
    fl = _gen("flare", "claim", merge_into=sb)
    doc = yaml.safe_load(fl)
    assert "fsp_permissions" not in doc or doc["fsp_permissions"] == {}
    assert "fsp_self_submit" not in doc or doc["fsp_self_submit"] == []
    assert {"claimer-songbird", "claimer-flare"} <= set(doc["wallets"])
    assert _roundtrip(tmp_path, fl) == []


def test_fsp_self_submit_grows_only_by_added_net(tmp_path: Path) -> None:
    """Each fsp add appends exactly one signing wallet to fsp_self_submit; the
    prior entries keep their order (order-preserving list union)."""
    sb = _gen("songbird", "fsp")
    assert yaml.safe_load(sb)["fsp_self_submit"] == ["fsp-signing-songbird"]
    fl = _gen("flare", "fsp", merge_into=sb)
    assert yaml.safe_load(fl)["fsp_self_submit"] == ["fsp-signing-songbird", "fsp-signing-flare"]
    c2 = _gen("coston2", "fsp", merge_into=fl)
    assert yaml.safe_load(c2)["fsp_self_submit"] == [
        "fsp-signing-songbird",
        "fsp-signing-flare",
        "fsp-signing-coston2",
    ]
    assert _roundtrip(tmp_path, c2) == []
