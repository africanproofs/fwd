"""Superset invariant for the a76 additive policy merge.

THE INVARIANT (CLAUDE.md doctrine, policy_init._merge_policies):
adding a network N to an existing policy P must yield a SUPERSET of P — no
caller / wallet / permission / constraint / fsp_permission that P had may be
dropped by adding N, and P's fsp_self_submit list must remain a subset of the
merged one. An add can NEVER drop a key.

This file is a small parametrized fuzz over (existing-networks, added-network,
capabilities) combinations. It asserts, for every dict section:

    set(merged[section].keys()) >= set(existing[section].keys())

and existing fsp_self_submit ⊆ merged fsp_self_submit. The crucial adversarial
case — adding a network that is ALREADY present — is included: re-adding must
still drop nothing (it may overwrite its own keys with identical values, but the
key set stays a superset).

Style mirrors tests/unit/test_policy_init.py.
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

# Every dict-typed policy section the merge unions per-key.
_DICT_SECTIONS = ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions")


def _gen(networks: str, capabilities: str, merge_into: str | None = None) -> str:
    return generate_policy(
        networks=networks.split(","),
        capabilities=capabilities.split(","),
        recipient=RECIPIENT,
        abis_dir=ABIS_DIR,
        networks_file=NETWORKS_FILE,
        merge_into=merge_into,
    )


def _roundtrip(tmp_path: Path, text: str) -> list[str]:
    """Write, load_policy (schema), check_consistency vs empty DB. Return errors."""
    p = tmp_path / "policy.yaml"
    p.write_text(text)
    policy = load_policy(p)
    registry = AbiRegistry.load(ABIS_DIR)
    return check_consistency(policy, [], [], registry)


def _assert_superset(existing: dict, merged: dict) -> None:
    """Core invariant assertion: merged is a key-superset of existing in every section."""
    for section in _DICT_SECTIONS:
        ex_keys = set(existing.get(section, {}) or {})
        mg_keys = set(merged.get(section, {}) or {})
        dropped = ex_keys - mg_keys
        assert not dropped, f"merge DROPPED keys from {section}: {sorted(dropped)}"

    ex_ss = list(existing.get("fsp_self_submit", []) or [])
    mg_ss = list(merged.get("fsp_self_submit", []) or [])
    missing = [w for w in ex_ss if w not in mg_ss]
    assert not missing, f"merge DROPPED fsp_self_submit entries: {missing}"


# ---------------------------------------------------------------------------
# Parametrized fuzz: (existing-networks, added-network, capabilities)
# ---------------------------------------------------------------------------

# Spread of starting policies × the network added on top × capability sets.
# The last few rows deliberately re-add an ALREADY-PRESENT network.
_FUZZ_CASES = [
    # (existing_nets, existing_caps, added_net, added_caps)
    ("songbird", "claim,fsp", "flare", "claim,fsp"),
    ("flare", "claim,fsp", "songbird", "claim,fsp"),
    ("flare", "claim", "songbird", "fsp"),
    ("songbird", "fsp", "coston2", "claim"),
    ("flare,songbird", "claim,fsp", "coston2", "claim,fsp"),
    ("coston2", "claim", "flare", "claim,fsp"),
    ("flare", "fsp", "songbird", "claim,fsp"),
    ("songbird", "claim", "coston2", "fsp"),
    ("flare,songbird,coston2", "claim,fsp", "flare", "claim,fsp"),  # add already-present
    ("flare", "claim,fsp", "flare", "claim,fsp"),  # re-add same single net
    ("songbird", "claim,fsp", "songbird", "claim"),  # re-add narrower caps
    ("flare,songbird", "fsp", "songbird", "fsp"),  # re-add one of two
]


@pytest.mark.parametrize(("ex_nets", "ex_caps", "add_net", "add_caps"), _FUZZ_CASES)
def test_merge_never_drops_a_key(
    tmp_path: Path, ex_nets: str, ex_caps: str, add_net: str, add_caps: str
) -> None:
    """For each combination, merging the add into the existing policy is a key-superset.

    Covers the adversarial 'add a network already present' rows: the merge may
    overwrite its own keys with identical values, but it can never drop a key.
    """
    existing_text = _gen(ex_nets, ex_caps)
    existing = yaml.safe_load(existing_text)

    merged_text = _gen(add_net, add_caps, merge_into=existing_text)
    merged = yaml.safe_load(merged_text)

    _assert_superset(existing, merged)

    # The merged policy must still pass the daemon's own startup checks (it is a
    # real, deployable policy, not just a dict that happens to be a superset).
    assert _roundtrip(tmp_path, merged_text) == []


@pytest.mark.parametrize(("ex_nets", "ex_caps", "add_net", "add_caps"), _FUZZ_CASES)
def test_existing_values_unchanged_for_non_overlapping_keys(
    ex_nets: str, ex_caps: str, add_net: str, add_caps: str
) -> None:
    """Keys NOT re-emitted by the add keep their exact prior value (no mutation).

    A key in `existing` is only legitimately overwritten if the add re-emits it
    (same network + same capability). Every OTHER existing key must be value-
    identical after the merge — the invariant forbids alteration, not just
    deletion. We compute the keys the add itself emits and exempt only those.
    """
    existing_text = _gen(ex_nets, ex_caps)
    existing = yaml.safe_load(existing_text)

    # What the add emits on its own (fresh) — exactly the keys it may overwrite.
    add_only = yaml.safe_load(_gen(add_net, add_caps))

    merged = yaml.safe_load(_gen(add_net, add_caps, merge_into=existing_text))

    for section in _DICT_SECTIONS:
        ex_sec = existing.get(section, {}) or {}
        add_sec = add_only.get(section, {}) or {}
        mg_sec = merged.get(section, {}) or {}
        for key, val in ex_sec.items():
            if key in add_sec:
                # legitimately re-emitted by the add; value may be overwritten
                continue
            assert mg_sec[key] == val, f"untouched {section}/{key} was mutated by the merge"


# ---------------------------------------------------------------------------
# Targeted edge: a hand-authored existing policy with operator-renamed keys.
# The invariant must hold even when the base was NOT generated by us (the merge
# code is a pure dict union, so a renamed caller/wallet must survive untouched).
# ---------------------------------------------------------------------------

_HAND_AUTHORED = """\
version: 7
callers:
  my-renamed-claimer:
    policy_path: perm/whatever
wallets:
  treasury-cold:
    policy_path: wc/treasury
permissions:
  perm/whatever:
    contracts: {}
    wallet_allowlist: [treasury-cold]
    rate: {per_hour: 1, per_day: 2}
wallet_constraints:
  wc/treasury:
    max_aggregate_value_wei_per_day: "0"
    rate: {per_hour: 1, per_day: 2}
fsp_permissions:
  fsp/legacy:
    message_types: [UPTIME]
    wallet_allowlist: [treasury-cold]
    rate: {per_hour: 1, per_day: 2}
fsp_self_submit:
  - treasury-cold
"""


@pytest.mark.parametrize("add_net", ["flare", "songbird", "coston2"])
@pytest.mark.parametrize("add_caps", ["claim", "fsp", "claim,fsp"])
def test_hand_authored_base_is_fully_preserved(add_net: str, add_caps: str) -> None:
    """Operator-renamed keys in a non-generated base survive the merge unchanged.

    None of the hand-authored keys collide with the network-suffixed keys the add
    emits, so every one must be present AND byte-identical after the merge, and
    the hand-authored fsp_self_submit entry must remain.
    """
    existing = yaml.safe_load(_HAND_AUTHORED)
    merged = yaml.safe_load(_gen(add_net, add_caps, merge_into=_HAND_AUTHORED))

    _assert_superset(existing, merged)

    # stronger: byte-identical values for every hand-authored key (none collide)
    for section in _DICT_SECTIONS:
        for key, val in (existing.get(section, {}) or {}).items():
            assert merged[section][key] == val, f"hand-authored {section}/{key} mutated"

    assert "treasury-cold" in merged["fsp_self_submit"]


def test_hand_authored_version_is_carried_from_add_not_base() -> None:
    """The merge sets version from the additions (always 1), not the base.

    Documents the actual behaviour of _merge_policies: it overwrites version with
    additions['version']. This is NOT a superset concern (version is a scalar, not
    a key set), but it confirms the merge does not silently inherit a base version
    that would surprise the operator. (The generator always emits version 1.)
    """
    merged = yaml.safe_load(_gen("flare", "claim", merge_into=_HAND_AUTHORED))
    # additions (the freshly generated policy) carries version 1.
    assert merged["version"] == 1


# ---------------------------------------------------------------------------
# Chained merges: onboard one network at a time and never lose an earlier one.
# ---------------------------------------------------------------------------


def test_chained_merges_accumulate_all_networks(tmp_path: Path) -> None:
    """Onboard flare, then songbird, then coston2 one-by-one: all three survive.

    Each step's existing policy must remain a subset of the next step's result.
    """
    nets = ["flare", "songbird", "coston2"]
    policy_text = _gen(nets[0], "claim,fsp")
    accumulated = yaml.safe_load(policy_text)

    for net in nets[1:]:
        prev = yaml.safe_load(policy_text)
        policy_text = _gen(net, "claim,fsp", merge_into=policy_text)
        cur = yaml.safe_load(policy_text)
        _assert_superset(prev, cur)
        accumulated = cur

    # all three networks present in every section that takes per-net keys
    for net in nets:
        assert f"claimer-{net}" in accumulated["wallets"]
        assert f"fsp-signing-{net}" in accumulated["wallets"]
        assert f"fsp-sender-{net}" in accumulated["wallets"]
        assert f"claim-{net}" in accumulated["callers"]
        assert f"fsp-sign-{net}" in accumulated["callers"]
        assert f"perm/claim-{net}" in accumulated["permissions"]
        assert f"fsp/{net}" in accumulated["fsp_permissions"]
        assert f"fsp-signing-{net}" in accumulated["fsp_self_submit"]

    assert _roundtrip(tmp_path, policy_text) == []


def test_chained_merges_in_either_order_converge(tmp_path: Path) -> None:
    """Merge order does not lose data: A+B and B+A both contain A and B fully.

    Not a commutativity claim about exact equality (key ordering may differ); the
    invariant is that neither ordering drops the other network's keys.
    """
    a = _gen("flare", "claim,fsp")
    b = _gen("songbird", "claim,fsp")

    ab = yaml.safe_load(_gen("songbird", "claim,fsp", merge_into=a))
    ba = yaml.safe_load(_gen("flare", "claim,fsp", merge_into=b))

    a_doc = yaml.safe_load(a)
    b_doc = yaml.safe_load(b)

    # A+B is a superset of both A and B
    _assert_superset(a_doc, ab)
    _assert_superset(b_doc, ab)
    # B+A is a superset of both A and B
    _assert_superset(a_doc, ba)
    _assert_superset(b_doc, ba)

    # both orderings carry the same full key set per section
    for section in _DICT_SECTIONS:
        assert set(ab.get(section, {}) or {}) == set(ba.get(section, {}) or {}), (
            f"{section} key set differs between merge orders"
        )


# ---------------------------------------------------------------------------
# Adversarial bases that the merge must NOT crash on while preserving keys.
# ---------------------------------------------------------------------------


def test_merge_into_base_missing_a_section_still_supersets() -> None:
    """A base lacking some dict sections (e.g. claim-only base, add fsp) supersets.

    The base has no fsp_permissions / fsp_self_submit; adding fsp must create them
    without disturbing the base's claim keys. The empty-set superset check holds
    trivially for the missing sections and meaningfully for the present ones.
    """
    base = _gen("flare", "claim")  # no fsp_permissions, no fsp_self_submit
    base_doc = yaml.safe_load(base)
    assert "fsp_permissions" not in base_doc
    assert "fsp_self_submit" not in base_doc

    merged = yaml.safe_load(_gen("flare", "fsp", merge_into=base))
    _assert_superset(base_doc, merged)
    # the add introduced the fsp sections
    assert "fsp/flare" in merged["fsp_permissions"]
    assert "fsp-signing-flare" in merged["fsp_self_submit"]
    # and the claim caller from the base is still there
    assert "claim-flare" in merged["callers"]


def test_merge_into_base_with_extra_unknown_top_level_key_preserved() -> None:
    """An unknown top-level key in the base survives the merge (deepcopy of base).

    _merge_policies deepcopies the base and only touches version + the known dict
    sections + fsp_self_submit. Any other top-level key the operator placed must
    pass through untouched.
    """
    base = "version: 1\ncallers: {}\nwallets: {}\nmy_operator_note: keep-me\n"
    merged = yaml.safe_load(_gen("flare", "claim", merge_into=base))
    assert merged["my_operator_note"] == "keep-me"
    # and the add's keys landed
    assert "claim-flare" in merged["callers"]


def test_merge_into_invalid_yaml_raises() -> None:
    """A non-YAML merge target raises PolicyInitError (cannot silently drop data)."""
    with pytest.raises(PolicyInitError, match="not valid YAML"):
        _gen("flare", "claim", merge_into="key: [unbalanced\n")


def test_merge_into_non_mapping_raises() -> None:
    """A YAML list merge target raises PolicyInitError, not a partial/superset."""
    with pytest.raises(PolicyInitError, match="not a policy mapping"):
        _gen("flare", "claim", merge_into="- a\n- b\n")
