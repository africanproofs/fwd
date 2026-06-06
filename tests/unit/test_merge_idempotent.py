"""Adversarial idempotency + order-independence tests for the a76 additive policy-merge.

Dimension: "idempotent". Focus:
  - Re-merging the SAME network into a policy that already has it yields
    content-equal YAML (no growth, no duplicate fsp_self_submit entries).
  - Merging A-then-B vs B-then-A produces content-equal policies.
  - Merging a network into a policy that is exactly its own fresh output is a no-op.

Style mirrors tests/unit/test_policy_init.py: generate_policy(...) + load_policy +
check_consistency for the roundtrip gate; yaml.safe_load to compare parsed dicts.

INVARIANT under protection: for any existing policy P and added network N, the
merged policy is a SUPERSET of P — adding N drops/alters nothing P had, and
re-adding what is already there changes nothing.

NOTE ON ORDER-INDEPENDENCE OF fsp_self_submit
---------------------------------------------
`_merge_policies` builds `fsp_self_submit` as an order-PRESERVING list union
(base entries first, then additions). So merging flare-into-songbird gives
['fsp-signing-songbird', 'fsp-signing-flare'] while songbird-into-flare gives
['fsp-signing-flare', 'fsp-signing-songbird'] — the LISTS differ in order, even
though the SET of self-submit wallets is identical. That is intended (the list
is order-preserving by contract; the carve-out semantics are set-membership, not
order). Tests that compare order-independence therefore compare the policies with
`fsp_self_submit` normalised to a set / sorted — comparing the raw lists would be
a BAD TEST asserting an order guarantee the code never promised. Every other
section is a dict (order-independent under ==), so those are compared directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from fwd.app.policy_init import generate_policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.policy_loader import check_consistency, load_policy

_ROOT = Path(__file__).resolve().parents[2]
ABIS_DIR = _ROOT / "config" / "abis"
NETWORKS_FILE = _ROOT / "config" / "networks.yaml"
RECIPIENT = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"

INERT = "# fwd INERT default-deny policy (installed). Empty on purpose.\nversion: 1\n"


def _gen(
    networks: str,
    capabilities: str,
    merge_into: str | None = None,
    recipient: str | None = RECIPIENT,
) -> str:
    return generate_policy(
        networks=networks.split(","),
        capabilities=capabilities.split(","),
        recipient=recipient,
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


def _norm(doc: dict[str, Any]) -> dict[str, Any]:
    """Order-normalise: fsp_self_submit -> sorted (set-equality, not list-order).

    Every other section is a dict, already order-independent under ==.
    """
    out = dict(doc)
    if "fsp_self_submit" in out:
        out["fsp_self_submit"] = sorted(out["fsp_self_submit"])
    return out


# ---------------------------------------------------------------------------
# 1. Re-merging the SAME network is a content no-op (no growth, no dups)
# ---------------------------------------------------------------------------


def test_remerge_same_network_claim_fsp_is_content_equal() -> None:
    """Merging songbird into a policy that already has songbird == the original."""
    base = _gen("songbird", "claim,fsp")
    again = _gen("songbird", "claim,fsp", merge_into=base)
    assert yaml.safe_load(again) == yaml.safe_load(base)


def test_remerge_same_network_claim_only_is_content_equal() -> None:
    base = _gen("flare", "claim")
    again = _gen("flare", "claim", merge_into=base)
    assert yaml.safe_load(again) == yaml.safe_load(base)


def test_remerge_same_network_fsp_only_is_content_equal() -> None:
    base = _gen("coston2", "fsp")
    again = _gen("coston2", "fsp", merge_into=base)
    assert yaml.safe_load(again) == yaml.safe_load(base)


def test_remerge_three_times_does_not_grow() -> None:
    """Idempotency must be stable under repeated application (no slow growth)."""
    base = _gen("songbird", "claim,fsp")
    once = _gen("songbird", "claim,fsp", merge_into=base)
    twice = _gen("songbird", "claim,fsp", merge_into=once)
    thrice = _gen("songbird", "claim,fsp", merge_into=twice)
    base_doc = yaml.safe_load(base)
    assert yaml.safe_load(once) == base_doc
    assert yaml.safe_load(twice) == base_doc
    assert yaml.safe_load(thrice) == base_doc


def test_remerge_no_section_grows_in_size() -> None:
    """Explicitly assert every section count is unchanged after a same-net re-merge."""
    base = yaml.safe_load(_gen("flare,songbird", "claim,fsp"))
    again = yaml.safe_load(
        _gen("flare,songbird", "claim,fsp", merge_into=_gen("flare,songbird", "claim,fsp"))
    )
    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        assert len(again[section]) == len(base[section]), f"{section} grew on re-merge"
    assert len(again["fsp_self_submit"]) == len(base["fsp_self_submit"])


def test_remerge_no_duplicate_fsp_self_submit_entries() -> None:
    """The order-preserving list union must not duplicate an already-present wallet."""
    base = _gen("flare,songbird", "claim,fsp")
    again = _gen("flare,songbird", "claim,fsp", merge_into=base)
    ss = yaml.safe_load(again)["fsp_self_submit"]
    assert len(ss) == len(set(ss)), f"duplicate self-submit entries: {ss}"
    assert sorted(ss) == ["fsp-signing-flare", "fsp-signing-songbird"]


# ---------------------------------------------------------------------------
# 2. Order-independence: A-then-B vs B-then-A are content-equal
# ---------------------------------------------------------------------------


def test_order_independence_two_networks_claim_fsp() -> None:
    """flare-then-songbird vs songbird-then-flare produce the same policy content.

    fsp_self_submit is an order-preserving list, so its raw ORDER differs between
    the two assembly orders; we compare with it normalised to a set (the carve-out
    is set-membership). Every other section is a dict (order-independent under ==).
    """
    flare_first = _gen("songbird", "claim,fsp", merge_into=_gen("flare", "claim,fsp"))
    songbird_first = _gen("flare", "claim,fsp", merge_into=_gen("songbird", "claim,fsp"))
    assert _norm(yaml.safe_load(flare_first)) == _norm(yaml.safe_load(songbird_first))


def test_order_independence_self_submit_set_is_equal() -> None:
    """The SET of fsp_self_submit wallets is order-independent (membership, not order)."""
    flare_first = _gen("songbird", "fsp", merge_into=_gen("flare", "fsp"))
    songbird_first = _gen("flare", "fsp", merge_into=_gen("songbird", "fsp"))
    a = set(yaml.safe_load(flare_first)["fsp_self_submit"])
    b = set(yaml.safe_load(songbird_first)["fsp_self_submit"])
    assert a == b == {"fsp-signing-flare", "fsp-signing-songbird"}


def test_order_independence_three_networks() -> None:
    """All assembly orders of {flare, songbird, coston2} give content-equal policies."""
    import itertools

    nets = ["flare", "songbird", "coston2"]
    docs = []
    for order in itertools.permutations(nets):
        acc: str | None = None
        for n in order:
            acc = _gen(n, "claim,fsp", merge_into=acc)
        docs.append(_norm(yaml.safe_load(acc)))
    first = docs[0]
    for d in docs[1:]:
        assert d == first


def test_order_independence_equals_single_multinetwork_generate() -> None:
    """Incremental A-then-B merge == one fresh generate(A,B) (modulo self-submit order).

    This is the strongest superset/no-op statement: building a two-network policy
    one network at a time yields the SAME content as generating both at once.
    """
    incremental = _gen("songbird", "claim,fsp", merge_into=_gen("flare", "claim,fsp"))
    single = _gen("flare,songbird", "claim,fsp")
    assert _norm(yaml.safe_load(incremental)) == _norm(yaml.safe_load(single))


# ---------------------------------------------------------------------------
# 3. Merging a network into its OWN fresh output is a no-op
# ---------------------------------------------------------------------------


def test_merge_network_into_own_fresh_output_is_noop() -> None:
    fresh = _gen("songbird", "claim,fsp")
    merged = _gen("songbird", "claim,fsp", merge_into=fresh)
    assert yaml.safe_load(merged) == yaml.safe_load(fresh)


def test_merge_multinetwork_into_own_fresh_output_is_noop() -> None:
    fresh = _gen("flare,songbird,coston2", "claim,fsp")
    merged = _gen("flare,songbird,coston2", "claim,fsp", merge_into=fresh)
    assert yaml.safe_load(merged) == yaml.safe_load(fresh)


def test_merge_into_inert_then_remerge_is_noop() -> None:
    """Inert -> add net (== fresh) -> re-add same net is a stable fixed point."""
    fresh = yaml.safe_load(_gen("songbird", "claim,fsp"))
    first = _gen("songbird", "claim,fsp", merge_into=INERT)
    assert yaml.safe_load(first) == fresh
    second = _gen("songbird", "claim,fsp", merge_into=first)
    assert yaml.safe_load(second) == fresh


# ---------------------------------------------------------------------------
# 4. Idempotency holds while still preserving an UNRELATED existing network
# ---------------------------------------------------------------------------


def test_remerge_same_network_preserves_other_network_byte_identical() -> None:
    """Re-adding songbird must not perturb a flare already present (superset, no churn)."""
    two_net = _gen("flare,songbird", "claim,fsp")
    two_doc = yaml.safe_load(two_net)
    re_songbird = _gen("songbird", "claim,fsp", merge_into=two_net)
    doc = yaml.safe_load(re_songbird)

    # flare keys are untouched by re-merging songbird
    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        for key, val in two_doc[section].items():
            assert doc[section][key] == val, f"{section}/{key} changed on songbird re-merge"
    # whole-doc content equality too
    assert doc == two_doc


def test_idempotent_merge_still_roundtrips(tmp_path: Path) -> None:
    """A re-merged policy still passes the daemon's own startup checks."""
    base = _gen("flare,songbird", "claim,fsp")
    again = _gen("songbird", "claim,fsp", merge_into=base)
    assert _roundtrip(tmp_path, again) == []


def test_order_independent_merge_still_roundtrips(tmp_path: Path) -> None:
    incremental = _gen("songbird", "claim,fsp", merge_into=_gen("flare", "claim,fsp"))
    assert _roundtrip(tmp_path, incremental) == []


# ---------------------------------------------------------------------------
# 5. Version is carried idempotently (never duplicated / dropped on re-merge)
# ---------------------------------------------------------------------------


def test_version_carried_on_remerge() -> None:
    base = _gen("songbird", "claim,fsp")
    again = _gen("songbird", "claim,fsp", merge_into=base)
    assert yaml.safe_load(again)["version"] == yaml.safe_load(base)["version"] == 1
