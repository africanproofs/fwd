"""Adversarial roundtrip tests for the a76 additive policy-merge.

DIMENSION: roundtrip. The binding assertion: every MERGED combination — 2 and 3
networks, every capability mix (claim / fsp / claim,fsp), both fsp_sender modes
(per-network / shared) — round-trips through the daemon's OWN startup checks
(load_policy schema + check_consistency vs an empty DB + the real ABI registry)
with ZERO errors. A merged policy is always a valid a29 policy: adding a network
to an existing policy produces a SUPERSET that the daemon accepts unchanged.

This complements test_policy_init.py (which proves a *fresh* generate is valid).
Here the invariant under attack is: union(P, network N) is itself a schema- and
consistency-valid a29 policy for every order, every cap mix, every sender mode —
the merge never emits a policy the daemon would reject at startup.

Read the code under test: src/fwd/app/policy_init.py (_merge_policies +
generate_policy) and src/fwd/cli/policy.py (--merge passes the live policy in).
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

# Empty default-deny policy the installer drops in (the first merge target).
INERT = "# fwd INERT default-deny policy (installed). Empty on purpose.\nversion: 1\n"

# Every (networks, capabilities) that should round-trip clean.
NETWORKS = ("flare", "songbird", "coston2")
CAP_MIXES = ("claim", "fsp", "claim,fsp")
SENDER_MODES = ("per-network", "shared")


def _gen(
    networks: str,
    capabilities: str,
    *,
    recipient: str | None = RECIPIENT,
    fsp_sender_mode: str = "per-network",
    merge_into: str | None = None,
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
    """Write, load_policy (schema), check_consistency vs empty DB. Return errors."""
    p = tmp_path / "policy.yaml"
    p.write_text(text)
    policy = load_policy(p)  # raises PolicyLoadError on schema failure
    registry = AbiRegistry.load(ABIS_DIR)
    return check_consistency(policy, [], [], registry)


def _assert_valid(tmp_path: Path, text: str) -> dict:
    """Roundtrip MUST be clean; return the parsed doc for further assertions."""
    errors = _roundtrip(tmp_path, text)
    assert errors == [], f"merged policy failed daemon startup checks: {errors}"
    return yaml.safe_load(text)


# ---------------------------------------------------------------------------
# Core matrix: merge ONE network into the inert default, every cap × sender.
# This is the literal first-onboard path the installer drives.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("net", NETWORKS)
@pytest.mark.parametrize("caps", CAP_MIXES)
@pytest.mark.parametrize("mode", SENDER_MODES)
def test_merge_single_into_inert_roundtrips(tmp_path: Path, net: str, caps: str, mode: str) -> None:
    """Every (network × cap-mix × sender-mode) merged into INERT round-trips clean."""
    text = _gen(net, caps, fsp_sender_mode=mode, merge_into=INERT)
    _assert_valid(tmp_path, text)


@pytest.mark.parametrize("net", NETWORKS)
@pytest.mark.parametrize("caps", CAP_MIXES)
@pytest.mark.parametrize("mode", SENDER_MODES)
def test_merge_into_inert_equals_fresh(net: str, caps: str, mode: str) -> None:
    """Merging into the inert/empty policy is identical to a fresh generate.

    The inert policy carries only `version: 1`; the union must add exactly the
    fresh network rules and nothing else — proves the merge introduces no
    artifacts that would diverge a merged policy from a freshly generated one.
    """
    fresh = yaml.safe_load(_gen(net, caps, fsp_sender_mode=mode))
    merged = yaml.safe_load(_gen(net, caps, fsp_sender_mode=mode, merge_into=INERT))
    assert merged == fresh


# ---------------------------------------------------------------------------
# Two-network merges: onboard A fresh, then ADD B by merging. Round-trip clean
# for EVERY ordered pair and EVERY cap mix and EVERY sender mode.
# ---------------------------------------------------------------------------


def _ordered_pairs() -> list[tuple[str, str]]:
    return [(a, b) for a in NETWORKS for b in NETWORKS if a != b]


@pytest.mark.parametrize("first,second", _ordered_pairs())
@pytest.mark.parametrize("caps", CAP_MIXES)
@pytest.mark.parametrize("mode", SENDER_MODES)
def test_merge_two_networks_roundtrips(
    tmp_path: Path, first: str, second: str, caps: str, mode: str
) -> None:
    """Onboard `first`, merge-add `second`: the 2-network policy round-trips clean."""
    base = _gen(first, caps, fsp_sender_mode=mode)
    merged = _gen(second, caps, fsp_sender_mode=mode, merge_into=base)
    doc = _assert_valid(tmp_path, merged)

    # Both networks' claim wallets present (when claim is in the mix).
    if "claim" in caps:
        assert f"claimer-{first}" in doc["wallets"]
        assert f"claimer-{second}" in doc["wallets"]
    # Both networks' FSP signing wallets present (when fsp is in the mix).
    if "fsp" in caps:
        assert f"fsp-signing-{first}" in doc["wallets"]
        assert f"fsp-signing-{second}" in doc["wallets"]


@pytest.mark.parametrize("first,second", _ordered_pairs())
@pytest.mark.parametrize("mode", SENDER_MODES)
def test_merge_two_networks_mixed_caps_roundtrips(
    tmp_path: Path, first: str, second: str, mode: str
) -> None:
    """A claim-only base + an fsp-only addition (and the reverse) still round-trips.

    The merge unions heterogeneous cap sections; the resulting hybrid policy must
    remain a valid a29 policy (a claim network alongside an fsp-only network).
    """
    base = _gen(first, "claim", fsp_sender_mode=mode)
    merged = _gen(second, "fsp", fsp_sender_mode=mode, merge_into=base)
    doc = _assert_valid(tmp_path, merged)
    assert f"claimer-{first}" in doc["wallets"]
    assert f"fsp-signing-{second}" in doc["wallets"]

    # reverse order
    base2 = _gen(first, "fsp", fsp_sender_mode=mode)
    merged2 = _gen(second, "claim", fsp_sender_mode=mode, merge_into=base2)
    doc2 = _assert_valid(tmp_path, merged2)
    assert f"fsp-signing-{first}" in doc2["wallets"]
    assert f"claimer-{second}" in doc2["wallets"]


# ---------------------------------------------------------------------------
# Three-network merges: the full Flare-family set, added one at a time. The
# 3-network policy round-trips clean for every cap mix and sender mode.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("caps", CAP_MIXES)
@pytest.mark.parametrize("mode", SENDER_MODES)
def test_merge_three_networks_roundtrips(tmp_path: Path, caps: str, mode: str) -> None:
    """flare → +songbird → +coston2, added incrementally, round-trips clean."""
    p = _gen("flare", caps, fsp_sender_mode=mode)
    p = _gen("songbird", caps, fsp_sender_mode=mode, merge_into=p)
    p = _gen("coston2", caps, fsp_sender_mode=mode, merge_into=p)
    doc = _assert_valid(tmp_path, p)

    if "claim" in caps:
        assert {"claimer-flare", "claimer-songbird", "claimer-coston2"} <= set(doc["wallets"])
    if "fsp" in caps:
        assert {
            "fsp-signing-flare",
            "fsp-signing-songbird",
            "fsp-signing-coston2",
        } <= set(doc["wallets"])


def test_merge_three_networks_equals_single_fresh_generate(tmp_path: Path) -> None:
    """Three incremental single-network merges == one fresh 3-network generate.

    Onboarding-one-at-a-time must converge to exactly the policy a single
    `generate_policy(networks=[all three])` would have produced — the additive
    path is not a second, divergent code path.
    """
    incremental = _gen("flare", "claim,fsp")
    incremental = _gen("songbird", "claim,fsp", merge_into=incremental)
    incremental = _gen("coston2", "claim,fsp", merge_into=incremental)

    one_shot = _gen("flare,songbird,coston2", "claim,fsp")

    # Both must round-trip clean...
    assert _roundtrip(tmp_path, incremental) == []
    assert _roundtrip(tmp_path, one_shot) == []
    # ...and be semantically identical.
    inc_doc = yaml.safe_load(incremental)
    one_doc = yaml.safe_load(one_shot)
    assert inc_doc == one_doc


# ---------------------------------------------------------------------------
# Idempotency under roundtrip: re-merging a network already present yields a
# policy that is still valid AND identical (no duplicate-key growth that could
# break consistency).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("net", NETWORKS)
@pytest.mark.parametrize("caps", CAP_MIXES)
@pytest.mark.parametrize("mode", SENDER_MODES)
def test_merge_same_network_idempotent_and_valid(
    tmp_path: Path, net: str, caps: str, mode: str
) -> None:
    """Re-merging an already-present network is a no-op AND stays round-trip-valid."""
    base = _gen(net, caps, fsp_sender_mode=mode)
    twice = _gen(net, caps, fsp_sender_mode=mode, merge_into=base)
    assert _roundtrip(tmp_path, twice) == []
    assert yaml.safe_load(twice) == yaml.safe_load(base)


def test_repeated_remerge_is_fixed_point(tmp_path: Path) -> None:
    """Merging the same network five times never diverges and stays valid."""
    p = _gen("songbird", "claim,fsp")
    first = yaml.safe_load(p)
    for _ in range(5):
        p = _gen("songbird", "claim,fsp", merge_into=p)
        assert _roundtrip(tmp_path, p) == []
    assert yaml.safe_load(p) == first


# ---------------------------------------------------------------------------
# Shared-sender mode under merge: the single shared fsp-sender / wc/fsp-sender
# is reused across networks. The merged multi-network shared-sender policy must
# still round-trip clean (one sender wallet allowlisted across N submit perms).
# ---------------------------------------------------------------------------


def test_merge_shared_sender_multinetwork_roundtrips(tmp_path: Path) -> None:
    """Shared-sender mode: one fsp-sender shared across flare+songbird, still valid."""
    base = _gen("flare", "fsp", fsp_sender_mode="shared")
    merged = _gen("songbird", "fsp", fsp_sender_mode="shared", merge_into=base)
    doc = _assert_valid(tmp_path, merged)

    # exactly one shared sender wallet, no per-net sender wallets
    assert "fsp-sender" in doc["wallets"]
    assert "fsp-sender-flare" not in doc["wallets"]
    assert "fsp-sender-songbird" not in doc["wallets"]
    # the shared sender is allowlisted in BOTH networks' submit permissions
    assert "fsp-sender" in doc["permissions"]["perm/uptime-submit-flare"]["wallet_allowlist"]
    assert "fsp-sender" in doc["permissions"]["perm/uptime-submit-songbird"]["wallet_allowlist"]


def test_merge_three_networks_shared_sender_roundtrips(tmp_path: Path) -> None:
    """Shared sender across all three Flare-family networks round-trips clean."""
    p = _gen("flare", "claim,fsp", fsp_sender_mode="shared")
    p = _gen("songbird", "claim,fsp", fsp_sender_mode="shared", merge_into=p)
    p = _gen("coston2", "claim,fsp", fsp_sender_mode="shared", merge_into=p)
    doc = _assert_valid(tmp_path, p)
    assert "fsp-sender" in doc["wallets"]
    # one shared wc constraint, referenced by every network's sender wallet
    assert "wc/fsp-sender" in doc["wallet_constraints"]


# ---------------------------------------------------------------------------
# fsp_self_submit list union survives roundtrip: every signing wallet across
# all merged networks is in the carve-out, with no duplicates, and the policy
# stays valid (the carve-out is what makes the self-submit segmentation pass).
# ---------------------------------------------------------------------------


def test_merge_self_submit_union_complete_and_valid(tmp_path: Path) -> None:
    """fsp_self_submit accumulates every network's signing wallet, dedup'd, valid."""
    p = _gen("flare", "fsp")
    p = _gen("songbird", "fsp", merge_into=p)
    p = _gen("coston2", "fsp", merge_into=p)
    doc = _assert_valid(tmp_path, p)
    ss = doc["fsp_self_submit"]
    assert sorted(ss) == ["fsp-signing-coston2", "fsp-signing-flare", "fsp-signing-songbird"]
    # no duplicates introduced by the list-union path
    assert len(ss) == len(set(ss))


def test_merge_preexisting_self_submit_entries_preserved(tmp_path: Path) -> None:
    """A pre-existing (valid) fsp_self_submit entry survives a later network merge.

    The superset invariant under round-trip: a base that ALREADY has an fsp
    network (its signing wallet legitimately in fsp_self_submit + both its
    allowlists) must keep that carve-out entry intact after a second network is
    merged in — and the union must stay a valid a29 policy. Using a real,
    generator-produced base keeps the base itself consistent (an orphan carve-out
    wallet with no fsp_permissions allowlist is rejected by check_consistency by
    design, so the pre-existing entry must be a genuine, allowlisted one).
    """
    base = _gen("flare", "fsp")  # valid: fsp-signing-flare is a real carve-out entry
    assert "fsp-signing-flare" in yaml.safe_load(base)["fsp_self_submit"]

    merged = _gen("songbird", "fsp", merge_into=base)
    doc = _assert_valid(tmp_path, merged)

    # the pre-existing carve-out entry + its wallet + its constraint all survived
    assert "fsp-signing-flare" in doc["fsp_self_submit"]
    assert "fsp-signing-flare" in doc["wallets"]
    assert "wc/fsp-flare" in doc["wallet_constraints"]
    # and the newly-added network's carve-out entry joined it, deduped & ordered
    assert "fsp-signing-songbird" in doc["fsp_self_submit"]
    assert len(doc["fsp_self_submit"]) == len(set(doc["fsp_self_submit"]))


# ---------------------------------------------------------------------------
# Merge into a policy where merge_into is an EMPTY/whitespace/None string: the
# generator must fall back to a fresh (non-merged) generate — which itself must
# round-trip clean. (--merge with a missing/empty live policy file passes "".)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("merge_arg", [None, "", "   \n  "])
def test_merge_empty_target_falls_back_to_fresh_and_roundtrips(
    tmp_path: Path, merge_arg: str | None
) -> None:
    """None / empty / whitespace merge_into ⇒ fresh generate, still valid."""
    text = _gen("songbird", "claim,fsp", merge_into=merge_arg)
    doc_merged = _assert_valid(tmp_path, text)
    doc_fresh = yaml.safe_load(_gen("songbird", "claim,fsp"))
    assert doc_merged == doc_fresh


def test_merge_into_version_only_target_roundtrips(tmp_path: Path) -> None:
    """A target that is JUST `version: 1` (no sections) merges and round-trips."""
    text = _gen("flare", "claim,fsp", merge_into="version: 1\n")
    _assert_valid(tmp_path, text)


# ---------------------------------------------------------------------------
# Coverage cross-check: after a full 3-network claim,fsp merge, every section
# the consistency checker validates is present and the wallet/caller cross-refs
# resolve (this is exactly what a non-empty round-trip would have flagged).
# ---------------------------------------------------------------------------


def test_merge_full_set_all_sections_consistent(tmp_path: Path) -> None:
    """Full 3-network claim,fsp merge: every section present + cross-refs resolve."""
    p = _gen("flare", "claim,fsp")
    p = _gen("songbird", "claim,fsp", merge_into=p)
    p = _gen("coston2", "claim,fsp", merge_into=p)
    doc = _assert_valid(tmp_path, p)

    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        assert section in doc and doc[section], f"missing/empty section {section}"

    # Every caller's policy_path resolves to a permissions OR fsp_permissions key.
    perm_keys = set(doc["permissions"]) | set(doc["fsp_permissions"])
    for caller, spec in doc["callers"].items():
        assert spec["policy_path"] in perm_keys, f"caller {caller} dangling policy_path"

    # Every wallet's policy_path resolves to a wallet_constraints key.
    wc_keys = set(doc["wallet_constraints"])
    for wallet, spec in doc["wallets"].items():
        assert spec["policy_path"] in wc_keys, f"wallet {wallet} dangling policy_path"

    # Every permission/fsp_permission wallet_allowlist entry is a real wallet.
    wallet_keys = set(doc["wallets"])
    for pp, spec in {**doc["permissions"], **doc["fsp_permissions"]}.items():
        for w in spec.get("wallet_allowlist", []):
            assert w in wallet_keys, f"{pp} allowlists unknown wallet {w}"


# ---------------------------------------------------------------------------
# Negative: an invalid merge target must raise (not silently emit a broken
# policy that would later fail the daemon's startup) — guards the roundtrip
# contract at the input boundary.
# ---------------------------------------------------------------------------


def test_merge_non_mapping_target_raises() -> None:
    with pytest.raises(PolicyInitError, match="not a policy mapping"):
        _gen("flare", "claim", merge_into="- a\n- b\n")


def test_merge_invalid_yaml_target_raises() -> None:
    with pytest.raises(PolicyInitError, match="not valid YAML"):
        _gen("flare", "claim", merge_into="key: [unterminated\n")


def test_merge_scalar_target_raises() -> None:
    """A bare scalar (not a mapping) is rejected before any policy is emitted."""
    with pytest.raises(PolicyInitError, match="not a policy mapping"):
        _gen("flare", "claim", merge_into="just-a-string\n")
