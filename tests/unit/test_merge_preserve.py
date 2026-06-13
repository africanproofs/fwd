"""Adversarial PRESERVATION tests for the a76 additive policy-merge.

Dimension: "preserve". The invariant under protection: for any existing policy P
and any added network N, the merged policy is a SUPERSET of P — every key P had
survives byte-identical (deep-equal). Nothing P contained may be dropped or
altered by adding N.

The sharpest case is a HAND-ADDED key the new generation does NOT itself emit
(an operator-added caller, an extra contract under an existing network, a wholly
unknown top-level section). `_merge_policies` deep-copies the base first, then
per-key unions each known dict section, so hand-added keys with no collision must
survive untouched. Per-network claim `_recipient` predicates are network-suffixed
and therefore preserved independently across networks.

Style mirrors tests/unit/test_policy_init.py: generate via generate_policy(),
round-trip through the daemon's own load_policy + check_consistency, parse with
yaml.safe_load.
"""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

from fwd.app.policy_init import generate_policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.policy_loader import check_consistency, load_policy

_ROOT = Path(__file__).resolve().parents[2]
ABIS_DIR = _ROOT / "config" / "abis"
NETWORKS_FILE = _ROOT / "config" / "networks.yaml"
RECIPIENT = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"
# A distinct, valid checksummed address — a different per-network recipient.
RECIPIENT_ALT = "0x49CFE6199FffCA921B40e2290f565Ad107A530E0"


def _gen(networks: str, capabilities: str, recipient: str | None = RECIPIENT) -> str:
    return generate_policy(
        networks=networks.split(","),
        capabilities=capabilities.split(","),
        recipient=recipient,
        abis_dir=ABIS_DIR,
        networks_file=NETWORKS_FILE,
    )


def _gen_merge(
    networks: str,
    capabilities: str,
    merge_into: str,
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


def _assert_section_superset(base_doc: dict, merged_doc: dict, section: str) -> None:
    """Every key/value in base_doc[section] is byte-identical in merged_doc[section]."""
    for key, val in base_doc.get(section, {}).items():
        assert key in merged_doc.get(section, {}), f"{section}/{key} dropped by merge"
        assert merged_doc[section][key] == val, f"{section}/{key} altered by merge"


# ---------------------------------------------------------------------------
# 1. Whole-policy superset: every existing key survives deep-equal
# ---------------------------------------------------------------------------


def test_every_existing_section_key_survives_deep_equal(tmp_path: Path) -> None:
    """Onboard songbird, add flare: every songbird section key is deep-equal preserved."""
    songbird = _gen("songbird", "claim,fsp")
    sb_doc = yaml.safe_load(songbird)
    merged = _gen_merge("flare", "claim,fsp", songbird)
    doc = yaml.safe_load(merged)

    for section in (
        "callers",
        "wallets",
        "permissions",
        "wallet_constraints",
        "fsp_permissions",
    ):
        _assert_section_superset(sb_doc, doc, section)

    # fsp_self_submit: the existing entry survives (order-preserving union).
    for w in sb_doc["fsp_self_submit"]:
        assert w in doc["fsp_self_submit"], f"fsp_self_submit dropped {w}"

    assert _roundtrip(tmp_path, merged) == []


def test_merge_never_shrinks_any_section() -> None:
    """No section in the merged policy is smaller than in the base."""
    songbird = _gen("songbird", "claim,fsp")
    sb_doc = yaml.safe_load(songbird)
    merged = _gen_merge("flare", "claim,fsp", songbird)
    doc = yaml.safe_load(merged)

    for section in (
        "callers",
        "wallets",
        "permissions",
        "wallet_constraints",
        "fsp_permissions",
        "fsp_self_submit",
    ):
        assert len(doc[section]) >= len(sb_doc[section]), f"{section} shrank"


# ---------------------------------------------------------------------------
# 2. HAND-ADDED keys the generator never emits must survive
# ---------------------------------------------------------------------------


def test_hand_added_caller_survives_merge(tmp_path: Path) -> None:
    """An operator-added caller (a key the generator never emits) survives the merge."""
    songbird = _gen("songbird", "claim")
    base = yaml.safe_load(songbird)
    base["callers"]["operator-extra"] = {"policy_path": "perm/claim-songbird"}
    base_text = yaml.safe_dump(base, sort_keys=False)

    merged = _gen_merge("flare", "claim", base_text)
    doc = yaml.safe_load(merged)

    assert "operator-extra" in doc["callers"], "hand-added caller dropped by merge"
    assert doc["callers"]["operator-extra"] == {"policy_path": "perm/claim-songbird"}
    # and the generator's own keys are all present too
    assert {"claim-songbird", "claim-flare"} <= set(doc["callers"])
    assert _roundtrip(tmp_path, merged) == []


def test_hand_added_wallet_and_constraint_survive(tmp_path: Path) -> None:
    """A hand-added wallet + its wallet_constraint survive a network add."""
    songbird = _gen("songbird", "claim")
    base = yaml.safe_load(songbird)
    base["wallets"]["gas-topup"] = {"policy_path": "wc/gas-topup"}
    base["wallet_constraints"]["wc/gas-topup"] = {
        "max_aggregate_value_wei_per_day": "0",
        "rate": {"per_hour": 1, "per_day": 2},
    }
    base_text = yaml.safe_dump(base, sort_keys=False)

    merged = _gen_merge("flare", "claim", base_text)
    doc = yaml.safe_load(merged)

    assert doc["wallets"]["gas-topup"] == {"policy_path": "wc/gas-topup"}
    assert doc["wallet_constraints"]["wc/gas-topup"] == {
        "max_aggregate_value_wei_per_day": "0",
        "rate": {"per_hour": 1, "per_day": 2},
    }
    assert _roundtrip(tmp_path, merged) == []


def test_hand_added_extra_contract_under_existing_network_survives(tmp_path: Path) -> None:
    """An operator adds a second contract to songbird's claim permission; adding flare keeps it.

    The generator's flare run rewrites perm/claim-flare (new key) and would only
    overwrite perm/claim-songbird if it were passed songbird — it is not. So the
    hand-edited perm/claim-songbird (now with an EXTRA contract) must survive
    byte-identical.
    """
    songbird = _gen("songbird", "claim")
    base = yaml.safe_load(songbird)
    perm = base["permissions"]["perm/claim-songbird"]
    # Add an operator-chosen extra contract block under the same permission.
    extra_addr = "0x1111111111111111111111111111111111111111"
    perm["contracts"][extra_addr] = {
        "abi": "reward_manager",
        "chains": [19],
        "methods": {
            "claim(address,address,uint24,bool)": {
                "max_value_wei": "0",
                "allow_unconstrained_args": True,
                "arg_predicates": {"_recipient": RECIPIENT},
            }
        },
    }
    expected_perm = copy.deepcopy(perm)
    base_text = yaml.safe_dump(base, sort_keys=False)

    merged = _gen_merge("flare", "claim", base_text)
    doc = yaml.safe_load(merged)

    assert (
        doc["permissions"]["perm/claim-songbird"] == expected_perm
    ), "hand-added extra contract on the existing network was lost/altered"
    assert extra_addr in doc["permissions"]["perm/claim-songbird"]["contracts"]


def test_unknown_top_level_section_survives(tmp_path: Path) -> None:
    """A top-level key the generator/merge does not know about is carried verbatim.

    _merge_policies deep-copies the base, so any section not in _MERGE_DICT_SECTIONS
    (and not version / fsp_self_submit) passes through untouched.
    """
    songbird = _gen("songbird", "claim")
    base = yaml.safe_load(songbird)
    base["operator_notes"] = {"owner": "khosi", "rotated": "2026-06-01"}
    base_text = yaml.safe_dump(base, sort_keys=False)

    merged = _gen_merge("flare", "claim", base_text)
    doc = yaml.safe_load(merged)

    assert doc["operator_notes"] == {"owner": "khosi", "rotated": "2026-06-01"}


# ---------------------------------------------------------------------------
# 3. Per-network _recipient predicates are preserved independently
# ---------------------------------------------------------------------------


def test_per_network_recipient_predicates_are_independent(tmp_path: Path) -> None:
    """Songbird pinned to RECIPIENT; add flare pinned to RECIPIENT_ALT — each keeps its own."""
    songbird = _gen("songbird", "claim", recipient=RECIPIENT)
    merged = _gen_merge("flare", "claim", songbird, recipient=RECIPIENT_ALT)
    doc = yaml.safe_load(merged)

    sb_addr = "0xE26AD68b17224951b5740F33926Cc438764eB9a7"  # songbird reward_manager
    fl_addr = "0xC8f55c5aA2C752eE285Bd872855C749f4ee6239B"  # flare reward_manager

    sb_method = next(
        iter(doc["permissions"]["perm/claim-songbird"]["contracts"][sb_addr]["methods"].values())
    )
    fl_method = next(
        iter(doc["permissions"]["perm/claim-flare"]["contracts"][fl_addr]["methods"].values())
    )

    assert sb_method["arg_predicates"]["_recipient"] == RECIPIENT
    assert fl_method["arg_predicates"]["_recipient"] == RECIPIENT_ALT
    assert _roundtrip(tmp_path, merged) == []


def test_existing_recipient_not_overwritten_by_new_network_recipient() -> None:
    """Adding flare with a DIFFERENT recipient does not rewrite songbird's recipient."""
    songbird = _gen("songbird", "claim", recipient=RECIPIENT)
    sb_doc = yaml.safe_load(songbird)
    sb_perm_before = copy.deepcopy(sb_doc["permissions"]["perm/claim-songbird"])

    merged = _gen_merge("flare", "claim", songbird, recipient=RECIPIENT_ALT)
    doc = yaml.safe_load(merged)

    assert doc["permissions"]["perm/claim-songbird"] == sb_perm_before


# ---------------------------------------------------------------------------
# 4. version is preserved (and stays schema-valid at 1)
# ---------------------------------------------------------------------------


def test_version_preserved_at_one() -> None:
    """The merged policy keeps version == 1 (both base and additions carry 1)."""
    songbird = _gen("songbird", "claim,fsp")
    merged = _gen_merge("flare", "claim,fsp", songbird)
    assert yaml.safe_load(merged)["version"] == 1


# ---------------------------------------------------------------------------
# 5. Three-network chain: each add preserves all prior networks
# ---------------------------------------------------------------------------


def test_three_network_sequential_adds_preserve_all_prior(tmp_path: Path) -> None:
    """songbird -> +flare -> +coston2: after each add, all prior networks survive deep-equal."""
    songbird = _gen("songbird", "claim,fsp")
    sb_doc = yaml.safe_load(songbird)

    plus_flare = _gen_merge("flare", "claim,fsp", songbird)
    pf_doc = yaml.safe_load(plus_flare)
    # songbird intact after adding flare
    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        _assert_section_superset(sb_doc, pf_doc, section)

    plus_coston2 = _gen_merge("coston2", "claim,fsp", plus_flare)
    pc_doc = yaml.safe_load(plus_coston2)
    # BOTH songbird and flare intact after adding coston2
    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        _assert_section_superset(pf_doc, pc_doc, section)

    # all three networks' signing wallets are present and self-submit carved out
    assert {
        "fsp-signing-songbird",
        "fsp-signing-flare",
        "fsp-signing-coston2",
    } <= set(pc_doc["fsp_self_submit"])
    assert {
        "claimer-songbird",
        "claimer-flare",
        "claimer-coston2",
    } <= set(pc_doc["wallets"])

    assert _roundtrip(tmp_path, plus_coston2) == []


# ---------------------------------------------------------------------------
# 6. Asymmetric capabilities: adding a claim-only network does not erase
#    the existing network's FSP rules
# ---------------------------------------------------------------------------


def test_adding_claim_only_network_preserves_existing_fsp(tmp_path: Path) -> None:
    """Base songbird has claim+fsp; add flare claim-only — songbird's FSP rules survive."""
    songbird = _gen("songbird", "claim,fsp")
    sb_doc = yaml.safe_load(songbird)
    merged = _gen_merge("flare", "claim", songbird)  # flare claim-only
    doc = yaml.safe_load(merged)

    # songbird's FSP machinery is entirely preserved
    assert "fsp/uptime-songbird" in doc["fsp_permissions"]
    assert doc["fsp_permissions"]["fsp/uptime-songbird"] == sb_doc["fsp_permissions"]["fsp/uptime-songbird"]
    assert "fsp-signing-songbird" in doc["fsp_self_submit"]
    assert "perm/uptime-submit-songbird" in doc["permissions"]
    assert (
        doc["permissions"]["perm/uptime-submit-songbird"]
        == sb_doc["permissions"]["perm/uptime-submit-songbird"]
    )
    # flare added claim-only: no flare FSP keys, but flare claim present
    assert "fsp/uptime-flare" not in doc["fsp_permissions"]
    assert "claim-flare" in doc["callers"]

    assert _roundtrip(tmp_path, merged) == []


# ---------------------------------------------------------------------------
# 7. fsp_self_submit preserves an operator-added entry (str union, no drop)
# ---------------------------------------------------------------------------


def test_fsp_self_submit_preserves_operator_added_entry() -> None:
    """A hand-added fsp_self_submit wallet survives the union (it is not the new net's)."""
    songbird = _gen("songbird", "fsp")
    base = yaml.safe_load(songbird)
    base["fsp_self_submit"].append("operator-extra-signer")
    base_text = yaml.safe_dump(base, sort_keys=False)

    merged = _gen_merge("flare", "fsp", base_text)
    doc = yaml.safe_load(merged)

    assert "operator-extra-signer" in doc["fsp_self_submit"]
    assert "fsp-signing-songbird" in doc["fsp_self_submit"]
    assert "fsp-signing-flare" in doc["fsp_self_submit"]
    # no duplicates introduced
    assert len(doc["fsp_self_submit"]) == len(set(doc["fsp_self_submit"]))
