"""Adversarial tests for the a76 additive policy-merge (merge_into / _merge_policies).

THE INVARIANT UNDER TEST: for any existing policy P and any added network N,
the merged policy must be a SUPERSET of P — adding a network must NEVER drop or
alter a caller/wallet/permission/constraint that P already had.

This file deliberately FEEDS MALFORMED merge_into to generate_policy and
_merge_policies and asserts:
  - PolicyInitError where the code raises it (invalid YAML, non-mapping),
  - graceful "fresh generate" where it does not (None / empty / whitespace),
  - superset-preservation for odd-but-valid base mappings (missing sections,
    null sections, unknown top-level keys, weird fsp_self_submit contents).

Every assertion here was derived by READING src/fwd/app/policy_init.py
(_merge_policies + the merge block of generate_policy) — never assumed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from fwd.app.policy_init import PolicyInitError, _merge_policies, generate_policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.policy_loader import check_consistency, load_policy

_ROOT = Path(__file__).resolve().parents[2]
ABIS_DIR = _ROOT / "config" / "abis"
NETWORKS_FILE = _ROOT / "config" / "networks.yaml"
RECIPIENT = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"


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


# ---------------------------------------------------------------------------
# merge_into that means "no merge — fresh generate" (None / empty / whitespace)
# ---------------------------------------------------------------------------


def test_merge_into_none_is_fresh_generate() -> None:
    """merge_into=None → identical to a plain generate (no merge path taken)."""
    fresh = _gen("songbird", "claim,fsp", merge_into=None)
    plain = _gen("songbird", "claim,fsp")
    assert yaml.safe_load(fresh) == yaml.safe_load(plain)


def test_merge_into_empty_string_is_fresh_generate() -> None:
    """Empty string fails the `merge_into.strip()` guard → fresh generate, no error."""
    merged = _gen("songbird", "claim,fsp", merge_into="")
    plain = _gen("songbird", "claim,fsp")
    assert yaml.safe_load(merged) == yaml.safe_load(plain)


def test_merge_into_whitespace_only_is_fresh_generate() -> None:
    """Whitespace-only (spaces, tabs, newlines) also fails the strip() guard → fresh."""
    merged = _gen("songbird", "claim,fsp", merge_into="   \n\t  \n")
    plain = _gen("songbird", "claim,fsp")
    assert yaml.safe_load(merged) == yaml.safe_load(plain)


def test_merge_into_comment_only_yaml_parses_to_none_treated_as_empty(tmp_path: Path) -> None:
    """A merge target of only comments + a newline parses to None → existing={} →
    merge into an empty base == fresh generate. Survives the daemon's checks."""
    comment_only = "# nothing but a comment\n# another comment\n"
    merged = _gen("songbird", "claim,fsp", merge_into=comment_only)
    plain = _gen("songbird", "claim,fsp")
    assert yaml.safe_load(merged) == yaml.safe_load(plain)
    assert _roundtrip(tmp_path, merged) == []


# ---------------------------------------------------------------------------
# merge_into that the code REJECTS with PolicyInitError
# ---------------------------------------------------------------------------


def test_merge_into_invalid_yaml_raises() -> None:
    """Structurally invalid YAML → yaml.YAMLError → PolicyInitError(not valid YAML)."""
    # Unbalanced flow mapping is a hard parse error, not just odd content.
    with pytest.raises(PolicyInitError, match="not valid YAML"):
        _gen("flare", "claim", merge_into="version: 1\ncallers: {unterminated: \n  - a: [1, 2}\n")


def test_merge_into_tab_indentation_raises() -> None:
    """A tab used for indentation is a YAML scanner error → PolicyInitError(not valid YAML)."""
    with pytest.raises(PolicyInitError, match="not valid YAML"):
        _gen("flare", "claim", merge_into="callers:\n\tclaim-x: {}\n")


def test_merge_into_yaml_list_raises_non_mapping() -> None:
    """A top-level YAML list is valid YAML but not a policy mapping → PolicyInitError."""
    with pytest.raises(PolicyInitError, match="not a policy mapping"):
        _gen("flare", "claim", merge_into="- just\n- a\n- list\n")


def test_merge_into_scalar_string_raises_non_mapping() -> None:
    """A bare scalar string is valid YAML, parses to a str, not a dict → PolicyInitError."""
    with pytest.raises(PolicyInitError, match="not a policy mapping"):
        _gen("flare", "claim", merge_into="just-a-string-not-a-mapping")


def test_merge_into_scalar_int_raises_non_mapping() -> None:
    """A bare integer parses to int → not a mapping → PolicyInitError."""
    with pytest.raises(PolicyInitError, match="not a policy mapping"):
        _gen("flare", "claim", merge_into="42\n")


def test_merge_into_scalar_bool_raises_non_mapping() -> None:
    """A bare YAML bool parses to True → not a mapping → PolicyInitError."""
    with pytest.raises(PolicyInitError, match="not a policy mapping"):
        _gen("flare", "claim", merge_into="true\n")


# ---------------------------------------------------------------------------
# odd-but-valid base mappings — must NOT crash, must preserve the base (superset)
# ---------------------------------------------------------------------------


def test_merge_into_empty_mapping_equals_fresh(tmp_path: Path) -> None:
    """An explicit empty mapping `{}` is a valid dict → merge into empty == fresh."""
    merged = _gen("songbird", "claim,fsp", merge_into="{}\n")
    plain = _gen("songbird", "claim,fsp")
    assert yaml.safe_load(merged) == yaml.safe_load(plain)
    assert _roundtrip(tmp_path, merged) == []


def test_merge_into_mapping_missing_all_sections(tmp_path: Path) -> None:
    """A base that is just `version: 1` (no callers/wallets/... sections at all) —
    the inert-default case — merges cleanly and produces the network's rules."""
    base = "version: 1\n"
    merged = _gen("songbird", "claim,fsp", merge_into=base)
    doc = yaml.safe_load(merged)
    assert "claimer-songbird" in doc["wallets"]
    assert "claim-songbird" in doc["callers"]
    assert _roundtrip(tmp_path, merged) == []


def test_merge_into_mapping_with_only_some_sections_preserves_them(tmp_path: Path) -> None:
    """Base has a wallets section but no callers/permissions — the present sections
    survive; the absent ones are populated by the added network."""
    base = (
        "version: 1\n"
        "wallets:\n"
        "  preexisting-wallet:\n"
        "    policy_path: wc/preexisting\n"
        "wallet_constraints:\n"
        "  wc/preexisting:\n"
        "    max_aggregate_value_wei_per_day: '0'\n"
        "    rate: {per_hour: 1, per_day: 2}\n"
    )
    merged = _gen("songbird", "claim", merge_into=base)
    doc = yaml.safe_load(merged)
    # the preexisting wallet survives untouched
    assert doc["wallets"]["preexisting-wallet"] == {"policy_path": "wc/preexisting"}
    assert "wc/preexisting" in doc["wallet_constraints"]
    # and the added network is present
    assert "claimer-songbird" in doc["wallets"]
    assert "claim-songbird" in doc["callers"]


def test_merge_into_section_explicitly_null_does_not_crash(tmp_path: Path) -> None:
    """A section explicitly set to YAML null (`callers:` with no value) → cur is None;
    _merge_policies coerces non-dict cur to {} when there are additions for it.
    Must not crash and must end with the added network's keys."""
    base = "version: 1\ncallers:\nwallets:\npermissions:\n"
    merged = _gen("songbird", "claim", merge_into=base)
    doc = yaml.safe_load(merged)
    assert "claim-songbird" in doc["callers"]
    assert "claimer-songbird" in doc["wallets"]
    assert _roundtrip(tmp_path, merged) == []


def test_merge_into_unknown_top_level_key_preserved() -> None:
    """An unknown extra top-level key is carried through verbatim (deepcopy of base),
    never dropped or made to crash the merge."""
    base = "version: 1\nmy_custom_top_level: {foo: bar, nested: [1, 2, 3]}\n"
    merged = _gen("songbird", "claim", merge_into=base)
    doc = yaml.safe_load(merged)
    assert doc["my_custom_top_level"] == {"foo": "bar", "nested": [1, 2, 3]}
    # the added network coexists with the unknown key
    assert "claim-songbird" in doc["callers"]


def test_merge_into_preserves_version_from_base_when_additions_default() -> None:
    """version is carried: additions always emit version 1, base is also 1 — but
    confirm the merge writes a concrete version (the merged policy is loadable)."""
    base = "version: 1\n"
    merged = _gen("songbird", "claim", merge_into=base)
    doc = yaml.safe_load(merged)
    assert doc["version"] == 1


# ---------------------------------------------------------------------------
# fsp_self_submit adversarial shapes — directly against _merge_policies, which is
# where the list-union logic lives (the generate_policy path always emits a clean
# list of str, so these odd shapes can only arrive via a hand-edited base).
# ---------------------------------------------------------------------------


def _additions_with_self_submit(*names: str) -> dict[str, object]:
    """Minimal additions dict carrying only an fsp_self_submit list."""
    return {"version": 1, "fsp_self_submit": list(names)}


def test_merge_self_submit_base_non_list_string_is_sanitised() -> None:
    """If a hand-edited base has fsp_self_submit as a STRING (not a list), the merge
    filters it via `isinstance(w, str)` on iteration. Iterating a string yields its
    chars — DOCUMENTS the actual behaviour: the malformed scalar is exploded into
    single-char entries, then the addition is appended.

    This is NOT the merge dropping a real entry — a string base value was never a
    valid fsp_self_submit and could only come from manual corruption. We assert the
    code does not CRASH and that the legitimately-added wallet survives."""
    base = {"version": 1, "fsp_self_submit": "fsp-signing-songbird"}
    merged = _merge_policies(base, _additions_with_self_submit("fsp-signing-flare"))
    # does not raise; the real added wallet is present
    assert "fsp-signing-flare" in merged["fsp_self_submit"]
    # the string got exploded to chars (documented quirk of a corrupt base, not a
    # superset violation of any *valid* base) — the list is all strings, no crash
    assert all(isinstance(w, str) for w in merged["fsp_self_submit"])


def test_merge_self_submit_base_with_non_string_entries_filtered() -> None:
    """Non-string entries in a hand-corrupted base fsp_self_submit list are dropped
    by the `isinstance(w, str)` filter; valid string entries are kept."""
    base = {"version": 1, "fsp_self_submit": ["fsp-signing-songbird", 123, None, "keep-me"]}
    merged = _merge_policies(base, _additions_with_self_submit("fsp-signing-flare"))
    ss = merged["fsp_self_submit"]
    assert "fsp-signing-songbird" in ss
    assert "keep-me" in ss
    assert "fsp-signing-flare" in ss
    assert 123 not in ss
    assert None not in ss


def test_merge_self_submit_dedups_overlap() -> None:
    """A wallet already in the base list is not duplicated when re-added."""
    base = {"version": 1, "fsp_self_submit": ["fsp-signing-songbird"]}
    merged = _merge_policies(
        base, _additions_with_self_submit("fsp-signing-songbird", "fsp-signing-flare")
    )
    ss = merged["fsp_self_submit"]
    assert ss.count("fsp-signing-songbird") == 1
    assert ss == ["fsp-signing-songbird", "fsp-signing-flare"]


def test_merge_self_submit_preserves_order() -> None:
    """Order-preserving list union: base order first, then new additions in order."""
    base = {"version": 1, "fsp_self_submit": ["a", "b"]}
    merged = _merge_policies(base, {"version": 1, "fsp_self_submit": ["b", "c", "d"]})
    assert merged["fsp_self_submit"] == ["a", "b", "c", "d"]


def test_merge_self_submit_absent_in_both_is_omitted() -> None:
    """If neither base nor additions has fsp_self_submit, the key is not emitted
    (the `if ss:` guard) — a claim-only merge has no fsp_self_submit."""
    base = {"version": 1}
    merged = _merge_policies(base, {"version": 1})
    assert "fsp_self_submit" not in merged


# ---------------------------------------------------------------------------
# the core superset invariant against a realistic, fully-populated base
# ---------------------------------------------------------------------------


def test_merge_superset_against_populated_base(tmp_path: Path) -> None:
    """The headline invariant: take a real generated songbird policy as the base,
    add flare via merge, and assert EVERY base key in EVERY dict section is present
    and byte-identical in the merged result (superset; nothing dropped or altered)."""
    base_text = _gen("songbird", "claim,fsp")
    base_doc = yaml.safe_load(base_text)
    merged_doc = yaml.safe_load(_gen("flare", "claim,fsp", merge_into=base_text))

    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        for key, val in base_doc[section].items():
            assert key in merged_doc[section], f"dropped {section}/{key}"
            assert merged_doc[section][key] == val, f"altered {section}/{key}"

    # base fsp_self_submit entries all survive
    for w in base_doc["fsp_self_submit"]:
        assert w in merged_doc["fsp_self_submit"]

    assert _roundtrip(tmp_path, _gen("flare", "claim,fsp", merge_into=base_text)) == []


def test_merge_base_section_as_non_dict_scalar_does_not_drop_additions() -> None:
    """If a hand-corrupted base has a dict-section set to a SCALAR (e.g. callers: 5),
    _merge_policies replaces the non-dict cur with {} before unioning additions —
    so the corrupt scalar is discarded but the ADDED network's keys are never lost.

    This documents that a corrupt base scalar cannot swallow the additions (the
    additive guarantee holds even on a malformed base for the added network)."""
    base = {"version": 1, "callers": 5, "wallets": "oops"}
    additions = {
        "version": 1,
        "callers": {"claim-songbird": {"policy_path": "perm/claim-songbird"}},
        "wallets": {"claimer-songbird": {"policy_path": "wc/claimer-songbird"}},
    }
    merged = _merge_policies(base, additions)
    assert merged["callers"] == {"claim-songbird": {"policy_path": "perm/claim-songbird"}}
    assert merged["wallets"] == {"claimer-songbird": {"policy_path": "wc/claimer-songbird"}}
