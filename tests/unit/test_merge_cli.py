"""Adversarial CLI tests for `clifwd policy init --merge` (a76 additive merge).

Dimension: "cli". The invariant under protection: for any existing policy P
and any added network N, `clifwd policy init --merge` must produce a SUPERSET
of P — no caller/wallet/permission/constraint P had may be dropped or altered
by adding N. These tests drive the real Typer CLI (via CliRunner) so they cover
the cli/policy.py plumbing the unit-level generate_policy tests do not:

  - --merge reads settings.fwd_policy_path and merges into it,
  - a MISSING policy file → fresh generate (no crash, merge_into stays None),
  - --merge into an inert ("version: 1") policy == a fresh generate,
  - plain `init` (no --merge) is unchanged: never reads/merges the live policy.

Style mirrors tests/unit/test_cli_policy.py: CliRunner + monkeypatch on the
FWD_* env vars, with get_settings.cache_clear() bracketing because Settings is
lru_cached. The shell `install/onboard` wrapper is out of scope (not unit-tested).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from typer.testing import CliRunner

from fwd.cli.main import app

if TYPE_CHECKING:
    import pytest

runner = CliRunner()

_ROOT = Path(__file__).resolve().parents[2]
ABIS_DIR = _ROOT / "config" / "abis"
NETWORKS_FILE = _ROOT / "config" / "networks.yaml"
RECIPIENT = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"

# What the installer drops as the inert default-deny policy.
INERT = "# fwd INERT default-deny policy (installed). Empty on purpose.\nversion: 1\n"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _env(monkeypatch: pytest.MonkeyPatch, policy_path: Path | None) -> None:
    """Point the CLI's settings at the real ABIs + networks file and (optionally)
    a tmp policy path, then clear the lru_cache so the new env is read."""
    from fwd.settings import get_settings

    monkeypatch.setenv("FWD_ABIS_DIR", str(ABIS_DIR))
    monkeypatch.setenv("FWD_NETWORKS_FILE", str(NETWORKS_FILE))
    if policy_path is not None:
        monkeypatch.setenv("FWD_POLICY_PATH", str(policy_path))
    get_settings.cache_clear()


def _clear() -> None:
    from fwd.settings import get_settings

    get_settings.cache_clear()


def _init(args: list[str]) -> object:
    """Run `clifwd policy init <args>` and return the CliRunner result."""
    return runner.invoke(app, ["policy", "init", *args])


def _doc(result: object) -> dict:
    """Parse the YAML the CLI printed to stdout (strips the header comments)."""
    return yaml.safe_load(result.output)  # type: ignore[attr-defined]


# Conventional default arg sets (claim+fsp; recipient required for claim).
_SONGBIRD = [
    "--networks",
    "songbird",
    "--capabilities",
    "claim,fsp",
    "--recipient",
    RECIPIENT,
]
_FLARE = [
    "--networks",
    "flare",
    "--capabilities",
    "claim,fsp",
    "--recipient",
    RECIPIENT,
]


def _generate_to(monkeypatch: pytest.MonkeyPatch, path: Path, args: list[str]) -> dict:
    """Fresh-generate a policy to `path` (no merge), return its parsed doc.

    Uses --out so the file on disk becomes the live FWD_POLICY_PATH a later
    --merge run will read.
    """
    _env(monkeypatch, path)
    try:
        result = _init([*args, "--out", str(path)])
        assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
    finally:
        _clear()
    return yaml.safe_load(path.read_text())


# ---------------------------------------------------------------------------
# --merge into an inert policy == fresh generate
# ---------------------------------------------------------------------------


def test_merge_into_inert_equals_fresh(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """First onboard: --merge into the installed inert policy == a plain init."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(INERT)

    _env(monkeypatch, policy)
    try:
        merged = _init([*_SONGBIRD, "--merge"])
        assert merged.exit_code == 0, merged.output  # type: ignore[attr-defined]
        merged_doc = _doc(merged)
    finally:
        _clear()

    # A plain init (no --merge) of the same network. FWD_POLICY_PATH is irrelevant
    # here since plain init never reads it, but keep the env consistent.
    _env(monkeypatch, policy)
    try:
        fresh = _init(_SONGBIRD)
        assert fresh.exit_code == 0, fresh.output  # type: ignore[attr-defined]
        fresh_doc = _doc(fresh)
    finally:
        _clear()

    assert merged_doc == fresh_doc


def test_merge_into_bare_version_one_equals_fresh(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A minimal `version: 1` (no comment header) merge target == fresh generate."""
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n")

    _env(monkeypatch, policy)
    try:
        merged = _init([*_FLARE, "--merge"])
        assert merged.exit_code == 0, merged.output  # type: ignore[attr-defined]
        merged_doc = _doc(merged)
    finally:
        _clear()

    _env(monkeypatch, policy)
    try:
        fresh = _doc(_init(_FLARE))
    finally:
        _clear()

    assert merged_doc == fresh


# ---------------------------------------------------------------------------
# missing policy file → fresh generate (no crash)
# ---------------------------------------------------------------------------


def test_merge_missing_policy_file_falls_back_to_fresh(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """--merge when FWD_POLICY_PATH does not exist: cur.exists() is False, so
    merge_into stays None → behaves exactly like a fresh generate, exit 0."""
    missing = tmp_path / "does-not-exist.yaml"
    assert not missing.exists()

    _env(monkeypatch, missing)
    try:
        merged = _init([*_SONGBIRD, "--merge"])
        assert merged.exit_code == 0, merged.output  # type: ignore[attr-defined]
        merged_doc = _doc(merged)
    finally:
        _clear()

    _env(monkeypatch, missing)
    try:
        fresh_doc = _doc(_init(_SONGBIRD))
    finally:
        _clear()

    assert merged_doc == fresh_doc
    # the missing-file path must NOT have been created as a side effect (init
    # only writes when --out is given)
    assert not missing.exists()


def test_merge_missing_policy_does_not_write_anything(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Sanity: --merge with a missing policy and no --out prints to stdout and
    leaves the filesystem untouched (read-only contract of `init`)."""
    missing = tmp_path / "policy.yaml"
    _env(monkeypatch, missing)
    try:
        result = _init([*_FLARE, "--merge"])
        assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
        assert "wallets:" in result.output  # type: ignore[attr-defined]
    finally:
        _clear()
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# the core invariant: --merge ADDS a network, never drops the existing one
# ---------------------------------------------------------------------------


def test_merge_adds_network_preserves_existing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Onboard songbird (write it to FWD_POLICY_PATH), then ADD flare via
    --merge: both networks present; every songbird rule byte-identical."""
    policy = tmp_path / "policy.yaml"
    sb_doc = _generate_to(monkeypatch, policy, _SONGBIRD)

    _env(monkeypatch, policy)
    try:
        result = _init([*_FLARE, "--merge"])
        assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
        doc = _doc(result)
    finally:
        _clear()

    # both networks present across the dict sections
    assert {
        "claimer-songbird",
        "claimer-flare",
        "fsp-signing-songbird",
        "fsp-signing-flare",
        "fsp-sender-songbird",
        "fsp-sender-flare",
    } <= set(doc["wallets"])
    assert {
        "claim-songbird",
        "claim-flare",
        "fsp-sign-songbird",
        "fsp-sign-flare",
        "fsp-submit-songbird",
        "fsp-submit-flare",
    } <= set(doc["callers"])
    assert {"fsp/songbird", "fsp/flare"} <= set(doc["fsp_permissions"])
    assert sorted(doc["fsp_self_submit"]) == ["fsp-signing-flare", "fsp-signing-songbird"]

    # SUPERSET: every songbird key/value the original had survives unchanged.
    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        for key, val in sb_doc[section].items():
            assert key in doc[section], f"songbird {section}/{key} dropped by merge"
            assert doc[section][key] == val, f"songbird {section}/{key} altered by merge"


def test_merge_three_way_chain_preserves_all(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """songbird → +flare → +coston2, each via --merge against the prior file.
    After the third add, all three networks coexist and nothing was dropped."""
    policy = tmp_path / "policy.yaml"
    sb_doc = _generate_to(monkeypatch, policy, _SONGBIRD)

    # add flare, write back to the same path
    _env(monkeypatch, policy)
    try:
        r2 = _init([*_FLARE, "--merge", "--out", str(policy)])
        assert r2.exit_code == 0, r2.output  # type: ignore[attr-defined]
    finally:
        _clear()
    after_flare = yaml.safe_load(policy.read_text())

    # add coston2 (claim needs a recipient; coston2 supports both caps)
    coston2 = [
        "--networks",
        "coston2",
        "--capabilities",
        "claim,fsp",
        "--recipient",
        RECIPIENT,
    ]
    _env(monkeypatch, policy)
    try:
        r3 = _init([*coston2, "--merge"])
        assert r3.exit_code == 0, r3.output  # type: ignore[attr-defined]
        doc = _doc(r3)
    finally:
        _clear()

    assert {"claimer-songbird", "claimer-flare", "claimer-coston2"} <= set(doc["wallets"])
    assert {"fsp/songbird", "fsp/flare", "fsp/coston2"} <= set(doc["fsp_permissions"])

    # songbird survived BOTH subsequent adds, byte-identical to the first gen.
    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        for key, val in sb_doc[section].items():
            assert doc[section][key] == val, f"songbird {section}/{key} changed across two merges"
        # flare (added at step 2) also survived the coston2 add.
        for key, val in after_flare[section].items():
            assert doc[section][key] == val, f"step-2 {section}/{key} changed by coston2 merge"


def test_merge_idempotent_same_network(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Re-running the SAME network with --merge yields an identical policy
    (its own keys overwrite with identical values; no growth/dups)."""
    policy = tmp_path / "policy.yaml"
    first = _generate_to(monkeypatch, policy, _SONGBIRD)

    _env(monkeypatch, policy)
    try:
        result = _init([*_SONGBIRD, "--merge"])
        assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
        again = _doc(result)
    finally:
        _clear()

    assert again == first


def test_merge_preserves_operator_renamed_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Adversarial: the operator hand-added a NON-suffixed caller/wallet the
    generator never emits. Adding a network must not touch it (superset)."""
    base = {
        "version": 1,
        "callers": {"my-custom-caller": {"policy_path": "perm/custom"}},
        "wallets": {"treasury-watch": {"policy_path": "wc/treasury"}},
        "permissions": {
            "perm/custom": {
                "contracts": {
                    "0x1234567890abcdef1234567890abcdef12345678": {
                        "abi": "erc20",
                        "chains": [114],
                        "methods": {"transfer(address,uint256)": {"max_value_wei": "0"}},
                    }
                },
                "wallet_allowlist": ["treasury-watch"],
            }
        },
        "wallet_constraints": {"wc/treasury": {}},
    }
    policy = tmp_path / "policy.yaml"
    policy.write_text(yaml.safe_dump(base, sort_keys=False))

    _env(monkeypatch, policy)
    try:
        result = _init([*_FLARE, "--merge"])
        assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
        doc = _doc(result)
    finally:
        _clear()

    # the operator's custom entries survive untouched alongside the new flare keys
    assert doc["callers"]["my-custom-caller"] == {"policy_path": "perm/custom"}
    assert doc["wallets"]["treasury-watch"] == {"policy_path": "wc/treasury"}
    assert doc["permissions"]["perm/custom"] == base["permissions"]["perm/custom"]
    assert doc["wallet_constraints"]["wc/treasury"] == {}
    assert "claimer-flare" in doc["wallets"]


def test_merge_preserves_preexisting_fsp_self_submit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A pre-existing fsp_self_submit entry (e.g. an operator-renamed signer)
    is preserved and the new network's entry is appended, not replaced."""
    base = {
        "version": 1,
        "callers": {},
        "wallets": {},
        "permissions": {},
        "wallet_constraints": {},
        "fsp_self_submit": ["operator-renamed-signer"],
    }
    policy = tmp_path / "policy.yaml"
    policy.write_text(yaml.safe_dump(base, sort_keys=False))

    _env(monkeypatch, policy)
    try:
        result = _init([*_FLARE, "--merge"])
        assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
        doc = _doc(result)
    finally:
        _clear()

    ss = doc["fsp_self_submit"]
    assert "operator-renamed-signer" in ss, "pre-existing self-submit entry dropped"
    assert "fsp-signing-flare" in ss
    # order-preserving union: the pre-existing entry stays first.
    assert ss[0] == "operator-renamed-signer"


# ---------------------------------------------------------------------------
# plain `init` (no --merge) NEVER reads/merges the live policy
# ---------------------------------------------------------------------------


def test_plain_init_ignores_live_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A populated FWD_POLICY_PATH must NOT bleed into a plain (no --merge) init.

    Write a songbird policy to the live path, then plain-init flare: the output
    must contain ONLY flare keys — no songbird leakage."""
    policy = tmp_path / "policy.yaml"
    _generate_to(monkeypatch, policy, _SONGBIRD)  # live path now holds songbird

    _env(monkeypatch, policy)
    try:
        result = _init(_FLARE)  # NO --merge
        assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
        doc = _doc(result)
    finally:
        _clear()

    assert "claimer-flare" in doc["wallets"]
    # zero songbird leakage anywhere
    assert not any("songbird" in k for k in doc["wallets"])
    assert not any("songbird" in k for k in doc["callers"])
    assert not any("songbird" in k for k in doc["permissions"])
    assert not any("songbird" in k for k in doc.get("fsp_permissions", {}))


def test_plain_init_does_not_read_a_corrupt_live_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Adversarial: even if the live policy is garbage YAML, a PLAIN init must
    succeed (it never reads it). Only --merge would surface a corrupt target."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(": : not : valid : yaml : at all\n\t- broken")

    _env(monkeypatch, policy)
    try:
        result = _init(_FLARE)  # no --merge → never opens the file
        assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
    finally:
        _clear()


# ---------------------------------------------------------------------------
# --merge surfaces an invalid merge target as a clean CLI error (exit 2)
# ---------------------------------------------------------------------------


def test_merge_non_mapping_target_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """--merge into a YAML LIST (not a mapping) → PolicyInitError → exit 2, with
    a readable message; the CLI does not crash with a traceback."""
    policy = tmp_path / "policy.yaml"
    policy.write_text("- just\n- a\n- list\n")

    _env(monkeypatch, policy)
    try:
        result = _init([*_FLARE, "--merge"])
        assert result.exit_code == 2, result.output  # type: ignore[attr-defined]
        assert "policy init failed" in result.output  # type: ignore[attr-defined]
        assert "not a policy mapping" in result.output  # type: ignore[attr-defined]
    finally:
        _clear()


def test_merge_invalid_yaml_target_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """--merge into a non-parseable YAML file → exit 2 (merge-target-not-valid-YAML),
    not an unhandled traceback."""
    policy = tmp_path / "policy.yaml"
    # A genuine YAML parse error (unclosed flow mapping).
    policy.write_text("version: {1\n")

    _env(monkeypatch, policy)
    try:
        result = _init([*_FLARE, "--merge"])
        assert result.exit_code == 2, result.output  # type: ignore[attr-defined]
        assert "policy init failed" in result.output  # type: ignore[attr-defined]
    finally:
        _clear()


def test_merge_bad_input_still_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """--merge does not mask ordinary bad input: an unknown network still exits 2
    (the merge target is fine; generate_policy rejects the network first)."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(INERT)

    _env(monkeypatch, policy)
    try:
        result = _init(
            [
                "--networks",
                "ethereum",
                "--capabilities",
                "claim",
                "--recipient",
                RECIPIENT,
                "--merge",
            ]
        )
        assert result.exit_code == 2, result.output  # type: ignore[attr-defined]
        assert "unknown network" in result.output  # type: ignore[attr-defined]
    finally:
        _clear()


# ---------------------------------------------------------------------------
# --merge with --out writes the merged superset to disk
# ---------------------------------------------------------------------------


def test_merge_with_out_writes_superset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """--merge --out writes the merged (songbird+flare) policy to the --out path;
    reading it back shows both networks. (install/onboard uses this shape.)"""
    policy = tmp_path / "policy.yaml"
    sb_doc = _generate_to(monkeypatch, policy, _SONGBIRD)
    out = tmp_path / "merged.yaml"

    _env(monkeypatch, policy)
    try:
        result = _init([*_FLARE, "--merge", "--out", str(out)])
        assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
        assert "wrote" in result.output  # type: ignore[attr-defined]
    finally:
        _clear()

    doc = yaml.safe_load(out.read_text())
    assert "claimer-songbird" in doc["wallets"]
    assert "claimer-flare" in doc["wallets"]
    for section in ("callers", "wallets", "permissions", "wallet_constraints", "fsp_permissions"):
        for key, val in sb_doc[section].items():
            assert (
                doc[section][key] == val
            ), f"songbird {section}/{key} changed when written via --out"
