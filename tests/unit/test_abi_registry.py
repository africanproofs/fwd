"""Unit tests for fwd.infra.abi_registry (ABI registry loader).

Per decisions.md D15. All tests are synchronous (plain def).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fwd.domain.intent import canonical_signature, selector_of
from fwd.infra.abi_registry import AbiMethod, AbiRegistry, AbiRegistryError

# ---------------------------------------------------------------------------
# Path to real ABI files
# ---------------------------------------------------------------------------
_ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_registry_yaml(abis: dict[str, str]) -> str:
    lines = ["version: 1", "abis:"]
    for name, filename in abis.items():
        lines.append(f"  {name}: {filename}")
    return "\n".join(lines) + "\n"


def _minimal_fn_entry(name: str, inputs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "type": "function",
        "name": name,
        "stateMutability": "nonpayable",
        "inputs": inputs or [],
        "outputs": [],
    }


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


def test_load_real_abis_succeeds_with_correct_names() -> None:
    """Test 1: AbiRegistry.load succeeds; abi_names matches the registry."""
    registry = AbiRegistry.load(_ABIS_DIR)
    assert registry.abi_names() == frozenset(
        {
            "reward_manager",
            "participant_register",
            "erc20",
            "flare_systems_manager",
            "submission",
            "fast_updater",
            "relay",
        }
    )


def test_lookup_erc20_transfer_returns_correct_method() -> None:
    """Test 2: lookup erc20 transfer selector returns correct AbiMethod."""
    registry = AbiRegistry.load(_ABIS_DIR)
    # Known transfer selector
    sel = "0xa9059cbb"
    method = registry.lookup("erc20", sel)
    assert method is not None
    assert isinstance(method, AbiMethod)
    assert method.method_signature == "transfer(address,uint256)"
    assert method.canonical_input_types == ("address", "uint256")


def test_lookup_reward_manager_claim_canonical_types() -> None:
    """Test 3: lookup reward_manager claim — canonical_input_types includes full tuple expansion."""
    registry = AbiRegistry.load(_ABIS_DIR)
    # Find the claim selector via domain helper
    rm_json = json.loads((_ABIS_DIR / "reward_manager.json").read_text())
    claim_entry = next(e for e in rm_json if e.get("name") == "claim")
    sel = selector_of(claim_entry)
    method = registry.lookup("reward_manager", sel)
    assert method is not None
    # The last canonical input type must be the full nested tuple expansion
    assert method.canonical_input_types[-1] == "(bytes32[],(uint24,bytes20,uint120,uint8))[]"
    # Signature includes the full expansion
    assert "bytes32[]" in method.method_signature
    assert method.method_signature == canonical_signature(claim_entry)


def test_lookup_participant_register_register_types() -> None:
    """Test 4: lookup participant_register register → (uint8, string)."""
    registry = AbiRegistry.load(_ABIS_DIR)
    pr_json = json.loads((_ABIS_DIR / "participant_register.json").read_text())
    reg_entry = next(e for e in pr_json if e.get("name") == "register")
    sel = selector_of(reg_entry)
    method = registry.lookup("participant_register", sel)
    assert method is not None
    assert method.canonical_input_types == ("uint8", "string")


def test_lookup_view_method_returns_none() -> None:
    """Test 5: view methods are not indexed — lookup returns None."""
    registry = AbiRegistry.load(_ABIS_DIR)
    # activeCount() is a view method in participant_register
    pr_json = json.loads((_ABIS_DIR / "participant_register.json").read_text())
    active_count_entry = next(e for e in pr_json if e.get("name") == "activeCount")
    assert active_count_entry.get("stateMutability") == "view"
    sel = selector_of(active_count_entry)
    result = registry.lookup("participant_register", sel)
    assert result is None


def test_lookup_unknown_abi_name_returns_none() -> None:
    """Test 6: lookup for an unknown abi_name returns None, does not raise."""
    registry = AbiRegistry.load(_ABIS_DIR)
    result = registry.lookup("nonexistent_abi", "0xa9059cbb")
    assert result is None


def test_lookup_known_abi_bogus_selector_returns_none() -> None:
    """Test 7: lookup with known abi but unknown selector returns None."""
    registry = AbiRegistry.load(_ABIS_DIR)
    result = registry.lookup("erc20", "0xdeadbeef")
    assert result is None


def test_load_hardhat_wrapped_abi(tmp_path: Path) -> None:
    """Test 8: Hardhat-wrapped ABI (dict with 'abi' key) loads and indexes correctly."""
    fn = _minimal_fn_entry("doThing", [{"name": "x", "type": "uint256"}])
    artifact = {"abi": [fn], "bytecode": "0x", "_format": "hh-sol-artifact-1"}
    (tmp_path / "my_contract.json").write_text(json.dumps(artifact))
    (tmp_path / "registry.yaml").write_text(
        _minimal_registry_yaml({"my_contract": "my_contract.json"})
    )

    registry = AbiRegistry.load(tmp_path)
    assert "my_contract" in registry.abi_names()
    sel = selector_of(fn)
    method = registry.lookup("my_contract", sel)
    assert method is not None
    assert method.method_signature == "doThing(uint256)"


def test_load_bare_array_abi(tmp_path: Path) -> None:
    """Test 9: bare JSON array ABI loads and indexes correctly."""
    fn = _minimal_fn_entry("simpleFn", [{"name": "a", "type": "bool"}])
    (tmp_path / "simple.json").write_text(json.dumps([fn]))
    (tmp_path / "registry.yaml").write_text(_minimal_registry_yaml({"simple": "simple.json"}))

    registry = AbiRegistry.load(tmp_path)
    assert "simple" in registry.abi_names()
    sel = selector_of(fn)
    method = registry.lookup("simple", sel)
    assert method is not None
    assert method.canonical_input_types == ("bool",)


def test_load_duplicate_selector_raises_error(tmp_path: Path) -> None:
    """Test 10: two entries with identical selectors in one ABI → AbiRegistryError."""
    # Two entries with the same name+inputs produce the same selector
    fn1 = _minimal_fn_entry("doThing", [{"name": "x", "type": "uint256"}])
    fn2 = _minimal_fn_entry("doThing", [{"name": "y", "type": "uint256"}])
    (tmp_path / "dup.json").write_text(json.dumps([fn1, fn2]))
    (tmp_path / "registry.yaml").write_text(_minimal_registry_yaml({"dup": "dup.json"}))

    with pytest.raises(AbiRegistryError) as exc_info:
        AbiRegistry.load(tmp_path)
    msg = str(exc_info.value)
    assert "dup" in msg
    assert selector_of(fn1) in msg


def test_load_malformed_json_raises_error(tmp_path: Path) -> None:
    """Test 11: malformed JSON file → AbiRegistryError."""
    (tmp_path / "bad.json").write_text("this is not json }{")
    (tmp_path / "registry.yaml").write_text(_minimal_registry_yaml({"bad": "bad.json"}))

    with pytest.raises(AbiRegistryError):
        AbiRegistry.load(tmp_path)


def test_load_missing_abi_file_raises_error(tmp_path: Path) -> None:
    """Test 12: registry.yaml references a file that does not exist → AbiRegistryError."""
    (tmp_path / "registry.yaml").write_text(_minimal_registry_yaml({"ghost": "ghost.json"}))

    with pytest.raises(AbiRegistryError) as exc_info:
        AbiRegistry.load(tmp_path)
    assert "ghost" in str(exc_info.value).lower() or "ghost.json" in str(exc_info.value)


def test_load_wrong_version_raises_error(tmp_path: Path) -> None:
    """Test 13: registry.yaml with version: 2 → AbiRegistryError."""
    (tmp_path / "registry.yaml").write_text("version: 2\nabis: {}\n")

    with pytest.raises(AbiRegistryError) as exc_info:
        AbiRegistry.load(tmp_path)
    assert "version" in str(exc_info.value).lower() or "2" in str(exc_info.value)


def test_load_missing_abis_key_raises_error(tmp_path: Path) -> None:
    """Test 14: registry.yaml missing 'abis' key → AbiRegistryError."""
    (tmp_path / "registry.yaml").write_text("version: 1\n")

    with pytest.raises(AbiRegistryError) as exc_info:
        AbiRegistry.load(tmp_path)
    assert "abis" in str(exc_info.value).lower()


def test_load_path_traversal_raises_error(tmp_path: Path) -> None:
    """Test 15: abis entry with '../escape.json' → AbiRegistryError (path-traversal defense)."""
    (tmp_path / "registry.yaml").write_text(_minimal_registry_yaml({"x": "../escape.json"}))

    with pytest.raises(AbiRegistryError) as exc_info:
        AbiRegistry.load(tmp_path)
    assert "traversal" in str(exc_info.value).lower() or ".." in str(exc_info.value)


def test_registry_selector_and_signature_match_domain_helpers() -> None:
    """Test 16: single-source regression — registry reuses domain helpers.

    For erc20 transfer, the stored selector and method_signature must equal
    fwd.domain.intent.selector_of() and canonical_signature() called directly
    on the same entry. This proves infra reuses the domain helpers (no
    duplicated computation) and exercises the infra→domain import path.
    """
    erc20_json = json.loads((_ABIS_DIR / "erc20.json").read_text())
    transfer_entry = next(e for e in erc20_json if e.get("name") == "transfer")

    # Compute via domain helpers directly
    expected_sel = selector_of(transfer_entry)
    expected_sig = canonical_signature(transfer_entry)

    # Load via registry
    registry = AbiRegistry.load(_ABIS_DIR)
    method = registry.lookup("erc20", expected_sel)
    assert method is not None
    assert method.method_signature == expected_sig
    # The stored abi_fn_entry is the same entry (we can verify by recomputing)
    assert selector_of(method.abi_fn_entry) == expected_sel
