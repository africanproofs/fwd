"""Tests for AbiRegistry.signatures_for — added in v0.5.0a6."""

from __future__ import annotations

from pathlib import Path

from fwd.infra.abi_registry import AbiRegistry

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"


def _registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


def test_signatures_for_erc20_contains_transfer() -> None:
    """signatures_for('erc20') must include the canonical transfer signature."""
    reg = _registry()
    sigs = reg.signatures_for("erc20")
    assert "transfer(address,uint256)" in sigs


def test_signatures_for_unknown_abi_returns_empty_frozenset() -> None:
    """Unknown ABI name → empty frozenset (no KeyError)."""
    reg = _registry()
    assert reg.signatures_for("no-such-abi") == frozenset()


def test_signatures_for_returns_frozenset_of_strings_containing_parens() -> None:
    """Every element is a str containing '(' (canonical signature shape)."""
    reg = _registry()
    sigs = reg.signatures_for("erc20")
    assert len(sigs) > 0
    for sig in sigs:
        assert isinstance(sig, str)
        assert "(" in sig


def test_signatures_for_cross_checks_with_lookup() -> None:
    """Every signature from signatures_for can be resolved via lookup via registry internals."""
    reg = _registry()
    for abi_name in reg.abi_names():
        for sig in reg.signatures_for(abi_name):
            # Find the actual entry via the registry internals (_data keyed by selector_hex).
            submap = reg._data[abi_name]
            matching = [m for m in submap.values() if m.method_signature == sig]
            assert len(matching) == 1, f"signature {sig!r} not uniquely lookupable in {abi_name!r}"
