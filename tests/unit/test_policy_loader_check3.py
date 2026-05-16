"""Tests for policy_loader check 3 — per-signature existence validation.

Added in v0.5.0a6 after AbiRegistry.signatures_for was wired into
check_consistency.
"""

from __future__ import annotations

from pathlib import Path

from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.policy_loader import check_consistency

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

ERC20_CONTRACT = "0x1234567890abcdef1234567890abcdef12345678"


def _registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


def _policy_with_method(method_sig: str) -> Policy:
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "wallets": {},
            "permissions": {
                "perm/test": {
                    "contracts": {
                        ERC20_CONTRACT: {
                            "abi": "erc20",
                            "methods": {
                                method_sig: {"max_value_wei": "0"},
                            },
                        }
                    },
                    "wallet_allowlist": [],
                }
            },
            "wallet_constraints": {},
        }
    )


def test_check3_unknown_method_produces_error() -> None:
    """A method signature not in the ABI → check_consistency returns a check-3 error."""
    registry = _registry()
    policy = _policy_with_method("nonExistentMethod(uint256)")
    errors = check_consistency(policy, [], [], registry)
    # At least one error mentions the bad method and the abi name.
    check3_errors = [e for e in errors if "nonExistentMethod" in e and "erc20" in e]
    assert len(check3_errors) >= 1, f"Expected check-3 error, got: {errors}"


def test_check3_known_method_produces_no_error() -> None:
    """A method signature that EXISTS in the ABI → no check-3 error."""
    registry = _registry()
    policy = _policy_with_method("transfer(address,uint256)")
    errors = check_consistency(policy, [], [], registry)
    # No errors expected (no callers/wallets to orphan).
    assert errors == [], f"Unexpected errors: {errors}"


def test_check3_unknown_abi_does_not_also_emit_check3_error() -> None:
    """An unknown ABI produces only a check-2 error, not also a check-3 error."""
    registry = _registry()
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "wallets": {},
            "permissions": {
                "perm/test": {
                    "contracts": {
                        ERC20_CONTRACT: {
                            "abi": "no-such-abi",  # unknown
                            "methods": {
                                "someMethod(uint256)": {"max_value_wei": "0"},
                            },
                        }
                    },
                    "wallet_allowlist": [],
                }
            },
            "wallet_constraints": {},
        }
    )
    errors = check_consistency(policy, [], [], registry)
    # Must have the check-2 unknown-abi error.
    check2_errors = [e for e in errors if "no-such-abi" in e]
    assert len(check2_errors) >= 1
    # Must NOT have a separate check-3 error for 'someMethod' (would double-report).
    check3_errors = [e for e in errors if "someMethod" in e]
    assert len(check3_errors) == 0, f"Unexpected check-3 error for unknown ABI: {check3_errors}"
