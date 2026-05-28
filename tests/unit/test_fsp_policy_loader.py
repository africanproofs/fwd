"""Tests for FSP-specific check_consistency + policy_path_exists behaviour.

Exercises the new G1/G2 additions to policy_loader:
  - FSP-only caller passes Check 1c (no boot-death).
  - policy_path_exists accepts fsp paths for kind="caller".
  - Address-level cross-domain segmentation violation is detected.
  - policy_path in BOTH permissions + fsp_permissions is rejected.
  - Unknown message_type in fsp_permissions is rejected.
  - Unknown wallet in fsp_permissions allowlist is rejected.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.caller_repo import Caller
from fwd.infra.policy_loader import check_consistency, policy_path_exists
from fwd.infra.wallet_repo import Wallet

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_caller(name: str, policy_path: str) -> Caller:
    return Caller(
        name=name,
        api_key_hash="h",
        api_key_prefix="p",
        policy_path=policy_path,
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _make_wallet(name: str, address: str = "0x" + "ab" * 20) -> Wallet:
    return Wallet(
        name=name,
        address=address,
        privkey_ciphertext="vault:v1:x",
        vault_master_key="fwd-master",
        policy_path="wc/default",
        created_at=datetime.now(UTC),
    )


@pytest.fixture(scope="module")
def registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


# ---------------------------------------------------------------------------
# FSP-only caller passes check_consistency (no boot-death)
# ---------------------------------------------------------------------------


def test_fsp_only_caller_passes_consistency(registry: AbiRegistry) -> None:
    """An FSP-only caller (bound to fsp_permissions, not permissions) is valid."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {
                "fsp-caller": {"policy_path": "fsp/main"},
            },
            "permissions": {},
            "fsp_permissions": {
                "fsp/main": {
                    "message_types": ["UPTIME"],
                    "wallet_allowlist": ["fsp-wallet"],
                }
            },
            "wallet_constraints": {},
        }
    )
    wallet = _make_wallet("fsp-wallet")
    caller = _make_caller("fsp-caller", "fsp/main")

    errors = check_consistency(policy, [caller], [wallet], registry)
    assert errors == [], f"Expected no errors but got: {errors}"


# ---------------------------------------------------------------------------
# policy_path_exists accepts FSP paths for kind="caller"
# ---------------------------------------------------------------------------


def test_policy_path_exists_fsp_path_accepted() -> None:
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {},
            "fsp_permissions": {
                "fsp/main": {
                    "message_types": ["UPTIME"],
                    "wallet_allowlist": [],
                }
            },
            "wallet_constraints": {},
        }
    )
    assert policy_path_exists(policy, "fsp/main", "caller") is True


def test_policy_path_exists_fsp_path_miss() -> None:
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {},
            "fsp_permissions": {
                "fsp/main": {
                    "message_types": ["UPTIME"],
                    "wallet_allowlist": [],
                }
            },
            "wallet_constraints": {},
        }
    )
    assert policy_path_exists(policy, "fsp/other", "caller") is False


# ---------------------------------------------------------------------------
# Address-level cross-domain segmentation violation
# ---------------------------------------------------------------------------


def test_cross_domain_address_segmentation_violation(registry: AbiRegistry) -> None:
    """Two DB wallets with the SAME address, one in EVM permissions and one in
    fsp_permissions -> check_consistency returns a segmentation error."""
    shared_address = "0x" + "cc" * 20  # same address on both wallets

    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/evm": {
                    "contracts": {},
                    "wallet_allowlist": ["evm-wallet"],
                }
            },
            "fsp_permissions": {
                "fsp/main": {
                    "message_types": ["UPTIME"],
                    "wallet_allowlist": ["fsp-wallet"],
                }
            },
            "wallet_constraints": {},
        }
    )
    evm_wallet = _make_wallet("evm-wallet", address=shared_address)
    fsp_wallet = _make_wallet("fsp-wallet", address=shared_address)

    errors = check_consistency(policy, [], [evm_wallet, fsp_wallet], registry)
    assert any("segmentation violation" in e for e in errors), (
        f"Expected segmentation violation error but got: {errors}"
    )


# ---------------------------------------------------------------------------
# policy_path in BOTH permissions + fsp_permissions
# ---------------------------------------------------------------------------


def test_policy_path_in_both_permissions_and_fsp_permissions(registry: AbiRegistry) -> None:
    """A policy_path present in both permissions and fsp_permissions is an error."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "shared/path": {
                    "contracts": {},
                    "wallet_allowlist": [],
                }
            },
            "fsp_permissions": {
                "shared/path": {
                    "message_types": ["UPTIME"],
                    "wallet_allowlist": [],
                }
            },
            "wallet_constraints": {},
        }
    )

    errors = check_consistency(policy, [], [], registry)
    assert any("BOTH permissions" in e for e in errors), (
        f"Expected 'BOTH permissions' error but got: {errors}"
    )


# ---------------------------------------------------------------------------
# Unknown message_type in fsp_permissions
# ---------------------------------------------------------------------------


def test_unknown_message_type_in_fsp_permissions(registry: AbiRegistry) -> None:
    """An unrecognised message_type in fsp_permissions is an error."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {},
            "fsp_permissions": {
                "fsp/main": {
                    "message_types": ["UPTIME", "BOGUS_TYPE"],
                    "wallet_allowlist": [],
                }
            },
            "wallet_constraints": {},
        }
    )

    errors = check_consistency(policy, [], [], registry)
    assert any("BOGUS_TYPE" in e for e in errors), (
        f"Expected BOGUS_TYPE error but got: {errors}"
    )


# ---------------------------------------------------------------------------
# Unknown wallet in fsp_permissions allowlist
# ---------------------------------------------------------------------------


def test_unknown_wallet_in_fsp_permissions_allowlist(registry: AbiRegistry) -> None:
    """A wallet name in fsp_permissions that doesn't exist in DB or policy.wallets is an error."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {},
            "fsp_permissions": {
                "fsp/main": {
                    "message_types": ["UPTIME"],
                    "wallet_allowlist": ["ghost-wallet"],
                }
            },
            "wallet_constraints": {},
        }
    )

    errors = check_consistency(policy, [], [], registry)
    assert any("ghost-wallet" in e for e in errors), (
        f"Expected ghost-wallet error but got: {errors}"
    )


# ---------------------------------------------------------------------------
# fsp_self_submit carve-out tests (v1.1.0a6)
# ---------------------------------------------------------------------------

# Shared address for carve-out tests — same address used for the FSP wallet
# and the EVM wallet to exercise the address-level overlap.
_SHARED_ADDR = "0x" + "dd" * 20


def _carve_out_policy(
    *,
    extra_method: str | None = None,
    non_fsm_abi: bool = False,
    nonzero_value: bool = False,
    fsp_allowlisted: bool = True,
    evm_allowlisted: bool = True,
    fsp_self_submit: list[str] | None = None,
) -> dict[str, object]:
    """Build a policy dict for carve-out tests.

    W is in BOTH fsp/main and perm/self-submit, with fsp_self_submit=[W]
    unless overridden. Flags allow injecting specific violation scenarios.
    """
    methods: dict[str, object] = {
        "signUptimeVote(uint24,bytes32,(uint8,bytes32,bytes32))": {"max_value_wei": "0"},
        "signRewards(uint24,(uint256,uint256)[],bytes32,(uint8,bytes32,bytes32))": {
            "max_value_wei": "0"
        },
    }
    if extra_method is not None:
        methods[extra_method] = {"max_value_wei": "0"}
    if nonzero_value:
        # Overwrite one of the canonical methods with a non-zero max_value_wei
        methods["signUptimeVote(uint24,bytes32,(uint8,bytes32,bytes32))"] = {
            "max_value_wei": "1"
        }

    abi_name = "reward_manager" if non_fsm_abi else "flare_systems_manager"

    return {
        "version": 1,
        "callers": {},
        "permissions": {
            "perm/self-submit": {
                "contracts": {
                    "0x" + "ee" * 20: {
                        "abi": abi_name,
                        "chains": [14],
                        "methods": methods,
                    }
                },
                "wallet_allowlist": ["W"] if evm_allowlisted else [],
            }
        },
        "fsp_permissions": {
            "fsp/main": {
                "message_types": ["UPTIME"],
                "wallet_allowlist": ["W"] if fsp_allowlisted else [],
            }
        },
        "wallet_constraints": {},
        "fsp_self_submit": fsp_self_submit if fsp_self_submit is not None else ["W"],
    }


def test_fsp_self_submit_happy_carve_out(registry: AbiRegistry) -> None:
    """Happy path: W in both domains under the constrained FSM shape + opt-in
    → no segmentation error."""
    policy = Policy.model_validate(_carve_out_policy())
    wallet = _make_wallet("W", address=_SHARED_ADDR)

    errors = check_consistency(policy, [], [wallet], registry)
    seg_errors = [e for e in errors if "segmentation violation" in e]
    assert seg_errors == [], (
        f"Expected no segmentation error for valid carve-out but got: {seg_errors}"
    )


def test_fsp_self_submit_refused_wrong_shape_extra_method(registry: AbiRegistry) -> None:
    """Negative: EVM permissions block has an extra method beyond the two canonical
    FSM self-submit sigs → carve-out refused (fail-fast error present)."""
    policy = Policy.model_validate(
        _carve_out_policy(
            extra_method="transfer(address,uint256)",
        )
    )
    # W needs an address in the DB for address-level segmentation to fire.
    wallet = _make_wallet("W", address=_SHARED_ADDR)

    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, f"Expected 'carve-out refused' error but got: {errors}"


def test_fsp_self_submit_refused_wrong_shape_non_fsm_abi(registry: AbiRegistry) -> None:
    """Negative: EVM permissions block uses a non-FSM abi → carve-out refused."""
    policy = Policy.model_validate(_carve_out_policy(non_fsm_abi=True))
    wallet = _make_wallet("W", address=_SHARED_ADDR)

    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, f"Expected 'carve-out refused' error but got: {errors}"


def test_fsp_self_submit_refused_wrong_shape_nonzero_value(registry: AbiRegistry) -> None:
    """Negative: EVM permissions block has max_value_wei != 0 → carve-out refused."""
    policy = Policy.model_validate(_carve_out_policy(nonzero_value=True))
    wallet = _make_wallet("W", address=_SHARED_ADDR)

    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, f"Expected 'carve-out refused' error but got: {errors}"


def test_fsp_self_submit_not_in_fsp_allowlist(registry: AbiRegistry) -> None:
    """Negative: opt-in wallet W is not in any fsp_permissions allowlist
    → 'meaningless carve-out' error."""
    policy = Policy.model_validate(_carve_out_policy(fsp_allowlisted=False))
    wallet = _make_wallet("W", address=_SHARED_ADDR)

    errors = check_consistency(policy, [], [wallet], registry)
    meaningful = [e for e in errors if "meaningless carve-out" in e]
    assert meaningful, f"Expected 'meaningless carve-out' error but got: {errors}"


def test_fsp_self_submit_not_in_evm_allowlist(registry: AbiRegistry) -> None:
    """Negative: opt-in wallet W is in fsp_permissions but in NO EVM permissions
    allowlist → 'carve-out declared but unused' error."""
    policy = Policy.model_validate(_carve_out_policy(evm_allowlisted=False))
    wallet = _make_wallet("W", address=_SHARED_ADDR)

    errors = check_consistency(policy, [], [wallet], registry)
    unused = [e for e in errors if "carve-out declared but unused" in e]
    assert unused, f"Expected 'carve-out declared but unused' error but got: {errors}"


def test_fsp_self_submit_regression_other_wallet_still_violations(
    registry: AbiRegistry,
) -> None:
    """Regression: fsp_self_submit names a DIFFERENT wallet (X), but the actual
    shared-address wallet (W) is NOT opted in → original segmentation violation
    still fires for W."""
    shared_address = "0x" + "ff" * 20

    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/evm": {
                    "contracts": {},
                    "wallet_allowlist": ["evm-wallet"],
                }
            },
            "fsp_permissions": {
                "fsp/main": {
                    "message_types": ["UPTIME"],
                    "wallet_allowlist": ["fsp-wallet"],
                }
            },
            "wallet_constraints": {},
            # Opt-in names "other-wallet", NOT the actual shared-address wallets
            "fsp_self_submit": ["other-wallet"],
        }
    )
    evm_wallet = _make_wallet("evm-wallet", address=shared_address)
    fsp_wallet = _make_wallet("fsp-wallet", address=shared_address)
    # "other-wallet" is not actually in the DB — triggers "unknown wallet" error too
    errors = check_consistency(policy, [], [evm_wallet, fsp_wallet], registry)
    seg_errors = [e for e in errors if "segmentation violation" in e]
    assert seg_errors, (
        f"Expected segmentation violation for non-opted-in wallet but got: {errors}"
    )
