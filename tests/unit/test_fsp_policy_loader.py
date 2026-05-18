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
