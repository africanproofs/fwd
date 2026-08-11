"""Tests for infra/policy_loader.py check_consistency's native_transfers checks.

Mirrors the style of test_policy_loader.py: covers (a) the wallet-resolution
check (mirrors Check 4) and (b) Check 1c accepting a native_transfers-only
caller binding.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.caller_repo import Caller
from fwd.infra.policy_loader import check_consistency
from fwd.infra.wallet_repo import Wallet

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

CHAIN = 14
RECIPIENT = "0x" + "11" * 20
MAX_VALUE_WEI = "400000000000000000000"


def _make_caller(name: str, policy_path: str) -> Caller:
    return Caller(
        name=name,
        api_key_hash="h",
        api_key_prefix="p",
        policy_path=policy_path,
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _make_wallet(name: str) -> Wallet:
    return Wallet(
        name=name,
        address="0x" + "bb" * 20,
        privkey_ciphertext="seal:v1:x",
        vault_master_key="fwd-master",
        policy_path="wc/main",
        created_at=datetime.now(UTC),
    )


def _nt_policy_raw(*, wallet_allowlist: list[str]) -> dict[str, object]:
    return {
        "version": 1,
        "callers": {
            "funding-flare": {"policy_path": "perm/funding-flare"},
        },
        "native_transfers": {
            "perm/funding-flare": {
                "chains": [CHAIN],
                "recipient_allowlist": [RECIPIENT],
                "max_value_wei": MAX_VALUE_WEI,
                "wallet_allowlist": wallet_allowlist,
                "rate": {"per_hour": 6, "per_day": 20},
            }
        },
    }


def test_native_transfers_unknown_wallet_is_error() -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    policy = Policy.model_validate(_nt_policy_raw(wallet_allowlist=["ghost-wallet"]))
    callers = [_make_caller("funding-flare", "perm/funding-flare")]
    errors = check_consistency(policy, callers, [], registry)
    assert any(
        "native_transfers" in e and "ghost-wallet" in e and "unknown wallet" in e for e in errors
    ), errors


def test_native_transfers_known_wallet_passes() -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    policy = Policy.model_validate(_nt_policy_raw(wallet_allowlist=["funding-flare"]))
    callers = [_make_caller("funding-flare", "perm/funding-flare")]
    wallets = [_make_wallet("funding-flare")]
    errors = check_consistency(policy, callers, wallets, registry)
    assert errors == [], f"Expected no errors, got: {errors}"


def test_caller_bound_to_native_transfers_only_passes_check1c() -> None:
    """A caller binding present in neither permissions nor fsp_permissions,
    but present in native_transfers, must pass Check 1c (Change 3.1)."""
    registry = AbiRegistry.load(ABIS_DIR)
    policy = Policy.model_validate(_nt_policy_raw(wallet_allowlist=["funding-flare"]))
    assert policy.permissions == {}
    assert policy.fsp_permissions == {}
    assert "perm/funding-flare" in policy.native_transfers
    callers = [_make_caller("funding-flare", "perm/funding-flare")]
    wallets = [_make_wallet("funding-flare")]
    errors = check_consistency(policy, callers, wallets, registry)
    assert errors == [], f"Expected no errors, got: {errors}"
