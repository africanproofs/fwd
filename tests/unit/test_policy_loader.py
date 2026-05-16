"""Tests for infra/policy_loader.py.

Covers load_policy (file I/O + schema validation), check_consistency
(cross-reference against DB state and ABI registry), and policy_path_exists.
Uses tmp_path for YAML file creation; uses real AbiRegistry.load(config/abis).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.caller_repo import Caller
from fwd.infra.policy_loader import (
    PolicyLoadError,
    check_consistency,
    load_policy,
    policy_path_exists,
)
from fwd.infra.wallet_repo import Wallet

# Path to real ABI config (present in repo).
ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_caller(
    name: str,
    policy_path: str,
    *,
    revoked: bool = False,
) -> Caller:
    return Caller(
        name=name,
        api_key_hash="hash",
        api_key_prefix="pref",
        policy_path=policy_path,
        created_at=datetime.now(UTC),
        revoked_at=datetime.now(UTC) if revoked else None,
    )


def _make_wallet(name: str, policy_path: str = "wc/default") -> Wallet:
    return Wallet(
        name=name,
        address="0x" + "ab" * 20,
        privkey_ciphertext="vault:v1:x",
        vault_master_key="fwd-master",
        policy_path=policy_path,
        created_at=datetime.now(UTC),
    )


def _write_yaml(tmp_path: Path, content: object, filename: str = "policy.yaml") -> Path:
    p = tmp_path / filename
    p.write_text(yaml.dump(content))
    return p


def _minimal_raw_policy() -> dict[str, object]:
    return {"version": 1}


def _full_consistent_policy_raw() -> dict[str, object]:
    """A policy that passes check_consistency with matching caller/wallet/abi."""
    return {
        "version": 1,
        "callers": {
            "my-caller": {"policy_path": "perm/main"},
        },
        "wallets": {
            "my-wallet": {"policy_path": "wc/main"},
        },
        "permissions": {
            "perm/main": {
                "contracts": {
                    "0xabcdef1234567890abcdef1234567890abcdef12": {
                        "abi": "erc20",
                        "methods": {
                            "transfer(address,uint256)": {
                                "max_value_wei": "1000",
                            }
                        },
                    }
                },
                "wallet_allowlist": ["my-wallet"],
            }
        },
        "wallet_constraints": {
            "wc/main": {},
        },
    }


# ---------------------------------------------------------------------------
# load_policy — happy path
# ---------------------------------------------------------------------------


def test_load_policy_happy_path(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, _minimal_raw_policy())
    policy = load_policy(path)
    assert isinstance(policy, Policy)
    assert policy.version == 1


def test_load_policy_full_policy(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, _full_consistent_policy_raw())
    policy = load_policy(path)
    assert "my-caller" in policy.callers
    assert "perm/main" in policy.permissions


# ---------------------------------------------------------------------------
# load_policy — error cases
# ---------------------------------------------------------------------------


def test_load_policy_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError, match="not found"):
        load_policy(tmp_path / "nonexistent.yaml")


def test_load_policy_malformed_yaml_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("key: [unclosed")
    with pytest.raises(PolicyLoadError, match="YAML parse error"):
        load_policy(path)


def test_load_policy_schema_invalid_raises(tmp_path: Path) -> None:
    # version is a string, not int
    path = _write_yaml(tmp_path, {"version": "one"})
    with pytest.raises(PolicyLoadError, match="schema error"):
        load_policy(path)


def test_load_policy_version_2_raises(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, {"version": 2})
    with pytest.raises(PolicyLoadError):
        load_policy(path)


def test_load_policy_extra_key_raises(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, {"version": 1, "unknown_key": "oops"})
    with pytest.raises(PolicyLoadError, match="schema error"):
        load_policy(path)


# ---------------------------------------------------------------------------
# check_consistency — clean policy → empty list
# ---------------------------------------------------------------------------


def test_check_consistency_clean_returns_empty(tmp_path: Path) -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    policy = load_policy(_write_yaml(tmp_path, _full_consistent_policy_raw()))
    # Realistic shape: caller NAME ("my-caller") differs from its
    # policy_path ("perm/main") — policy.callers is name-keyed (D13).
    callers = [_make_caller("my-caller", "perm/main")]
    wallets = [_make_wallet("my-wallet")]
    errors = check_consistency(policy, callers, wallets, registry)
    assert errors == [], f"Expected no errors, got: {errors}"


# ---------------------------------------------------------------------------
# check_consistency — check 1: active caller issues
# ---------------------------------------------------------------------------


def test_check_consistency_active_caller_policy_path_not_in_policy(tmp_path: Path) -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    policy = load_policy(_write_yaml(tmp_path, _minimal_raw_policy()))
    # Active caller whose policy_path is not a key in policy.callers.
    callers = [_make_caller("alice", "alice")]
    errors = check_consistency(policy, callers, [], registry)
    assert any("alice" in e and "not in policy" in e for e in errors), errors


def test_check_consistency_revoked_caller_with_bad_path_not_an_error(tmp_path: Path) -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    policy = load_policy(_write_yaml(tmp_path, _minimal_raw_policy()))
    # Revoked caller with a policy_path not in policy.callers — should NOT error.
    callers = [_make_caller("alice", "alice", revoked=True)]
    errors = check_consistency(policy, callers, [], registry)
    assert errors == [], f"Revoked caller should not produce errors, got: {errors}"


def test_check_consistency_caller_binding_policy_path_not_in_permissions(tmp_path: Path) -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    raw = {
        "version": 1,
        "callers": {
            # The binding.policy_path "missing-perm" is not in permissions.
            "missing-perm": {"policy_path": "missing-perm"},
        },
        "permissions": {},
        "wallet_constraints": {},
        "wallets": {},
    }
    policy = load_policy(_write_yaml(tmp_path, raw))
    # Active caller whose name = policy_path = "missing-perm" (matches policy.callers key)
    # but binding.policy_path "missing-perm" has no permissions block.
    callers = [_make_caller("missing-perm", "missing-perm")]
    errors = check_consistency(policy, callers, [], registry)
    assert any("missing-perm" in e for e in errors), errors


def test_check_consistency_caller_policy_path_drifts_from_binding(tmp_path: Path) -> None:
    """Active caller declared in policy.callers (by NAME) but whose stored
    policy_path differs from the binding's policy_path → drift error.
    Mirrors policy_engine step 1 (test_step1_caller_policy_path_drift).
    """
    registry = AbiRegistry.load(ABIS_DIR)
    raw = {
        "version": 1,
        "callers": {
            "ftso-claimer": {"policy_path": "perm/main"},
        },
        "permissions": {
            "perm/main": {"contracts": {}, "wallet_allowlist": []},
        },
        "wallet_constraints": {},
        "wallets": {},
    }
    policy = load_policy(_write_yaml(tmp_path, raw))
    # Name matches the policy.callers key; stored policy_path "stale/path"
    # drifts from the binding's "perm/main".
    callers = [_make_caller("ftso-claimer", "stale/path")]
    errors = check_consistency(policy, callers, [], registry)
    assert any("ftso-claimer" in e and "drift" in e for e in errors), errors


# ---------------------------------------------------------------------------
# check_consistency — check 2: unknown abi
# ---------------------------------------------------------------------------


def test_check_consistency_unknown_abi_in_permissions(tmp_path: Path) -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    raw = {
        "version": 1,
        "callers": {},
        "wallets": {},
        "permissions": {
            "perm/bad-abi": {
                "contracts": {
                    "0x1234567890123456789012345678901234567890": {
                        "abi": "no_such_abi",
                        "methods": {},
                    }
                },
                "wallet_allowlist": [],
            }
        },
        "wallet_constraints": {},
    }
    policy = load_policy(_write_yaml(tmp_path, raw))
    errors = check_consistency(policy, [], [], registry)
    assert any("no_such_abi" in e for e in errors), errors


# ---------------------------------------------------------------------------
# check_consistency — check 4: unknown wallet in allowlist
# ---------------------------------------------------------------------------


def test_check_consistency_unknown_wallet_in_allowlist(tmp_path: Path) -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    raw = {
        "version": 1,
        "callers": {},
        "wallets": {},
        "permissions": {
            "perm/main": {
                "contracts": {},
                "wallet_allowlist": ["ghost-wallet"],
            }
        },
        "wallet_constraints": {},
    }
    policy = load_policy(_write_yaml(tmp_path, raw))
    # No wallets in DB and no wallets in policy.wallets — ghost-wallet is unknown.
    errors = check_consistency(policy, [], [], registry)
    assert any("ghost-wallet" in e for e in errors), errors


def test_check_consistency_wallet_in_db_is_known(tmp_path: Path) -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    raw = {
        "version": 1,
        "callers": {},
        "wallets": {},
        "permissions": {
            "perm/main": {
                "contracts": {},
                "wallet_allowlist": ["db-wallet"],
            }
        },
        "wallet_constraints": {},
    }
    policy = load_policy(_write_yaml(tmp_path, raw))
    wallets = [_make_wallet("db-wallet")]
    errors = check_consistency(policy, [], wallets, registry)
    # db-wallet is in the DB, so no error.
    assert not any("db-wallet" in e for e in errors), errors


# ---------------------------------------------------------------------------
# check_consistency — check 5: wallet binding policy_path not in constraints
# ---------------------------------------------------------------------------


def test_check_consistency_wallet_binding_policy_path_missing(tmp_path: Path) -> None:
    registry = AbiRegistry.load(ABIS_DIR)
    raw = {
        "version": 1,
        "callers": {},
        "wallets": {
            "my-wallet": {"policy_path": "wc/nonexistent"},
        },
        "permissions": {},
        "wallet_constraints": {},
    }
    policy = load_policy(_write_yaml(tmp_path, raw))
    errors = check_consistency(policy, [], [], registry)
    assert any("my-wallet" in e and "wc/nonexistent" in e for e in errors), errors


# ---------------------------------------------------------------------------
# policy_path_exists
# ---------------------------------------------------------------------------


def _make_policy_for_path_exists() -> Policy:
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "wallets": {},
            "permissions": {
                "perm/caller-a": {
                    "contracts": {},
                    "wallet_allowlist": [],
                },
            },
            "wallet_constraints": {
                "wc/wallet-a": {},
            },
        }
    )


def test_policy_path_exists_caller_hit() -> None:
    policy = _make_policy_for_path_exists()
    assert policy_path_exists(policy, "perm/caller-a", "caller") is True


def test_policy_path_exists_caller_miss() -> None:
    policy = _make_policy_for_path_exists()
    assert policy_path_exists(policy, "perm/no-such", "caller") is False


def test_policy_path_exists_wallet_hit() -> None:
    policy = _make_policy_for_path_exists()
    assert policy_path_exists(policy, "wc/wallet-a", "wallet") is True


def test_policy_path_exists_wallet_miss() -> None:
    policy = _make_policy_for_path_exists()
    assert policy_path_exists(policy, "wc/no-such", "wallet") is False


def test_policy_path_exists_unknown_kind_returns_false() -> None:
    policy = _make_policy_for_path_exists()
    assert policy_path_exists(policy, "anything", "unknown-kind") is False
