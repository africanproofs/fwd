"""Tests for the domain/policy.py Pydantic schema.

Validates schema parsing, strict extra-field rejection, version enforcement,
and field defaults per decisions.md D13/D14.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fwd.domain.policy import (
    CallerBinding,
    ContractRule,
    MethodRule,
    PermissionBlock,
    Policy,
    RateLimit,
    WalletBinding,
    WalletConstraint,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_policy(**overrides: object) -> dict[str, object]:
    """Return the smallest valid policy dict."""
    base: dict[str, object] = {"version": 1}
    base.update(overrides)
    return base


def _full_policy_dict() -> dict[str, object]:
    """Return a fully-populated policy dict for round-trip tests."""
    return {
        "version": 1,
        "callers": {
            "ftso-claimer": {"policy_path": "policies/ftso-claimer"},
        },
        "wallets": {
            "claim-recipient": {"policy_path": "wallet-constraints/claim-recipient"},
        },
        "permissions": {
            "policies/ftso-claimer": {
                "contracts": {
                    "0x1234567890abcdef1234567890abcdef12345678": {
                        "abi": "erc20",
                        "chains": [14],
                        "methods": {
                            "transfer(address,uint256)": {
                                "max_value_wei": "1000000000000000000",
                                "arg_predicates": {
                                    "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                                },
                            }
                        },
                    }
                },
                "wallet_allowlist": ["claim-recipient"],
                "rate": {"per_hour": 10, "per_day": 100},
            }
        },
        "wallet_constraints": {
            "wallet-constraints/claim-recipient": {
                "max_aggregate_value_wei_per_day": "5000000000000000000",
                "rate": {"per_hour": 5, "per_day": 50},
            }
        },
    }


# ---------------------------------------------------------------------------
# Happy-path parsing and round-trip
# ---------------------------------------------------------------------------


def test_minimal_policy_parses() -> None:
    p = Policy.model_validate(_minimal_policy())
    assert p.version == 1
    assert p.callers == {}
    assert p.wallets == {}
    assert p.permissions == {}
    assert p.wallet_constraints == {}


def test_full_policy_round_trips_fields() -> None:
    raw = _full_policy_dict()
    p = Policy.model_validate(raw)
    assert p.version == 1

    # callers
    assert "ftso-claimer" in p.callers
    assert p.callers["ftso-claimer"].policy_path == "policies/ftso-claimer"

    # wallets
    assert "claim-recipient" in p.wallets
    assert p.wallets["claim-recipient"].policy_path == "wallet-constraints/claim-recipient"

    # permissions
    perm = p.permissions["policies/ftso-claimer"]
    assert "0x1234567890abcdef1234567890abcdef12345678" in perm.contracts
    crule = perm.contracts["0x1234567890abcdef1234567890abcdef12345678"]
    assert crule.abi == "erc20"
    assert "transfer(address,uint256)" in crule.methods
    mrule = crule.methods["transfer(address,uint256)"]
    assert mrule.max_value_wei == "1000000000000000000"
    assert mrule.arg_predicates["to"] == "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    assert perm.wallet_allowlist == ["claim-recipient"]
    assert perm.rate is not None
    assert perm.rate.per_hour == 10
    assert perm.rate.per_day == 100

    # wallet_constraints
    wc = p.wallet_constraints["wallet-constraints/claim-recipient"]
    assert wc.max_aggregate_value_wei_per_day == "5000000000000000000"
    assert wc.rate is not None
    assert wc.rate.per_hour == 5
    assert wc.rate.per_day == 50


# ---------------------------------------------------------------------------
# extra="forbid" — unknown keys must raise ValidationError
# ---------------------------------------------------------------------------


def test_extra_key_in_policy_root_raises() -> None:
    raw = _minimal_policy(unknown_top_level_key="oops")
    with pytest.raises(ValidationError):
        Policy.model_validate(raw)


def test_extra_key_in_rate_limit_raises() -> None:
    with pytest.raises(ValidationError):
        RateLimit.model_validate({"per_hour": 5, "surprise": True})


def test_extra_key_in_method_rule_raises() -> None:
    with pytest.raises(ValidationError):
        MethodRule.model_validate({"max_value_wei": "0", "unknown": "x"})


def test_extra_key_in_contract_rule_raises() -> None:
    with pytest.raises(ValidationError):
        ContractRule.model_validate({"abi": "erc20", "methods": {}, "extra_field": 1})


def test_extra_key_in_permission_block_raises() -> None:
    with pytest.raises(ValidationError):
        PermissionBlock.model_validate({"contracts": {}, "wallet_allowlist": [], "foo": "bar"})


def test_extra_key_in_wallet_constraint_raises() -> None:
    with pytest.raises(ValidationError):
        WalletConstraint.model_validate({"extra": True})


def test_extra_key_in_caller_binding_raises() -> None:
    with pytest.raises(ValidationError):
        CallerBinding.model_validate({"policy_path": "p", "extra": True})


def test_extra_key_in_wallet_binding_raises() -> None:
    with pytest.raises(ValidationError):
        WalletBinding.model_validate({"policy_path": "p", "extra": True})


# ---------------------------------------------------------------------------
# version validation
# ---------------------------------------------------------------------------


def test_version_2_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 2})


def test_version_0_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 0})


# ---------------------------------------------------------------------------
# RateLimit ge=1 constraint
# ---------------------------------------------------------------------------


def test_rate_limit_per_hour_zero_rejected() -> None:
    with pytest.raises(ValidationError):
        RateLimit.model_validate({"per_hour": 0})


def test_rate_limit_per_day_zero_rejected() -> None:
    with pytest.raises(ValidationError):
        RateLimit.model_validate({"per_day": 0})


def test_rate_limit_per_hour_negative_rejected() -> None:
    with pytest.raises(ValidationError):
        RateLimit.model_validate({"per_hour": -1})


def test_rate_limit_per_hour_one_accepted() -> None:
    rl = RateLimit.model_validate({"per_hour": 1})
    assert rl.per_hour == 1


# ---------------------------------------------------------------------------
# Defaults — empty collections are valid
# ---------------------------------------------------------------------------


def test_policy_empty_callers_defaults() -> None:
    p = Policy.model_validate({"version": 1})
    assert p.callers == {}
    assert p.wallets == {}
    assert p.permissions == {}
    assert p.wallet_constraints == {}


def test_method_rule_defaults() -> None:
    mr = MethodRule.model_validate({})
    assert mr.max_value_wei == "0"
    assert mr.arg_predicates == {}


def test_rate_limit_all_none_by_default() -> None:
    rl = RateLimit.model_validate({})
    assert rl.per_hour is None
    assert rl.per_day is None
