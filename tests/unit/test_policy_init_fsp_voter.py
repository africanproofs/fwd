"""Tests for the `fsp-voter` capability in app/policy_init.generate_policy (1c-ii).

1c-ii extends 1c-i: replaces the single fastupdate-sign seat with three seats
(fastupdate-{1,2,3}) that each have a SIGN (FAST_UPDATE) leg + a SUBMIT
(FastUpdater.submitUpdates) leg + fsp_self_submit carve-out. Also adds
ftso-price-submit (Submission.submit1/2/3) and ftso-signature-submit
(Submission.submitSignatures) as EVM-only roles.

Assertions:
  - the generated blocks round-trip through load_policy + check_consistency;
  - 3-seat structure (sign + submit per seat, wallets in fsp_self_submit);
  - ftso-price-submit and ftso-signature-submit are EVM-only (NOT in fsp_self_submit);
  - carve-out POSITIVE: fastupdate wallet passes (FAST_UPDATE sign + submitUpdates);
  - carve-out NEGATIVE: non-exempt method or non-zero value refuses the carve-out;
  - cross-domain wallet NOT in fsp_self_submit still triggers segmentation violation;
  - REGRESSION: claim,fsp output carries NONE of the new keys.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from fwd.app.capability_grant import ConsumerSpec, provisioning_plan
from fwd.app.policy_init import generate_policy
from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.policy_loader import check_consistency, load_policy
from fwd.infra.wallet_repo import Wallet

_ROOT = Path(__file__).resolve().parents[2]
ABIS_DIR = _ROOT / "config" / "abis"
NETWORKS_FILE = _ROOT / "config" / "networks.yaml"
RECIPIENT = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"

_SGB = 19  # songbird chain id

# The three sign-only fsp_permissions blocks from the shared signing wallet (unchanged).
_SIGNING_BLOCKS = {
    "fsp/signing-policy-songbird": "SIGNING_POLICY",
    "fsp/voter-registration-songbird": "VOTER_REGISTRATION",
    "fsp/protocol-message-songbird": "PROTOCOL_PAYLOAD",
}
# The three fast-update SIGN blocks (one per seat).
_FU_SIGN_BLOCKS = {
    f"fsp/fastupdate-sign-{i}-songbird": "FAST_UPDATE" for i in (1, 2, 3)
}
# All expected fsp_permissions blocks for a standalone fsp-voter run.
_ALL_FSP_BLOCKS = {**_SIGNING_BLOCKS, **_FU_SIGN_BLOCKS}


def _gen(capabilities: str, recipient: str | None = RECIPIENT) -> str:
    return generate_policy(
        networks=["songbird"],
        capabilities=capabilities.split(","),
        recipient=recipient,
        abis_dir=ABIS_DIR,
        networks_file=NETWORKS_FILE,
    )


def _roundtrip(tmp_path: Path, text: str) -> list[str]:
    p = tmp_path / "policy.yaml"
    p.write_text(text)
    policy = load_policy(p)
    registry = AbiRegistry.load(ABIS_DIR)
    return check_consistency(policy, [], [], registry)


def _make_wallet(name: str, address: str = "0x" + "ab" * 20) -> Wallet:
    return Wallet(
        name=name,
        address=address,
        privkey_ciphertext="seal:v1:x",
        vault_master_key="fwd-master",
        policy_path="wc/default",
        created_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Core structure test — 3 seats + EVM submit roles
# ---------------------------------------------------------------------------


def test_fsp_voter_3seats_and_evm_submit_roundtrip(tmp_path: Path) -> None:
    """fsp-voter now emits 3 fast-update seats (sign+submit) plus ftso-price-submit
    and ftso-signature-submit. Full round-trip must be clean."""
    text = _gen("fsp-voter", recipient=None)
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    fperms = doc["fsp_permissions"]
    perms = doc["permissions"]

    # fsp_permissions: exactly the 6 sign blocks (3 signing + 3 fast-update seats)
    assert set(fperms) == set(_ALL_FSP_BLOCKS), (
        f"fsp_permissions mismatch.\n  Expected: {sorted(_ALL_FSP_BLOCKS)}\n  Got: {sorted(fperms)}"
    )
    for path, mt in _ALL_FSP_BLOCKS.items():
        assert fperms[path]["message_types"] == [mt]
        assert fperms[path]["chain_ids"] == [_SGB]

    # Shared signing wallet serves the 3 sign-only blocks.
    for path in _SIGNING_BLOCKS:
        assert fperms[path]["wallet_allowlist"] == ["fsp-signing-songbird"]

    # Each fast-update SIGN block uses its own per-seat wallet.
    for i in (1, 2, 3):
        assert fperms[f"fsp/fastupdate-sign-{i}-songbird"]["wallet_allowlist"] == [
            f"fastupdate-{i}-songbird"
        ]

    # permissions: 3 fastupdate-submit + ftso-price-submit + ftso-signature-submit
    expected_perm_keys = (
        {f"perm/fastupdate-submit-{i}-songbird" for i in (1, 2, 3)}
        | {"perm/ftso-price-submit-songbird", "perm/ftso-signature-submit-songbird"}
    )
    assert set(perms) == expected_perm_keys, (
        f"permissions mismatch.\n  Expected: {sorted(expected_perm_keys)}\n  Got: {sorted(perms)}"
    )

    # Each fastupdate-submit block uses the fast_updater ABI and submitUpdates.
    for i in (1, 2, 3):
        perm = perms[f"perm/fastupdate-submit-{i}-songbird"]
        contract_rules = list(perm["contracts"].values())
        assert len(contract_rules) == 1
        rule = contract_rules[0]
        assert rule["abi"] == "fast_updater"
        assert rule["chains"] == [_SGB]
        methods = rule["methods"]
        assert len(methods) == 1
        sig = next(iter(methods))
        assert sig.startswith("submitUpdates(")
        assert methods[sig]["max_value_wei"] == "0"
        assert methods[sig]["allow_unconstrained_args"] is True
        # wallet_allowlist must be the per-seat wallet
        assert perm["wallet_allowlist"] == [f"fastupdate-{i}-songbird"]

    # ftso-price-submit uses the submission ABI with submit1/2/3.
    price_perm = perms["perm/ftso-price-submit-songbird"]
    price_rule = list(price_perm["contracts"].values())[0]
    assert price_rule["abi"] == "submission"
    assert set(price_rule["methods"].keys()) == {"submit1()", "submit2()", "submit3()"}
    for mval in price_rule["methods"].values():
        assert mval["max_value_wei"] == "0"
    assert price_perm["wallet_allowlist"] == ["fsp-submit-songbird"]

    # ftso-signature-submit uses the submission ABI with submitSignatures.
    sig_perm = perms["perm/ftso-signature-submit-songbird"]
    sig_rule = list(sig_perm["contracts"].values())[0]
    assert sig_rule["abi"] == "submission"
    assert set(sig_rule["methods"].keys()) == {"submitSignatures()"}
    assert sig_perm["wallet_allowlist"] == ["fsp-sig-submit-songbird"]


def test_fastupdate_wallets_in_fsp_self_submit(tmp_path: Path) -> None:
    """The three fastupdate-{i} wallets are in fsp_self_submit; the EVM-only
    wallets (fsp-submit, fsp-sig-submit) are NOT."""
    text = _gen("fsp-voter", recipient=None)
    doc = yaml.safe_load(text)
    ss = doc.get("fsp_self_submit", [])
    for i in (1, 2, 3):
        assert f"fastupdate-{i}-songbird" in ss, (
            f"fastupdate-{i}-songbird not in fsp_self_submit"
        )
    assert "fsp-submit-songbird" not in ss
    assert "fsp-sig-submit-songbird" not in ss


def test_fsp_and_fsp_voter_compose(tmp_path: Path) -> None:
    """fsp + fsp-voter compose cleanly: uptime/reward SIGN blocks plus all voter blocks."""
    text = _gen("fsp,fsp-voter")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    expected_fsp_subset = {
        "fsp/uptime-songbird",
        "fsp/reward-songbird",
        "fsp/signing-policy-songbird",
        "fsp/voter-registration-songbird",
        "fsp/protocol-message-songbird",
        "fsp/fastupdate-sign-1-songbird",
        "fsp/fastupdate-sign-2-songbird",
        "fsp/fastupdate-sign-3-songbird",
    }
    assert expected_fsp_subset <= set(doc["fsp_permissions"]), (
        f"Missing fsp_permissions blocks: {expected_fsp_subset - set(doc['fsp_permissions'])}"
    )
    # The shared signing wallet is defined once, identically.
    assert doc["wallets"]["fsp-signing-songbird"] == {"policy_path": "wc/fsp-songbird"}


# ---------------------------------------------------------------------------
# Carve-out POSITIVE: fastupdate wallet passes with FAST_UPDATE sign + submitUpdates
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


_SUBMIT_UPDATES_SIG = "submitUpdates((uint256,(uint256,(uint256,uint256),uint256,uint256),bytes,(uint8,bytes32,bytes32)))"
_SHARED_FU_ADDR = "0x" + "a1" * 20


def test_carve_out_positive_fastupdate_wallet(registry: AbiRegistry) -> None:
    """CARVE-OUT POSITIVE: a fastupdate wallet that signs FAST_UPDATE AND submits
    submitUpdates(max_value_wei=0) passes check_consistency with no segmentation error."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/fastupdate-submit-1-songbird": {
                    "contracts": {
                        "0x" + "bb" * 20: {
                            "abi": "fast_updater",
                            "chains": [_SGB],
                            "methods": {
                                _SUBMIT_UPDATES_SIG: {
                                    "max_value_wei": "0",
                                    "allow_unconstrained_args": True,
                                },
                            },
                        }
                    },
                    "wallet_allowlist": ["fastupdate-1-songbird"],
                }
            },
            "fsp_permissions": {
                "fsp/fastupdate-sign-1-songbird": {
                    "message_types": ["FAST_UPDATE"],
                    "wallet_allowlist": ["fastupdate-1-songbird"],
                    "chain_ids": [_SGB],
                }
            },
            "wallet_constraints": {
                "wc/fastupdate-1-songbird": {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": {"per_hour": 50, "per_day": 500},
                }
            },
            "wallets": {
                "fastupdate-1-songbird": {"policy_path": "wc/fastupdate-1-songbird"},
            },
            "fsp_self_submit": ["fastupdate-1-songbird"],
        }
    )
    wallet = _make_wallet("fastupdate-1-songbird", address=_SHARED_FU_ADDR)

    errors = check_consistency(policy, [], [wallet], registry)
    seg_errors = [e for e in errors if "segmentation violation" in e]
    assert seg_errors == [], (
        f"Expected NO segmentation error for valid fastupdate carve-out but got: {seg_errors}"
    )
    carve_refused = [e for e in errors if "carve-out refused" in e]
    assert carve_refused == [], (
        f"Expected NO carve-out refused for valid fastupdate shape but got: {carve_refused}"
    )
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Carve-out NEGATIVE: non-exempt method still refuses the carve-out
# ---------------------------------------------------------------------------


def test_carve_out_negative_non_exempt_method(registry: AbiRegistry) -> None:
    """CARVE-OUT NEGATIVE (proves the bound): a wallet in fsp_self_submit whose EVM
    permissions block contains a NON-exempt method is refused — the extension did
    not over-broaden the carve-out."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/bad-submit": {
                    "contracts": {
                        "0x" + "cc" * 20: {
                            "abi": "fast_updater",
                            "chains": [_SGB],
                            "methods": {
                                # submitUpdates is exempt, but daemonize() is NOT.
                                _SUBMIT_UPDATES_SIG: {
                                    "max_value_wei": "0",
                                    "allow_unconstrained_args": True,
                                },
                                "daemonize()": {
                                    "max_value_wei": "0",
                                },
                            },
                        }
                    },
                    "wallet_allowlist": ["bad-wallet"],
                }
            },
            "fsp_permissions": {
                "fsp/bad-sign": {
                    "message_types": ["FAST_UPDATE"],
                    "wallet_allowlist": ["bad-wallet"],
                    "chain_ids": [_SGB],
                }
            },
            "wallet_constraints": {
                "wc/bad-wallet": {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": {"per_hour": 50, "per_day": 500},
                }
            },
            "wallets": {
                "bad-wallet": {"policy_path": "wc/bad-wallet"},
            },
            "fsp_self_submit": ["bad-wallet"],
        }
    )
    wallet = _make_wallet("bad-wallet", address=_SHARED_FU_ADDR)

    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, (
        f"Expected 'carve-out refused' error for non-exempt method but got: {errors}"
    )


def test_carve_out_negative_nonzero_value_fastupdate(registry: AbiRegistry) -> None:
    """CARVE-OUT NEGATIVE: max_value_wei != '0' on submitUpdates refuses the carve-out."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/bad-value": {
                    "contracts": {
                        "0x" + "dd" * 20: {
                            "abi": "fast_updater",
                            "chains": [_SGB],
                            "methods": {
                                _SUBMIT_UPDATES_SIG: {
                                    "max_value_wei": "1",  # non-zero — must refuse
                                    "allow_unconstrained_args": True,
                                },
                            },
                        }
                    },
                    "wallet_allowlist": ["val-wallet"],
                }
            },
            "fsp_permissions": {
                "fsp/val-sign": {
                    "message_types": ["FAST_UPDATE"],
                    "wallet_allowlist": ["val-wallet"],
                    "chain_ids": [_SGB],
                }
            },
            "wallet_constraints": {
                "wc/val-wallet": {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": {"per_hour": 50, "per_day": 500},
                }
            },
            "wallets": {
                "val-wallet": {"policy_path": "wc/val-wallet"},
            },
            "fsp_self_submit": ["val-wallet"],
        }
    )
    wallet = _make_wallet("val-wallet", address="0x" + "ee" * 20)

    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, (
        f"Expected 'carve-out refused' for non-zero value on submitUpdates but got: {errors}"
    )


def test_carve_out_negative_non_exempt_abi(registry: AbiRegistry) -> None:
    """CARVE-OUT NEGATIVE: a wallet in fsp_self_submit with an EVM permissions block
    using a completely unrelated ABI is refused."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/bad-abi": {
                    "contracts": {
                        "0x" + "ff" * 20: {
                            "abi": "reward_manager",  # not in _FSP_SELF_SUBMIT_SHAPES
                            "chains": [_SGB],
                            "methods": {
                                "claim((bytes32,bytes32[],uint256,address)[])": {
                                    "max_value_wei": "0",
                                },
                            },
                        }
                    },
                    "wallet_allowlist": ["abi-wallet"],
                }
            },
            "fsp_permissions": {
                "fsp/abi-sign": {
                    "message_types": ["FAST_UPDATE"],
                    "wallet_allowlist": ["abi-wallet"],
                    "chain_ids": [_SGB],
                }
            },
            "wallet_constraints": {
                "wc/abi-wallet": {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": {"per_hour": 50, "per_day": 500},
                }
            },
            "wallets": {
                "abi-wallet": {"policy_path": "wc/abi-wallet"},
            },
            "fsp_self_submit": ["abi-wallet"],
        }
    )
    wallet = _make_wallet("abi-wallet", address="0x" + "a2" * 20)

    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, (
        f"Expected 'carve-out refused' for non-exempt ABI but got: {errors}"
    )


def test_cross_domain_wallet_not_opted_in_still_segmentation_violation(
    registry: AbiRegistry,
) -> None:
    """A wallet with the SAME address in BOTH EVM and FSP permissions, but NOT listed
    in fsp_self_submit, still triggers the segmentation violation error."""
    shared_address = "0x" + "b1" * 20
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/evm": {
                    "contracts": {},
                    "wallet_allowlist": ["evm-w"],
                }
            },
            "fsp_permissions": {
                "fsp/sign": {
                    "message_types": ["FAST_UPDATE"],
                    "wallet_allowlist": ["fsp-w"],
                }
            },
            "wallet_constraints": {},
        }
    )
    evm_w = _make_wallet("evm-w", address=shared_address)
    fsp_w = _make_wallet("fsp-w", address=shared_address)

    errors = check_consistency(policy, [], [evm_w, fsp_w], registry)
    seg_errors = [e for e in errors if "segmentation violation" in e]
    assert seg_errors, (
        f"Expected segmentation violation for cross-domain wallet NOT opted in but got: {errors}"
    )


# ---------------------------------------------------------------------------
# REGRESSION GUARD: claim,fsp output must carry NONE of the new keys
# ---------------------------------------------------------------------------


def test_claim_fsp_unaffected_by_fsp_voter_1cii(tmp_path: Path) -> None:
    """REGRESSION GUARD: clif's `claim,fsp` policy must carry NONE of the 1c-ii keys."""
    text = _gen("claim,fsp")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)

    # No fast-update sign blocks
    for i in (1, 2, 3):
        for key in (
            f"fsp/fastupdate-sign-{i}-songbird",
            f"perm/fastupdate-submit-{i}-songbird",
            f"fastupdate-{i}-songbird",
        ):
            assert key not in doc.get("fsp_permissions", {}), f"{key} leaked into claim,fsp fsp_permissions"
            assert key not in doc.get("permissions", {}), f"{key} leaked into claim,fsp permissions"
            assert key not in doc.get("wallets", {}), f"{key} leaked into claim,fsp wallets"

    # No submission/fast_updater EVM keys
    for key in (
        "perm/ftso-price-submit-songbird",
        "perm/ftso-signature-submit-songbird",
        "fsp-submit-songbird",
        "fsp-sig-submit-songbird",
    ):
        assert key not in doc.get("permissions", {}), f"{key} leaked into claim,fsp permissions"
        assert key not in doc.get("wallets", {}), f"{key} leaked into claim,fsp wallets"

    # No fsp-voter sign-only callers
    for caller in (
        "signing-policy-sign-songbird",
        "voter-registration-sign-songbird",
        "protocol-message-sign-songbird",
    ):
        assert caller not in doc["callers"], f"{caller} leaked into claim,fsp callers"

    # No fast-update callers
    for i in (1, 2, 3):
        assert f"fastupdate-sign-{i}-songbird" not in doc["callers"]
        assert f"fastupdate-submit-{i}-songbird" not in doc["callers"]


# ---------------------------------------------------------------------------
# capability_grant: _ROLE_CONVENTION derives the 8 seat roles + 2 submit roles
# ---------------------------------------------------------------------------


def test_capability_grant_derives_1cii_roles() -> None:
    """The 8 fast-update seat roles and 2 EVM submit roles resolve through
    _ROLE_CONVENTION in the grant path."""
    roles = [
        "signing-policy-sign",
        "voter-registration-sign",
        "protocol-message-sign",
        "fastupdate-sign-1",
        "fastupdate-sign-2",
        "fastupdate-sign-3",
        "fastupdate-submit-1",
        "fastupdate-submit-2",
        "fastupdate-submit-3",
        "ftso-price-submit",
        "ftso-signature-submit",
    ]
    spec = ConsumerSpec.model_validate(
        {
            "consumer": "fsp",
            "network": "songbird",
            "compat": {"fwd_contract_expected": "v1", "fwd_client": "0.1.0"},
            "capabilities": [
                {
                    "capability_id": f"fsp/songbird/{r}",
                    "role": r,
                    "endpoint": "/v1/sign-fsp-message",
                    "caller_token_env": f"{r.upper().replace('-', '_')}_TOKEN",
                    "wallet_env": "WALLET_NAME",
                    "wallet_name": f"{r}-songbird",
                    "contract": None,
                    "contract_name": None,
                    "method": None,
                    "value_wei": None,
                    "recipient_pinned": None,
                    "suggested_rate": None,
                }
                for r in roles
            ],
        }
    )
    by_id = {g.capability_id: g for g in provisioning_plan(spec)}

    # Signing-only roles
    assert by_id["fsp/songbird/signing-policy-sign"].policy_path == "fsp/signing-policy-songbird"
    assert by_id["fsp/songbird/voter-registration-sign"].caller_name == "voter-registration-sign-songbird"
    assert by_id["fsp/songbird/protocol-message-sign"].policy_path == "fsp/protocol-message-songbird"

    # Fast-update SIGN seats
    for i in (1, 2, 3):
        g = by_id[f"fsp/songbird/fastupdate-sign-{i}"]
        assert g.caller_name == f"fastupdate-sign-{i}-songbird"
        assert g.policy_path == f"fsp/fastupdate-sign-{i}-songbird"

    # Fast-update SUBMIT seats
    for i in (1, 2, 3):
        g = by_id[f"fsp/songbird/fastupdate-submit-{i}"]
        assert g.caller_name == f"fastupdate-submit-{i}-songbird"
        assert g.policy_path == f"perm/fastupdate-submit-{i}-songbird"

    # EVM submit roles
    g = by_id["fsp/songbird/ftso-price-submit"]
    assert g.caller_name == "ftso-price-submit-songbird"
    assert g.policy_path == "perm/ftso-price-submit-songbird"

    g = by_id["fsp/songbird/ftso-signature-submit"]
    assert g.caller_name == "ftso-signature-submit-songbird"
    assert g.policy_path == "perm/ftso-signature-submit-songbird"
