"""Tests for the `fsp-voter` capability in app/policy_init.generate_policy.

Corrected model (post-2a23dcf fix):
  - SIGNING_PK (fsp-signing-{net}) is the fast-update signing key — ONE
    fsp/fastupdate-sign-{net} block on the shared signing wallet.
  - The 3 FAST_UPDATES_ACCOUNTS are EVM-only submitUpdates tx senders
    (fastupdate-{1,2,3}-{net} wallets); they are NOT in fsp_self_submit.
  - No cross-domain carve-out for fastupdate wallets — _FSP_SELF_SUBMIT_SHAPES
    contains only flare_systems_manager.

Assertions:
  - the generated blocks round-trip through load_policy + check_consistency;
  - 4-block fsp_permissions (3 sign-only + 1 fastupdate-sign), ALL on fsp-signing;
  - 3 EVM-only fastupdate-submit wallets are NOT in fsp_self_submit;
  - fsp_self_submit is absent (or empty) for standalone fsp-voter;
  - carve-out NEGATIVE: FSM carve-out is still bounded (non-exempt method / non-zero
    value refuses it); the fast_updater shape no longer exists in the map;
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

# The four SIGN fsp_permissions blocks — all on fsp-signing-songbird.
_SIGNING_BLOCKS = {
    "fsp/signing-policy-songbird": "SIGNING_POLICY",
    "fsp/voter-registration-songbird": "VOTER_REGISTRATION",
    "fsp/protocol-message-songbird": "PROTOCOL_PAYLOAD",
    "fsp/fastupdate-sign-songbird": "FAST_UPDATE",
}
# All expected fsp_permissions blocks for a standalone fsp-voter run (same set).
_ALL_FSP_BLOCKS = _SIGNING_BLOCKS


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
# Core structure test — 4 fsp sign blocks + 3 EVM submit + 2 EVM FTSO
# ---------------------------------------------------------------------------


def test_fsp_voter_structure_and_roundtrip(tmp_path: Path) -> None:
    """fsp-voter emits 4 fsp sign blocks (all on fsp-signing) + 3 fastupdate-submit
    + ftso-price-submit + ftso-signature-submit. Full round-trip must be clean."""
    text = _gen("fsp-voter", recipient=None)
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    fperms = doc["fsp_permissions"]
    perms = doc["permissions"]

    # fsp_permissions: exactly 4 sign blocks, ALL on fsp-signing-songbird.
    assert set(fperms) == set(_ALL_FSP_BLOCKS), (
        f"fsp_permissions mismatch.\n  Expected: {sorted(_ALL_FSP_BLOCKS)}\n  Got: {sorted(fperms)}"
    )
    for path, mt in _ALL_FSP_BLOCKS.items():
        assert fperms[path]["message_types"] == [mt]
        assert fperms[path]["chain_ids"] == [_SGB]
        assert fperms[path]["wallet_allowlist"] == ["fsp-signing-songbird"], (
            f"{path} must use fsp-signing-songbird, got {fperms[path]['wallet_allowlist']}"
        )

    # permissions: 3 fastupdate-submit + ftso-price-submit + ftso-signature-submit
    # + relay-submit (Relay finalization on the shared fsp-signing wallet).
    expected_perm_keys = (
        {f"perm/fastupdate-submit-{i}-songbird" for i in (1, 2, 3)}
        | {"perm/ftso-price-submit-songbird", "perm/ftso-signature-submit-songbird"}
        | {"perm/relay-submit-songbird"}
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
        # wallet_allowlist must be the per-seat wallet (EVM-only, not signing wallet)
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


def test_fastupdate_submit_wallets_not_in_fsp_self_submit(tmp_path: Path) -> None:
    """The three fastupdate-{i} wallets are EVM-only SUBMIT wallets: they must NOT
    be in fsp_self_submit. fsp-submit and fsp-sig-submit are also NOT there."""
    text = _gen("fsp-voter", recipient=None)
    doc = yaml.safe_load(text)
    ss = doc.get("fsp_self_submit", [])
    for i in (1, 2, 3):
        assert f"fastupdate-{i}-songbird" not in ss, (
            f"fastupdate-{i}-songbird must NOT be in fsp_self_submit (EVM-only submit wallet)"
        )
    assert "fsp-submit-songbird" not in ss
    assert "fsp-sig-submit-songbird" not in ss
    # fsp-signing IS in fsp_self_submit for standalone fsp-voter: it self-submits
    # Relay finalization (the system-client FINALIZER signs with SIGNING_PK), so the
    # signing wallet is cross-domain over Relay and opts into the bounded carve-out.
    assert "fsp-signing-songbird" in ss


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
        "fsp/fastupdate-sign-songbird",
    }
    assert expected_fsp_subset <= set(doc["fsp_permissions"]), (
        f"Missing fsp_permissions blocks: {expected_fsp_subset - set(doc['fsp_permissions'])}"
    )
    # The shared signing wallet is defined once, identically.
    assert doc["wallets"]["fsp-signing-songbird"] == {"policy_path": "wc/fsp-songbird"}


# ---------------------------------------------------------------------------
# Carve-out NEGATIVE: FSM carve-out is still bounded; fast_updater shape gone
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


_SUBMIT_UPDATES_SIG = "submitUpdates((uint256,(uint256,(uint256,uint256),uint256,uint256),bytes,(uint8,bytes32,bytes32)))"


def test_carve_out_negative_fast_updater_no_longer_exempt(registry: AbiRegistry) -> None:
    """CARVE-OUT NEGATIVE: fast_updater is no longer in _FSP_SELF_SUBMIT_SHAPES.
    A wallet in fsp_self_submit that also has a fast_updater EVM block is refused
    (the carve-out shape check fires because abi not in _FSP_SELF_SUBMIT_SHAPES)."""
    # The wallet must be in both fsp_permissions AND permissions allowlists, and
    # also in fsp_self_submit, to reach the shape-check path.
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
                    "wallet_allowlist": ["fu-cross-wallet"],
                }
            },
            "fsp_permissions": {
                "fsp/fastupdate-sign-cross": {
                    "message_types": ["FAST_UPDATE"],
                    "wallet_allowlist": ["fu-cross-wallet"],
                    "chain_ids": [_SGB],
                }
            },
            "wallet_constraints": {
                "wc/fu-cross-wallet": {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": {"per_hour": 50, "per_day": 500},
                },
            },
            "wallets": {
                "fu-cross-wallet": {"policy_path": "wc/fu-cross-wallet"},
            },
            # fast_updater is no longer in _FSP_SELF_SUBMIT_SHAPES — must be refused.
            "fsp_self_submit": ["fu-cross-wallet"],
        }
    )
    fu_wallet = _make_wallet("fu-cross-wallet", address="0x" + "a1" * 20)

    errors = check_consistency(policy, [], [fu_wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, (
        f"Expected 'carve-out refused' for fast_updater (no longer in _FSP_SELF_SUBMIT_SHAPES) "
        f"but got: {errors}"
    )


def test_carve_out_negative_non_exempt_method(registry: AbiRegistry) -> None:
    """CARVE-OUT NEGATIVE (proves the FSM bound): a wallet in fsp_self_submit whose
    EVM permissions block contains a non-exempt FSM method is refused."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/bad-submit": {
                    "contracts": {
                        "0x" + "cc" * 20: {
                            "abi": "flare_systems_manager",
                            "chains": [_SGB],
                            "methods": {
                                "signUptimeVote(uint24,bytes32,(uint8,bytes32,bytes32))": {
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
                    "message_types": ["UPTIME"],
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
    wallet = _make_wallet("bad-wallet", address="0x" + "a3" * 20)

    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, (
        f"Expected 'carve-out refused' error for non-exempt method but got: {errors}"
    )


def test_carve_out_negative_nonzero_value(registry: AbiRegistry) -> None:
    """CARVE-OUT NEGATIVE: max_value_wei != '0' on a FSM method refuses the carve-out."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/bad-value": {
                    "contracts": {
                        "0x" + "dd" * 20: {
                            "abi": "flare_systems_manager",
                            "chains": [_SGB],
                            "methods": {
                                "signUptimeVote(uint24,bytes32,(uint8,bytes32,bytes32))": {
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
                    "message_types": ["UPTIME"],
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
        f"Expected 'carve-out refused' for non-zero value on FSM method but got: {errors}"
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


def test_claim_fsp_unaffected_by_fsp_voter(tmp_path: Path) -> None:
    """REGRESSION GUARD: clif's `claim,fsp` policy must carry NONE of the fsp-voter keys."""
    text = _gen("claim,fsp")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)

    # No fast-update blocks (the single sign block or any submit block)
    assert "fsp/fastupdate-sign-songbird" not in doc.get("fsp_permissions", {}), (
        "fsp/fastupdate-sign-songbird leaked into claim,fsp fsp_permissions"
    )
    for i in (1, 2, 3):
        for key in (
            f"perm/fastupdate-submit-{i}-songbird",
            f"fastupdate-{i}-songbird",
        ):
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
        "fastupdate-sign-songbird",
    ):
        assert caller not in doc["callers"], f"{caller} leaked into claim,fsp callers"

    # No fast-update submit callers
    for i in (1, 2, 3):
        assert f"fastupdate-submit-{i}-songbird" not in doc["callers"]


# ---------------------------------------------------------------------------
# capability_grant: _ROLE_CONVENTION derives 1 sign + 3 submit + 2 FTSO submit
# ---------------------------------------------------------------------------


def test_capability_grant_derives_fsp_voter_roles() -> None:
    """The corrected role set: 3 signing-only + 1 fastupdate-sign (on fsp-signing) +
    3 fastupdate-submit (EVM-only) + 2 FTSO EVM submit roles."""
    roles = [
        "signing-policy-sign",
        "voter-registration-sign",
        "protocol-message-sign",
        "fastupdate-sign",
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

    # ONE fast-update sign role (on fsp-signing wallet)
    g = by_id["fsp/songbird/fastupdate-sign"]
    assert g.caller_name == "fastupdate-sign-songbird"
    assert g.policy_path == "fsp/fastupdate-sign-songbird"

    # Three EVM-only fast-update submit seats
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


# ---------------------------------------------------------------------------
# relay-submit: Relay finalization on the SHARED fsp-signing wallet (carve-out)
# ---------------------------------------------------------------------------


def test_relay_submit_role_on_fsp_signing(tmp_path: Path) -> None:
    """fsp-voter emits a relay-submit role: a relay() EVM block on the SHARED
    fsp-signing wallet, max_value_wei=0, and the wallet opts into the carve-out.
    The full policy must still round-trip clean."""
    text = _gen("fsp-voter", recipient=None)
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)

    perm = doc["permissions"]["perm/relay-submit-songbird"]
    rule = next(iter(perm["contracts"].values()))
    assert rule["abi"] == "relay"
    assert rule["chains"] == [_SGB]
    assert set(rule["methods"].keys()) == {"relay()"}
    assert rule["methods"]["relay()"]["max_value_wei"] == "0"
    assert rule["methods"]["relay()"]["allow_unconstrained_args"] is True
    # Submitted by the SHARED signing wallet (cross-domain over Relay).
    assert perm["wallet_allowlist"] == ["fsp-signing-songbird"]
    # Caller wired.
    assert doc["callers"]["relay-submit-songbird"] == {"policy_path": "perm/relay-submit-songbird"}
    # fsp-signing opted into the carve-out.
    assert "fsp-signing-songbird" in doc.get("fsp_self_submit", [])
    # The Relay contract address is the verified Songbird Relay (lowercased compare).
    assert next(iter(perm["contracts"])).lower() == "0xcb86e8be709001e01897bf59847406853da8f14b"


def test_relay_carve_out_passes_with_fsm_and_relay_blocks(tmp_path: Path) -> None:
    """fsp + fsp-voter compose: fsp-signing carries FSM (signUptimeVote/signRewards)
    AND Relay (relay()) EVM blocks AND signs FSP messages — the carve-out must accept
    BOTH exempt shapes and the composed policy round-trips clean."""
    text = _gen("fsp,fsp-voter")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    # fsp-signing is reachable from FSM submit blocks, the relay-submit block, AND
    # multiple fsp_permissions sign blocks — the carve-out admits it.
    assert "fsp-signing-songbird" in doc["fsp_self_submit"]
    # Both exempt EVM shapes present on the same signing wallet.
    relay_rule = next(iter(doc["permissions"]["perm/relay-submit-songbird"]["contracts"].values()))
    assert relay_rule["abi"] == "relay"
    fsm_block = doc["permissions"]["perm/uptime-submit-songbird"]
    assert "fsp-signing-songbird" in fsm_block["wallet_allowlist"]


def test_relay_carve_out_negative_nonzero_value(registry: AbiRegistry) -> None:
    """CARVE-OUT NEGATIVE (proves the relay bound): a wallet in fsp_self_submit whose
    relay() EVM block carries max_value_wei != '0' is refused."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/relay-bad-value": {
                    "contracts": {
                        "0x" + "c1" * 20: {
                            "abi": "relay",
                            "chains": [_SGB],
                            "methods": {
                                "relay()": {
                                    "max_value_wei": "1",  # non-zero — must refuse
                                    "allow_unconstrained_args": True,
                                },
                            },
                        }
                    },
                    "wallet_allowlist": ["relay-w"],
                }
            },
            "fsp_permissions": {
                "fsp/relay-sign": {
                    "message_types": ["PROTOCOL_PAYLOAD"],
                    "wallet_allowlist": ["relay-w"],
                    "chain_ids": [_SGB],
                }
            },
            "wallet_constraints": {
                "wc/relay-w": {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": {"per_hour": 50, "per_day": 500},
                }
            },
            "wallets": {
                "relay-w": {"policy_path": "wc/relay-w"},
            },
            "fsp_self_submit": ["relay-w"],
        }
    )
    wallet = _make_wallet("relay-w", address="0x" + "c2" * 20)

    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, (
        f"Expected 'carve-out refused' for non-zero value on relay() but got: {errors}"
    )


def test_relay_carve_out_negative_non_exempt_relay_method(registry: AbiRegistry) -> None:
    """CARVE-OUT NEGATIVE: a wallet in fsp_self_submit with a relay-ABI block using a
    method OTHER than relay() (e.g. setSigningPolicy) is refused — only relay() is exempt."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/relay-bad-method": {
                    "contracts": {
                        "0x" + "c3" * 20: {
                            "abi": "relay",
                            "chains": [_SGB],
                            "methods": {
                                "setSigningPolicy((uint24,uint32,uint16,uint256,address[],uint16[]))": {
                                    "max_value_wei": "0",
                                    "allow_unconstrained_args": True,
                                },
                            },
                        }
                    },
                    "wallet_allowlist": ["relay-m"],
                }
            },
            "fsp_permissions": {
                "fsp/relay-m-sign": {
                    "message_types": ["PROTOCOL_PAYLOAD"],
                    "wallet_allowlist": ["relay-m"],
                    "chain_ids": [_SGB],
                }
            },
            "wallet_constraints": {
                "wc/relay-m": {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": {"per_hour": 50, "per_day": 500},
                }
            },
            "wallets": {
                "relay-m": {"policy_path": "wc/relay-m"},
            },
            "fsp_self_submit": ["relay-m"],
        }
    )
    wallet = _make_wallet("relay-m", address="0x" + "c4" * 20)

    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, (
        f"Expected 'carve-out refused' for non-exempt relay method but got: {errors}"
    )


def test_relay_submit_role_in_capability_grant() -> None:
    """_ROLE_CONVENTION derives the relay-submit role to caller/policy_path."""
    spec = ConsumerSpec.model_validate(
        {
            "consumer": "fsp",
            "network": "songbird",
            "compat": {"fwd_contract_expected": "v1", "fwd_client": "0.1.0"},
            "capabilities": [
                {
                    "capability_id": "fsp/songbird/relay-submit",
                    "role": "relay-submit",
                    "endpoint": "/v1/sign-transaction",
                    "caller_token_env": "RELAY_SUBMIT_TOKEN",
                    "wallet_env": "WALLET_NAME",
                    "wallet_name": "fsp-signing-songbird",
                    "contract": None,
                    "contract_name": None,
                    "method": None,
                    "value_wei": None,
                    "recipient_pinned": None,
                    "suggested_rate": None,
                }
            ],
        }
    )
    by_id = {g.capability_id: g for g in provisioning_plan(spec)}
    g = by_id["fsp/songbird/relay-submit"]
    assert g.caller_name == "relay-submit-songbird"
    assert g.policy_path == "perm/relay-submit-songbird"


def test_relay_regression_no_relay_keys_in_claim_fsp(tmp_path: Path) -> None:
    """REGRESSION: claim,fsp must carry NONE of the relay-submit keys (relay is
    fsp-voter-only); no relay() leaks onto fsp-signing under claim,fsp."""
    text = _gen("claim,fsp")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    assert "perm/relay-submit-songbird" not in doc.get("permissions", {})
    assert "relay-submit-songbird" not in doc["callers"]
    # No relay-ABI block anywhere in claim,fsp.
    for perm in doc.get("permissions", {}).values():
        for rule in perm.get("contracts", {}).values():
            assert rule["abi"] != "relay", "relay ABI leaked into claim,fsp permissions"
