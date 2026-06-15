"""Tests for the `fsp-register` capability in app/policy_init.generate_policy.

fsp-register is the ONE-TIME, revocable entity-registration capability: the 3
EntityManager `confirm*Registration` calls a keyless provider must self-sign to
register its own submit / submit-signatures / signing-policy addresses. The
matching `propose*Address` + `registerPublicKey` calls are signed by the COLD
identity key OFF fwd, so they are deliberately NOT in the policy.

Assertions:
  - co-generated fsp,fsp-voter,fsp-register round-trips through load_policy +
    check_consistency (the signing-policy confirm on the cross-domain fsp-signing
    wallet is admitted by the bounded entity_manager carve-out);
  - each confirm block: entity_manager ABI, value=0, scalar `_voter` pinned to
    --identity, NO allow_unconstrained_args, correct wallet;
  - fsp-register without --identity raises;
  - CARVE-OUT NEGATIVE: entity_manager is bounded to confirmSigningPolicyAddress
    Registration ONLY — a self-submit wallet with a DIFFERENT entity_manager method,
    or a non-zero value, is refused;
  - REGRESSION: claim,fsp and standalone fsp-voter carry NONE of the entity-confirm keys;
  - capability_grant: the 3 entity-confirm roles resolve to caller/policy_path.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from fwd.app.capability_grant import ConsumerSpec, provisioning_plan
from fwd.app.policy_init import PolicyInitError, generate_policy
from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.policy_loader import check_consistency, load_policy
from fwd.infra.wallet_repo import Wallet

_ROOT = Path(__file__).resolve().parents[2]
ABIS_DIR = _ROOT / "config" / "abis"
NETWORKS_FILE = _ROOT / "config" / "networks.yaml"
RECIPIENT = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"
IDENTITY = "0x80a104815C6d020fd7570DC59c87C7d449a156D6"

_SGB = 19  # songbird chain id

# role -> (perm path, wallet, confirm method signature)
_CONFIRM_BLOCKS = {
    "perm/entity-confirm-submit-songbird": (
        "fsp-submit-songbird",
        "confirmSubmitAddressRegistration(address)",
    ),
    "perm/entity-confirm-sig-submit-songbird": (
        "fsp-sig-submit-songbird",
        "confirmSubmitSignaturesAddressRegistration(address)",
    ),
    "perm/entity-confirm-signing-songbird": (
        "fsp-signing-songbird",
        "confirmSigningPolicyAddressRegistration(address)",
    ),
}
_EM_SONGBIRD = "0x46c417d0760198e94fee455ce0e223262a3d0049"


def _gen(capabilities: str, *, identity: str | None = IDENTITY, recipient: str | None = None) -> str:
    return generate_policy(
        networks=["songbird"],
        capabilities=capabilities.split(","),
        recipient=recipient,
        identity=identity,
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


@pytest.fixture(scope="module")
def registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


# ---------------------------------------------------------------------------
# Structure + round-trip (the signing confirm passes the carve-out)
# ---------------------------------------------------------------------------


def test_fsp_register_structure_and_roundtrip(tmp_path: Path) -> None:
    """fsp,fsp-voter,fsp-register emits 3 entity-confirm blocks; the signing-policy
    confirm on the cross-domain fsp-signing wallet is admitted; round-trip clean."""
    text = _gen("fsp,fsp-voter,fsp-register")
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    perms = doc["permissions"]

    for pp, (wallet, sig) in _CONFIRM_BLOCKS.items():
        assert pp in perms, f"missing {pp}"
        rule = next(iter(perms[pp]["contracts"].values()))
        assert rule["abi"] == "entity_manager"
        assert rule["chains"] == [_SGB]
        assert set(rule["methods"]) == {sig}, f"{pp} method mismatch"
        mrule = rule["methods"][sig]
        assert mrule["max_value_wei"] == "0"
        # scalar _voter pinned to identity; NOT unconstrained
        assert mrule.get("allow_unconstrained_args") is not True
        assert mrule["arg_predicates"] == {"_voter": IDENTITY}
        assert perms[pp]["wallet_allowlist"] == [wallet]
        # EntityManager address is the Songbird EntityManager (lowercased compare).
        assert next(iter(perms[pp]["contracts"])).lower() == _EM_SONGBIRD
        # caller wired
        caller = pp.replace("perm/", "")
        assert doc["callers"][caller] == {"policy_path": pp}

    # fsp-signing still opted into the carve-out.
    assert "fsp-signing-songbird" in doc["fsp_self_submit"]
    # The EVM-only confirm wallets are NOT in fsp_self_submit.
    assert "fsp-submit-songbird" not in doc["fsp_self_submit"]
    assert "fsp-sig-submit-songbird" not in doc["fsp_self_submit"]


def test_fsp_register_requires_identity() -> None:
    """fsp-register without --identity raises (it pins _voter)."""
    with pytest.raises(PolicyInitError, match="identity is required"):
        _gen("fsp,fsp-voter,fsp-register", identity=None)


def test_fsp_register_merges_into_existing_fsp_voter(tmp_path: Path) -> None:
    """`--capabilities fsp-register --merge` unions the 3 confirm blocks into an
    existing fsp,fsp-voter policy and the merged result round-trips clean."""
    base = _gen("fsp,fsp-voter")
    merged = generate_policy(
        networks=["songbird"],
        capabilities=["fsp-register"],
        recipient=None,
        identity=IDENTITY,
        abis_dir=ABIS_DIR,
        networks_file=NETWORKS_FILE,
        merge_into=base,
    )
    assert _roundtrip(tmp_path, merged) == []
    doc = yaml.safe_load(merged)
    for pp in _CONFIRM_BLOCKS:
        assert pp in doc["permissions"]
    # The fsp-voter steady-state blocks survive the merge.
    assert "perm/ftso-price-submit-songbird" in doc["permissions"]


# ---------------------------------------------------------------------------
# CARVE-OUT NEGATIVE: entity_manager bounded to confirmSigningPolicy... only
# ---------------------------------------------------------------------------


def test_carve_out_negative_entity_manager_non_exempt_method(registry: AbiRegistry) -> None:
    """Only confirmSigningPolicyAddressRegistration is exempt for entity_manager. A
    self-submit wallet with a DIFFERENT entity_manager confirm method is refused."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/em-bad-method": {
                    "contracts": {
                        "0x" + "f1" * 20: {
                            "abi": "entity_manager",
                            "chains": [_SGB],
                            "methods": {
                                # submit confirm is NOT in the exempt set for self-submit
                                "confirmSubmitAddressRegistration(address)": {
                                    "max_value_wei": "0",
                                    "arg_predicates": {"_voter": IDENTITY},
                                },
                            },
                        }
                    },
                    "wallet_allowlist": ["em-m"],
                }
            },
            "fsp_permissions": {
                "fsp/em-m-sign": {
                    "message_types": ["SIGNING_POLICY"],
                    "wallet_allowlist": ["em-m"],
                    "chain_ids": [_SGB],
                }
            },
            "wallet_constraints": {
                "wc/em-m": {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": {"per_hour": 50, "per_day": 500},
                }
            },
            "wallets": {"em-m": {"policy_path": "wc/em-m"}},
            "fsp_self_submit": ["em-m"],
        }
    )
    wallet = _make_wallet("em-m", address="0x" + "f2" * 20)
    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, f"Expected 'carve-out refused' for non-exempt entity_manager method: {errors}"


def test_carve_out_negative_entity_manager_nonzero_value(registry: AbiRegistry) -> None:
    """confirmSigningPolicyAddressRegistration with max_value_wei != '0' is refused."""
    policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {},
            "permissions": {
                "perm/em-bad-value": {
                    "contracts": {
                        "0x" + "f3" * 20: {
                            "abi": "entity_manager",
                            "chains": [_SGB],
                            "methods": {
                                "confirmSigningPolicyAddressRegistration(address)": {
                                    "max_value_wei": "1",  # non-zero — must refuse
                                    "arg_predicates": {"_voter": IDENTITY},
                                },
                            },
                        }
                    },
                    "wallet_allowlist": ["em-v"],
                }
            },
            "fsp_permissions": {
                "fsp/em-v-sign": {
                    "message_types": ["SIGNING_POLICY"],
                    "wallet_allowlist": ["em-v"],
                    "chain_ids": [_SGB],
                }
            },
            "wallet_constraints": {
                "wc/em-v": {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": {"per_hour": 50, "per_day": 500},
                }
            },
            "wallets": {"em-v": {"policy_path": "wc/em-v"}},
            "fsp_self_submit": ["em-v"],
        }
    )
    wallet = _make_wallet("em-v", address="0x" + "f4" * 20)
    errors = check_consistency(policy, [], [wallet], registry)
    refused = [e for e in errors if "carve-out refused" in e]
    assert refused, f"Expected 'carve-out refused' for non-zero value on confirm: {errors}"


# ---------------------------------------------------------------------------
# REGRESSION: entity-confirm keys must NOT appear without fsp-register
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("caps", ["claim,fsp", "fsp-voter"])
def test_entity_confirm_absent_without_fsp_register(tmp_path: Path, caps: str) -> None:
    """REGRESSION: claim,fsp and standalone fsp-voter carry NONE of the entity-confirm
    keys, and no entity_manager ABI block leaks in."""
    text = _gen(caps, recipient=(RECIPIENT if "claim" in caps else None))
    assert _roundtrip(tmp_path, text) == []
    doc = yaml.safe_load(text)
    for pp in _CONFIRM_BLOCKS:
        assert pp not in doc.get("permissions", {}), f"{pp} leaked into {caps}"
        assert pp.replace("perm/", "") not in doc["callers"], f"caller for {pp} leaked into {caps}"
    for perm in doc.get("permissions", {}).values():
        for rule in perm.get("contracts", {}).values():
            assert rule["abi"] != "entity_manager", f"entity_manager ABI leaked into {caps}"


# ---------------------------------------------------------------------------
# capability_grant: the 3 entity-confirm roles resolve
# ---------------------------------------------------------------------------


def test_entity_confirm_roles_in_capability_grant() -> None:
    """_ROLE_CONVENTION derives the 3 entity-confirm roles to caller/policy_path."""
    roles = ["entity-confirm-submit", "entity-confirm-sig-submit", "entity-confirm-signing"]
    spec = ConsumerSpec.model_validate(
        {
            "consumer": "fsp",
            "network": "songbird",
            "compat": {"fwd_contract_expected": "v1", "fwd_client": "0.1.0"},
            "capabilities": [
                {
                    "capability_id": f"fsp/songbird/{r}",
                    "role": r,
                    "endpoint": "/v1/sign-transaction",
                    "caller_token_env": f"{r.upper().replace('-', '_')}_TOKEN",
                    "wallet_env": "WALLET_NAME",
                    "wallet_name": "fsp-signing-songbird",
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
    for r in roles:
        g = by_id[f"fsp/songbird/{r}"]
        assert g.caller_name == f"{r}-songbird"
        assert g.policy_path == f"perm/{r}-songbird"
