"""App-layer policy.yaml generator (CLI-facing).

Emits a correct a29-schema policy.yaml from a provider's networks + recipient so
the operator does not hand-author the error-prone schema: required `chains`,
`allow_unconstrained_args` on the non-scalar-arg methods (claim / signRewards /
signUptimeVote), the recipient arg-predicate, the `fsp_self_submit` carve-out,
and per-wallet `wallet_constraints`. Method signatures are DERIVED from the
shipped ABI registry, so they always match what the daemon's check_consistency
validates. The output is meant to round-trip through `clifwd policy validate`.

cli -> app boundary: cli/policy.py calls generate_policy(); only this app module
touches infra (AbiRegistry, the networks data file, yaml). The generated wallet
and caller NAMES are conventional defaults the operator may rename; the SCHEMA is
what this exists to get right.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

from fwd.infra.abi_registry import AbiRegistry

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

__all__ = ["CLAIM", "FSP", "PolicyInitError", "generate_policy"]

CLAIM = "claim"
FSP = "fsp"
_VALID_CAPS = (CLAIM, FSP)


class PolicyInitError(Exception):
    """Raised on bad input (unknown network/capability, missing recipient, ABI gap)."""


def _load_networks(networks_file: Path) -> dict[str, dict[str, Any]]:
    if not networks_file.exists():
        raise PolicyInitError(f"networks file not found: {networks_file}")
    raw = yaml.safe_load(networks_file.read_text()) or {}
    if not isinstance(raw, dict):
        raise PolicyInitError(f"networks file malformed: {networks_file}")
    return raw


def _sig_for(registry: AbiRegistry, abi: str, method_name: str) -> str:
    """Return the single canonical signature for `method_name` in `abi`.

    Derived from the loaded registry so the generated policy's method keys are
    byte-identical to what check_consistency validates.
    """
    matches = [s for s in registry.signatures_for(abi) if s.split("(", 1)[0] == method_name]
    if len(matches) != 1:
        raise PolicyInitError(
            f"expected exactly one '{method_name}' in abi '{abi}', found {matches!r}"
        )
    return matches[0]


def generate_policy(
    *,
    networks: Iterable[str],
    capabilities: Iterable[str],
    recipient: str | None,
    abis_dir: Path,
    networks_file: Path,
    claim_rate: tuple[int, int] = (4, 8),
    fsp_rate: tuple[int, int] = (50, 500),
) -> str:
    """Build a policy.yaml string. See module docstring.

    `recipient` is required when CLAIM is in capabilities (it is pinned in the
    claim arg-predicate). The FSP sender wallet `fsp-sender` is shared across
    networks (chain is a runtime parameter on fwd's side); each network gets its
    own signing wallet `fsp-signing-<net>` (the fsp_self_submit carve-out key).
    """
    nets = [n.strip() for n in networks if n.strip()]
    caps = {c.strip().lower() for c in capabilities if c.strip()}
    if not nets:
        raise PolicyInitError("no networks given")
    bad_caps = caps - set(_VALID_CAPS)
    if bad_caps:
        raise PolicyInitError(f"unknown capabilities: {sorted(bad_caps)} (valid: {_VALID_CAPS})")
    if not caps:
        raise PolicyInitError(f"no capabilities given (valid: {_VALID_CAPS})")
    if CLAIM in caps and not recipient:
        raise PolicyInitError("recipient is required when 'claim' is in capabilities")

    table = _load_networks(networks_file)
    unknown = [n for n in nets if n not in table]
    if unknown:
        raise PolicyInitError(f"unknown network(s) {unknown}; known: {sorted(table)}")

    registry = AbiRegistry.load(abis_dir)
    claim_sig = _sig_for(registry, "reward_manager", "claim") if CLAIM in caps else None
    uptime_sig = _sig_for(registry, "flare_systems_manager", "signUptimeVote") if FSP in caps else None
    rewards_sig = _sig_for(registry, "flare_systems_manager", "signRewards") if FSP in caps else None

    callers: dict[str, Any] = {}
    wallets: dict[str, Any] = {}
    permissions: dict[str, Any] = {}
    wallet_constraints: dict[str, Any] = {}
    fsp_permissions: dict[str, Any] = {}
    fsp_self_submit: list[str] = []

    def _rate(pair: tuple[int, int]) -> dict[str, int]:
        return {"per_hour": pair[0], "per_day": pair[1]}

    for net in nets:
        spec = table[net]
        chain_id = spec["chain_id"]

        if CLAIM in caps:
            caller = f"claim-{net}"
            wallet = f"claimer-{net}"
            pp = f"perm/claim-{net}"
            wc = f"wc/claimer-{net}"
            callers[caller] = {"policy_path": pp}
            wallets[wallet] = {"policy_path": wc}
            permissions[pp] = {
                "contracts": {
                    spec["reward_manager"]: {
                        "abi": "reward_manager",
                        "chains": [chain_id],
                        "methods": {
                            claim_sig: {
                                "max_value_wei": "0",
                                "allow_unconstrained_args": True,
                                "arg_predicates": {"_recipient": recipient},
                            }
                        },
                    }
                },
                "wallet_allowlist": [wallet],
                "rate": _rate(claim_rate),
            }
            wallet_constraints[wc] = {
                "max_aggregate_value_wei_per_day": "0",
                "rate": _rate(claim_rate),
            }

        if FSP in caps:
            sign_caller = f"fsp-sign-{net}"
            submit_caller = f"fsp-submit-{net}"
            signing_wallet = f"fsp-signing-{net}"
            sender_wallet = "fsp-sender"  # shared across networks
            fsp_pp = f"fsp/{net}"
            submit_pp = f"perm/fsp-submit-{net}"
            wc_signing = f"wc/fsp-{net}"
            wc_sender = "wc/fsp-sender"

            callers[sign_caller] = {"policy_path": fsp_pp}
            callers[submit_caller] = {"policy_path": submit_pp}
            wallets[signing_wallet] = {"policy_path": wc_signing}
            wallets[sender_wallet] = {"policy_path": wc_sender}

            fsp_permissions[fsp_pp] = {
                "message_types": ["UPTIME", "REWARD_DISTRIBUTION"],
                "wallet_allowlist": [signing_wallet],
                "rate": _rate(fsp_rate),
            }
            permissions[submit_pp] = {
                "contracts": {
                    spec["flare_systems_manager"]: {
                        "abi": "flare_systems_manager",
                        "chains": [chain_id],
                        "methods": {
                            uptime_sig: {
                                "max_value_wei": "0",
                                "allow_unconstrained_args": True,
                                "arg_predicates": {"_rewardEpochId": "any"},
                            },
                            rewards_sig: {
                                "max_value_wei": "0",
                                "allow_unconstrained_args": True,
                                "arg_predicates": {"_rewardEpochId": "any"},
                            },
                        },
                    }
                },
                # The signing wallet self-submits (carve-out) + the dedicated
                # sole-submitter sender pays gas. Both must be allowlisted here.
                "wallet_allowlist": [signing_wallet, sender_wallet],
                "rate": _rate(fsp_rate),
            }
            # The signing-policy key signs FSP messages AND appears as a
            # self-submit EVM signer — opt into the segmentation carve-out.
            fsp_self_submit.append(signing_wallet)
            wallet_constraints[wc_signing] = {
                "max_aggregate_value_wei_per_day": "0",
                "rate": _rate(fsp_rate),
            }
            wallet_constraints[wc_sender] = {
                "max_aggregate_value_wei_per_day": "0",
                "rate": _rate(fsp_rate),
            }

    policy: dict[str, Any] = {"version": 1, "callers": callers, "wallets": wallets,
                              "permissions": permissions, "wallet_constraints": wallet_constraints}
    if fsp_permissions:
        policy["fsp_permissions"] = fsp_permissions
    if fsp_self_submit:
        # de-dup while preserving order
        policy["fsp_self_submit"] = list(dict.fromkeys(fsp_self_submit))

    header = (
        "# Generated by `clifwd policy init`. Operator-controlled private config\n"
        "# (Core invariant #12 — gitignored, never committed). Rename wallets/callers\n"
        "# to taste; create/import each wallet in fwd and mint each caller token,\n"
        "# then run `clifwd policy validate` before `docker compose up -d`.\n"
    )
    body = yaml.safe_dump(policy, sort_keys=False, default_flow_style=False, width=100)
    return header + body
