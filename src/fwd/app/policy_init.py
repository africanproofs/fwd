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

import copy
from typing import TYPE_CHECKING, Any

import yaml

from fwd.infra.abi_registry import AbiRegistry

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

__all__ = ["CLAIM", "FSP", "FSP_VOTER", "PolicyInitError", "generate_policy"]

CLAIM = "claim"
FSP = "fsp"
FSP_VOTER = "fsp-voter"
_VALID_CAPS = (CLAIM, FSP, FSP_VOTER)


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


_MERGE_DICT_SECTIONS = (
    "callers",
    "wallets",
    "permissions",
    "wallet_constraints",
    "fsp_permissions",
)


def _merge_policies(base: dict[str, Any], additions: dict[str, Any]) -> dict[str, Any]:
    """Union `additions` into `base`, preserving every key `additions` does not set.

    Onboarding emits strictly network-suffixed keys (claim-<net>, claimer-<net>,
    perm/claim-<net>, fsp/<net>, wc/fsp-<net>, …), so distinct networks never
    collide: merging ADDS the requested network and leaves every other network's
    rules byte-identical. Re-running the same network overwrites only its own
    (deterministically identical) keys. This is what makes adding a network
    purely additive — it can never drop a network that was not passed.
    """
    merged: dict[str, Any] = copy.deepcopy(base)
    merged["version"] = additions.get("version", merged.get("version", 1))
    for section in _MERGE_DICT_SECTIONS:
        add = additions.get(section)
        if not add or not isinstance(add, dict):
            continue
        cur = merged.get(section)
        merged[section] = {**(cur if isinstance(cur, dict) else {}), **add}
    _existing_ss = merged.get("fsp_self_submit", [])
    ss = [w for w in (_existing_ss if isinstance(_existing_ss, list) else []) if isinstance(w, str)]
    for w in additions.get("fsp_self_submit", []):
        if w not in ss:
            ss.append(w)
    if ss:
        merged["fsp_self_submit"] = ss
    return merged


def generate_policy(
    *,
    networks: Iterable[str],
    capabilities: Iterable[str],
    recipient: str | None,
    abis_dir: Path,
    networks_file: Path,
    fsp_sender_mode: str = "per-network",
    claim_rate: tuple[int, int] = (4, 8),
    fsp_rate: tuple[int, int] = (50, 500),
    merge_into: str | None = None,
) -> str:
    """Build a policy.yaml string. See module docstring.

    `recipient` is required when CLAIM is in capabilities (it is pinned in the
    claim arg-predicate). The FSP sender wallet is `fsp-sender-<net>` per network
    (fsp_sender_mode='per-network') or a single shared `fsp-sender`
    (fsp_sender_mode='shared'); each network always gets its own signing wallet
    `fsp-signing-<net>` (the fsp_self_submit carve-out key).
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
    if fsp_sender_mode not in ("per-network", "shared"):
        raise PolicyInitError(
            f"unknown fsp_sender_mode {fsp_sender_mode!r} (valid: 'per-network', 'shared')"
        )
    if CLAIM in caps and not recipient:
        raise PolicyInitError("recipient is required when 'claim' is in capabilities")

    table = _load_networks(networks_file)
    unknown = [n for n in nets if n not in table]
    if unknown:
        raise PolicyInitError(f"unknown network(s) {unknown}; known: {sorted(table)}")

    registry = AbiRegistry.load(abis_dir)
    claim_sig = _sig_for(registry, "reward_manager", "claim") if CLAIM in caps else None
    uptime_sig = (
        _sig_for(registry, "flare_systems_manager", "signUptimeVote") if FSP in caps else None
    )
    rewards_sig = (
        _sig_for(registry, "flare_systems_manager", "signRewards") if FSP in caps else None
    )
    # FSP_VOTER submit-tx method sigs (resolved from registry, not hand-written).
    submit1_sig = _sig_for(registry, "submission", "submit1") if FSP_VOTER in caps else None
    submit2_sig = _sig_for(registry, "submission", "submit2") if FSP_VOTER in caps else None
    submit3_sig = _sig_for(registry, "submission", "submit3") if FSP_VOTER in caps else None
    submitsig_sig = _sig_for(registry, "submission", "submitSignatures") if FSP_VOTER in caps else None
    submit_updates_sig = _sig_for(registry, "fast_updater", "submitUpdates") if FSP_VOTER in caps else None
    # Relay finalization method the system-client FINALIZER submits (it packs its own
    # calldata behind the relay() selector); resolved from the registry, not hand-written.
    relay_sig = _sig_for(registry, "relay", "relay") if FSP_VOTER in caps else None

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
                                # True required: claim(_proofs tuple[]) is non-scalar;
                                # _recipient predicate pins the beneficiary.
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
            # Per-message-type least-privilege (ADR-0004): each SIGN caller authorizes
            # exactly ONE FSP message type (UPTIME vs REWARD_DISTRIBUTION) on the shared
            # signing-policy wallet; each SUBMIT caller authorizes exactly ONE
            # FlareSystemsManager method on the shared sender wallet. An uptime token cannot
            # sign a reward distribution, and vice-versa.
            signing_wallet = f"fsp-signing-{net}"
            if fsp_sender_mode == "per-network":
                sender_wallet = f"fsp-sender-{net}"
                wc_sender = f"wc/fsp-sender-{net}"
            else:
                sender_wallet = "fsp-sender"  # shared across networks
                wc_sender = "wc/fsp-sender"
            wc_signing = f"wc/fsp-{net}"
            wallets[signing_wallet] = {"policy_path": wc_signing}
            wallets[sender_wallet] = {"policy_path": wc_sender}

            # SIGN legs (Leg-1, /v1/sign-fsp-message) — one caller + fsp_permissions block
            # per message type; both reference the shared signing wallet.
            uptime_sign_pp = f"fsp/uptime-{net}"
            reward_sign_pp = f"fsp/reward-{net}"
            callers[f"uptime-vote-sign-{net}"] = {"policy_path": uptime_sign_pp}
            callers[f"reward-distribution-sign-{net}"] = {"policy_path": reward_sign_pp}
            for _pp, _mt in ((uptime_sign_pp, "UPTIME"), (reward_sign_pp, "REWARD_DISTRIBUTION")):
                fsp_permissions[_pp] = {
                    "message_types": [_mt],
                    "wallet_allowlist": [signing_wallet],
                    "rate": _rate(fsp_rate),
                    # UPTIME has no epoch-bound chain context and is replayable across chains
                    # without an explicit allowlist (FSP-CROSSCHAIN-001); chain_ids pins it.
                    "chain_ids": [chain_id],
                }

            # SUBMIT legs (Leg-2, /v1/sign-transaction → FlareSystemsManager) — one caller +
            # permissions block per method.
            uptime_submit_pp = f"perm/uptime-submit-{net}"
            reward_submit_pp = f"perm/reward-submit-{net}"
            callers[f"uptime-vote-submit-{net}"] = {"policy_path": uptime_submit_pp}
            callers[f"reward-distribution-submit-{net}"] = {"policy_path": reward_submit_pp}
            _fsm = spec["flare_systems_manager"]
            for _pp, _method in ((uptime_submit_pp, uptime_sig), (reward_submit_pp, rewards_sig)):
                permissions[_pp] = {
                    "contracts": {
                        _fsm: {
                            "abi": "flare_systems_manager",
                            "chains": [chain_id],
                            "methods": {
                                _method: {
                                    "max_value_wei": "0",
                                    # signUptimeVote(tuple _signature) / signRewards(tuple[],
                                    # tuple) are non-scalar; chain_ids in fsp_permissions pins
                                    # the chain, epoch constraint via arg_predicates.
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

        if FSP_VOTER in caps:
            # fsp-voter adds:
            #   - three SIGN blocks (SIGNING_POLICY, VOTER_REGISTRATION, PROTOCOL_PAYLOAD)
            #     on the shared signing wallet;
            #   - ONE FAST_UPDATE SIGN block on the SAME shared signing wallet (SIGNING_PK
            #     is the fast-update BLS key — there are no per-seat signing keys);
            #   - three EVM-only SUBMIT wallets (fastupdate-{1,2,3}-{net}) for
            #     FastUpdater.submitUpdates (the 3 FAST_UPDATES_ACCOUNTS EVM seats);
            #   - ftso-price-submit (Submission.submit1/2/3) on the dedicated submit wallet;
            #   - ftso-signature-submit (Submission.submitSignatures) on the sig-submit wallet.
            # Verify the required network keys exist before emitting anything.
            if "submission" not in spec:
                raise PolicyInitError(
                    f"network '{net}' has no 'submission' address in networks.yaml "
                    f"(required for fsp-voter submit roles)"
                )
            if "fast_updater" not in spec:
                raise PolicyInitError(
                    f"network '{net}' has no 'fast_updater' address in networks.yaml "
                    f"(required for fsp-voter submit roles)"
                )
            if "relay" not in spec:
                raise PolicyInitError(
                    f"network '{net}' has no 'relay' address in networks.yaml "
                    f"(required for fsp-voter relay-submit role)"
                )
            submission_addr = spec["submission"]
            fast_updater_addr = spec["fast_updater"]
            relay_addr = spec["relay"]

            signing_wallet = f"fsp-signing-{net}"
            wc_signing = f"wc/fsp-{net}"
            # Defensively ensure the signing wallet (idempotent if FSP also present).
            wallets[signing_wallet] = {"policy_path": wc_signing}
            wallet_constraints[wc_signing] = {
                "max_aggregate_value_wei_per_day": "0",
                "rate": _rate(fsp_rate),
            }
            # The fsp-signing key now also self-submits Relay finalization (cross-domain
            # over Relay, per the system-client FINALIZER). Opt it into the segmentation
            # carve-out here so the fsp-voter policy is valid STANDALONE and composed with
            # the fsp cap (idempotent: fsp also appends the same wallet; de-dup at emit).
            fsp_self_submit.append(signing_wallet)

            # Four SIGN fsp_permissions blocks on the shared signing wallet:
            # SIGNING_POLICY, VOTER_REGISTRATION, PROTOCOL_PAYLOAD, FAST_UPDATE.
            for _pp, _mt, _caller in (
                (f"fsp/signing-policy-{net}", "SIGNING_POLICY", f"signing-policy-sign-{net}"),
                (f"fsp/voter-registration-{net}", "VOTER_REGISTRATION", f"voter-registration-sign-{net}"),
                (f"fsp/protocol-message-{net}", "PROTOCOL_PAYLOAD", f"protocol-message-sign-{net}"),
                (f"fsp/fastupdate-sign-{net}", "FAST_UPDATE", f"fastupdate-sign-{net}"),
            ):
                callers[_caller] = {"policy_path": _pp}
                fsp_permissions[_pp] = {
                    "message_types": [_mt],
                    "wallet_allowlist": [signing_wallet],
                    "rate": _rate(fsp_rate),
                    "chain_ids": [chain_id],
                }

            # Three EVM-only SUBMIT wallets for FastUpdater.submitUpdates.
            # These are the FAST_UPDATES_ACCOUNTS (submitUpdates tx senders only);
            # they do NOT sign FSP messages and are NOT in fsp_self_submit.
            for i in (1, 2, 3):
                fu_wallet = f"fastupdate-{i}-{net}"
                wc_fu = f"wc/fastupdate-{i}-{net}"
                wallets[fu_wallet] = {"policy_path": wc_fu}
                wallet_constraints[wc_fu] = {
                    "max_aggregate_value_wei_per_day": "0",
                    "rate": _rate(fsp_rate),
                }

                # SUBMIT leg (Leg-2, /v1/sign-transaction → FastUpdater.submitUpdates)
                fu_submit_pp = f"perm/fastupdate-submit-{i}-{net}"
                callers[f"fastupdate-submit-{i}-{net}"] = {"policy_path": fu_submit_pp}
                permissions[fu_submit_pp] = {
                    "contracts": {
                        fast_updater_addr: {
                            "abi": "fast_updater",
                            "chains": [chain_id],
                            "methods": {
                                submit_updates_sig: {
                                    "max_value_wei": "0",
                                    # submitUpdates takes a struct (non-scalar).
                                    "allow_unconstrained_args": True,
                                },
                            },
                        }
                    },
                    "wallet_allowlist": [fu_wallet],
                    "rate": _rate(fsp_rate),
                }
                # EVM-only: NOT added to fsp_self_submit.

            # ftso-price-submit: dedicated submit wallet for Submission.submit1/2/3.
            # EVM-only — NOT in fsp_self_submit.
            price_submit_wallet = f"fsp-submit-{net}"
            wc_price_submit = f"wc/fsp-submit-{net}"
            wallets[price_submit_wallet] = {"policy_path": wc_price_submit}
            wallet_constraints[wc_price_submit] = {
                "max_aggregate_value_wei_per_day": "0",
                "rate": _rate(fsp_rate),
            }
            price_submit_pp = f"perm/ftso-price-submit-{net}"
            callers[f"ftso-price-submit-{net}"] = {"policy_path": price_submit_pp}
            permissions[price_submit_pp] = {
                "contracts": {
                    submission_addr: {
                        "abi": "submission",
                        "chains": [chain_id],
                        "methods": {
                            submit1_sig: {
                                "max_value_wei": "0",
                                "allow_unconstrained_args": True,
                            },
                            submit2_sig: {
                                "max_value_wei": "0",
                                "allow_unconstrained_args": True,
                            },
                            submit3_sig: {
                                "max_value_wei": "0",
                                "allow_unconstrained_args": True,
                            },
                        },
                    }
                },
                "wallet_allowlist": [price_submit_wallet],
                "rate": _rate(fsp_rate),
            }

            # ftso-signature-submit: dedicated submit wallet for Submission.submitSignatures.
            # EVM-only — NOT in fsp_self_submit.
            sig_submit_wallet = f"fsp-sig-submit-{net}"
            wc_sig_submit = f"wc/fsp-sig-submit-{net}"
            wallets[sig_submit_wallet] = {"policy_path": wc_sig_submit}
            wallet_constraints[wc_sig_submit] = {
                "max_aggregate_value_wei_per_day": "0",
                "rate": _rate(fsp_rate),
            }
            sig_submit_pp = f"perm/ftso-signature-submit-{net}"
            callers[f"ftso-signature-submit-{net}"] = {"policy_path": sig_submit_pp}
            permissions[sig_submit_pp] = {
                "contracts": {
                    submission_addr: {
                        "abi": "submission",
                        "chains": [chain_id],
                        "methods": {
                            submitsig_sig: {
                                "max_value_wei": "0",
                                "allow_unconstrained_args": True,
                            },
                        },
                    }
                },
                "wallet_allowlist": [sig_submit_wallet],
                "rate": _rate(fsp_rate),
            }

            # relay-submit: Relay finalization on the SHARED fsp-signing wallet.
            # The system-client FINALIZER submits to Relay with SIGNING_PK (= the
            # fsp-signing wallet), so this is a cross-domain EVM block on the same key
            # that signs FSP messages — admitted only by the bounded carve-out
            # (_FSP_SELF_SUBMIT_SHAPES['relay'] = {relay()}), max_value_wei=0. The
            # finalizer packs its own calldata behind the relay() selector, so the args
            # are non-scalar/raw → allow_unconstrained_args.
            relay_submit_pp = f"perm/relay-submit-{net}"
            callers[f"relay-submit-{net}"] = {"policy_path": relay_submit_pp}
            permissions[relay_submit_pp] = {
                "contracts": {
                    relay_addr: {
                        "abi": "relay",
                        "chains": [chain_id],
                        "methods": {
                            relay_sig: {
                                "max_value_wei": "0",
                                "allow_unconstrained_args": True,
                            },
                        },
                    }
                },
                "wallet_allowlist": [signing_wallet],
                "rate": _rate(fsp_rate),
            }

    policy: dict[str, Any] = {
        "version": 1,
        "callers": callers,
        "wallets": wallets,
        "permissions": permissions,
        "wallet_constraints": wallet_constraints,
    }
    if fsp_permissions:
        policy["fsp_permissions"] = fsp_permissions
    if fsp_self_submit:
        # de-dup while preserving order
        policy["fsp_self_submit"] = list(dict.fromkeys(fsp_self_submit))

    # Additive onboarding (doctrine: adding a network must NEVER remove an existing
    # one). When merge_into is the current policy, union the generated network rules
    # INTO it — every emitted key is network-suffixed, so distinct networks never
    # collide; this ADDS the requested network(s) and leaves all others byte-identical
    # (re-running a network overwrites only its own keys).
    if merge_into is not None and merge_into.strip():
        try:
            existing = yaml.safe_load(merge_into)
        except yaml.YAMLError as exc:
            raise PolicyInitError(f"merge target is not valid YAML: {exc}") from exc
        if existing is None:
            existing = {}
        if not isinstance(existing, dict):
            raise PolicyInitError("merge target is not a policy mapping")
        policy = _merge_policies(existing, policy)

    header = (
        "# Generated by `clifwd policy init`. Operator-controlled private config\n"
        "# (Core invariant #12 — gitignored, never committed). Rename wallets/callers\n"
        "# to taste; create/import each wallet in fwd and mint each caller token,\n"
        "# then run `clifwd policy validate` before `docker compose up -d`.\n"
    )
    body = yaml.safe_dump(policy, sort_keys=False, default_flow_style=False, width=100)
    return header + body
