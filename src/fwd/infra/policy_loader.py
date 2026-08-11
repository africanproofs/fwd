"""Policy YAML loader and consistency checker — infra module.

Loads policy.yaml from disk, validates it against the Pydantic schema, and
cross-references it against live callers, wallets, and the ABI registry.
See decisions.md D14 for the startup fail-fast mandate.

Checks 1, 2, 3, 4, 5 are all implemented (check 3 landed in v0.5.0a6
after AbiRegistry was extended with the signatures_for(abi_name) accessor).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import yaml
from pydantic import ValidationError

from fwd.domain.fsp_message import MESSAGE_TYPES as _FSP_MESSAGE_TYPES
from fwd.domain.policy import Policy
from fwd.infra.abi_registry import (
    AbiRegistry,  # noqa: TC001 — used at runtime in check_consistency body
)

if TYPE_CHECKING:
    from pathlib import Path

    from fwd.infra.caller_repo import Caller
    from fwd.infra.wallet_repo import Wallet


# The two canonical FlareSystemsManager method signatures that are allowed
# under the fsp_self_submit carve-out (signer pays its own gas — Leg-2 tx).
# These are the only EVM methods that an FSP signing-policy key may appear in
# when also listed in an fsp_permissions allowlist, subject to the full
# constraint set in check_consistency. v1.1.0a6.
_FSP_SELF_SUBMIT_METHODS: frozenset[str] = frozenset(
    {
        "signUptimeVote(uint24,bytes32,(uint8,bytes32,bytes32))",
        "signRewards(uint24,(uint256,uint256)[],bytes32,(uint8,bytes32,bytes32))",
        # Epoch-submit: the system-client VOTER submits signNewSigningPolicy to
        # FlareSystemsManager with SIGNING_PK (= the fsp-signing wallet).
        # The signature arg is a non-scalar tuple; max_value_wei=0. v1.1.0 epoch-submit.
        "signNewSigningPolicy(uint24,bytes32,(uint8,bytes32,bytes32))",
    }
)

# Bounded map of exempt (abi_name → allowed_method_sigs) shapes for the
# fsp_self_submit carve-out. A wallet in fsp_self_submit passes iff EVERY EVM
# permissions block allowlisting it has: abi present in this map AND every
# method in that block is in the abi's allowed-method set AND max_value_wei=="0".
# Extending this map (adding a new abi or a new method to an existing abi) is the
# ONLY way to admit a new cross-domain wallet shape — the negative test enforces
# the bound. v1.1.0a7.
# The Relay finalization method exempt under the carve-out. The system-client
# FINALIZER submits to the Relay contract with cfg.Credentials.SigningPolicyPrivateKey
# (= the fsp-signing wallet), so fsp-signing is cross-domain over Relay as well as
# FlareSystemsManager. The finalizer packs its own calldata behind the relay()
# selector (relayABI.Methods["relay"].ID), so the exempt method sig is relay().
# max_value_wei=0 keeps the carve-out value-bounded. v1.1.0 relay-submit.
_FSP_SELF_SUBMIT_RELAY_METHODS: frozenset[str] = frozenset({"relay()"})

# VoterRegistry method exempt under the carve-out. The system-client VOTER role
# submits registerVoter to VoterRegistry with SIGNING_PK (= the fsp-signing
# wallet). The _signature arg is a non-scalar tuple; max_value_wei=0 keeps the
# carve-out value-bounded. v1.1.0 epoch-submit.
_FSP_SELF_SUBMIT_VOTER_REGISTRY_METHODS: frozenset[str] = frozenset(
    {"registerVoter(address,(uint8,bytes32,bytes32))"}
)

# EntityManager method exempt under the carve-out. The ONE-TIME entity
# registration confirms the signing-policy address by submitting
# confirmSigningPolicyAddressRegistration to EntityManager with SIGNING_PK
# (= the fsp-signing wallet), so fsp-signing is cross-domain over EntityManager
# for the bootstrap. The _voter arg is a SCALAR address pinned to the provider's
# identity in the policy arg-predicate; max_value_wei=0 keeps the carve-out
# value-bounded. Only confirmSigningPolicyAddressRegistration is exempt — the
# submit / submit-signatures confirms run on EVM-only wallets (fsp-submit /
# fsp-sig-submit) that are NOT in fsp_self_submit and so never reach this gate.
# Granted by the revocable `fsp-register` capability (policy_init). v1.1.0 fsp-register.
_FSP_SELF_SUBMIT_ENTITY_MANAGER_METHODS: frozenset[str] = frozenset(
    {"confirmSigningPolicyAddressRegistration(address)"}
)

_FSP_SELF_SUBMIT_SHAPES: dict[str, frozenset[str]] = {
    "flare_systems_manager": _FSP_SELF_SUBMIT_METHODS,
    "relay": _FSP_SELF_SUBMIT_RELAY_METHODS,
    "voter_registry": _FSP_SELF_SUBMIT_VOTER_REGISTRY_METHODS,
    "entity_manager": _FSP_SELF_SUBMIT_ENTITY_MANAGER_METHODS,
}


class PolicyLoadError(Exception):
    """Raised when policy.yaml cannot be loaded or fails schema validation."""


def load_policy(path: Path) -> Policy:
    """Load and validate policy.yaml from *path*.

    Raises PolicyLoadError on:
      - file not found
      - YAML parse error
      - Pydantic ValidationError (schema mismatch)
      - version != 1 (caught by model_post_init as ValidationError)
    """
    if not path.exists():
        raise PolicyLoadError(f"policy file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"YAML parse error in {path}: {exc}") from exc
    try:
        return Policy.model_validate(raw)
    except (ValidationError, ValueError) as exc:
        raise PolicyLoadError(f"policy schema error in {path}: {exc}") from exc


def check_consistency(
    policy: Policy,
    callers: list[Caller],
    wallets: list[Wallet],
    registry: AbiRegistry,
) -> list[str]:
    """Cross-reference policy against live DB state and the ABI registry.

    Returns a list of human-readable error strings; empty list means OK.
    The caller decides whether to abort on errors (startup fail-fast per D14).

    Checks implemented:
      1. Every ACTIVE caller must be declared in policy.callers (keyed by
         caller NAME, per D13 — NOT by policy_path). The caller's stored
         policy_path must match the binding's policy_path (drift detection,
         mirrors policy_engine step 1). The binding's policy_path must
         resolve to a policy.permissions block.
      2. Every permissions.<path>.contracts.<addr>.abi not in registry.abi_names().
      3. Per-signature existence check: for each contract rule whose abi IS known,
         every method signature must exist in registry.signatures_for(abi_name).
         (Landed v0.5.0a6 after AbiRegistry.signatures_for was added.)
      4. Every wallet_allowlist entry not resolvable to policy.wallets or DB wallets.
      5. Every policy.wallets binding whose policy_path is not in
         policy.wallet_constraints.
    """
    errors: list[str] = []

    # Build a set of known wallet names from the DB for check 4.
    db_wallet_names: set[str] = {w.name for w in wallets}
    policy_wallet_names: set[str] = set(policy.wallets.keys())
    known_wallet_names = db_wallet_names | policy_wallet_names

    # Check 1: active callers must be declared in policy.callers, keyed by
    # caller NAME (per D13 — policy.callers is name-keyed; the loader and
    # the evaluator MUST agree on the key space, see policy_engine step 1).
    for caller in callers:
        if caller.revoked_at is not None:
            # Only active callers are checked.
            continue
        binding = policy.callers.get(caller.name)
        if binding is None:
            errors.append(
                f"caller '{caller.name}' policy_path '{caller.policy_path}' not in policy"
            )
            continue
        # Check 1b: caller's stored policy_path must match the binding's
        # policy_path (drift detection; mirrors policy_engine step 1).
        if caller.policy_path != binding.policy_path:
            errors.append(
                f"caller '{caller.name}' policy_path '{caller.policy_path}' "
                f"drifts from policy binding '{binding.policy_path}'"
            )
        # Check 1c: caller binding's policy_path not in policy.permissions,
        # fsp_permissions, or native_transfers.
        if (
            binding.policy_path not in policy.permissions
            and binding.policy_path not in policy.fsp_permissions
            and binding.policy_path not in policy.native_transfers
        ):
            errors.append(
                f"caller '{caller.name}' binding policy_path "
                f"'{binding.policy_path}' not in permissions, fsp_permissions, "
                f"or native_transfers"
            )

    # Check 1d: capability_id uniqueness across CallerBindings. The
    # capability_id is the immutable <consumer>/<network>/<role> join key
    # (ADR-0001 §3); two bindings sharing one breaks the join's integrity.
    # Pure-policy check (no DB/registry needed); name-only bindings (None) skip.
    _seen_capability_id: dict[str, str] = {}
    for cname, cbinding in policy.callers.items():
        cid = cbinding.capability_id
        if cid is None:
            continue
        prior = _seen_capability_id.get(cid)
        if prior is not None:
            errors.append(
                f"capability_id '{cid}' is bound to BOTH caller '{prior}' "
                f"and caller '{cname}' (capability_id must be unique)"
            )
        else:
            _seen_capability_id[cid] = cname

    # Checks 2, 3 (partial), 4: walk all permissions blocks.
    for perm_path, perm in policy.permissions.items():
        for addr, crule in perm.contracts.items():
            # Check 2: ABI name must be registered.
            if crule.abi not in registry.abi_names():
                errors.append(
                    f"permissions '{perm_path}' contract '{addr}' "
                    f"references unknown abi '{crule.abi}'"
                )
            else:
                # Check 3: per-signature existence (only when abi IS known —
                # avoids double-reporting on an unknown-abi contract).
                known_sigs = registry.signatures_for(crule.abi)
                for sig in crule.methods:
                    if sig not in known_sigs:
                        errors.append(
                            f"permission '{perm_path}' contract '{addr}' "
                            f"method '{sig}' not found in abi '{crule.abi}'"
                        )

        # Check 4: wallet_allowlist entries must resolve to known wallets.
        for wallet_name in perm.wallet_allowlist:
            if wallet_name not in known_wallet_names:
                errors.append(f"permission '{perm_path}' allowlists unknown wallet '{wallet_name}'")
            # Check 4b (fail-closed, mirrors policy_engine step 9): a wallet
            # signable via the EVM path MUST have a policy.wallets binding so
            # an aggregate-value constraint applies. Without it the engine
            # denies at step 9 — surface that as a load-time error instead.
            if wallet_name not in policy_wallet_names:
                errors.append(
                    f"permission '{perm_path}' allowlists wallet '{wallet_name}' "
                    f"with no policy.wallets binding (no wallet constraint)"
                )

    # Check 4c: native_transfers wallet_allowlist entries must resolve to known
    # wallets (mirrors Check 4 for the EVM permissions path).
    for nt_path, nt_rule in policy.native_transfers.items():
        for wallet_name in nt_rule.wallet_allowlist:
            if wallet_name not in known_wallet_names:
                errors.append(
                    f"native_transfers '{nt_path}' allowlists unknown wallet '{wallet_name}'"
                )

    # Check 5: policy.wallets bindings must point to wallet_constraints keys.
    for wname, wbinding in policy.wallets.items():
        if wbinding.policy_path not in policy.wallet_constraints:
            errors.append(
                f"wallet '{wname}' policy_path '{wbinding.policy_path}' "
                f"not in wallet_constraints"
            )

    # FSP permission validation + address-level cross-domain segmentation.
    # Derived from the domain's single source of truth — never hand-maintained.
    _valid_fsp_types = _FSP_MESSAGE_TYPES
    name_to_addr = {w.name: w.address.lower() for w in wallets}

    for fperm_path, fperm in policy.fsp_permissions.items():
        if fperm_path in policy.permissions:
            errors.append(
                f"policy_path '{fperm_path}' is in BOTH permissions and "
                f"fsp_permissions (cross-domain key reuse forbidden)"
            )
        if not fperm.message_types:
            errors.append(f"fsp_permissions '{fperm_path}' has empty message_types")
        for mt in fperm.message_types:
            if mt not in _valid_fsp_types:
                errors.append(f"fsp_permissions '{fperm_path}' unknown message_type '{mt}'")
        for wname in fperm.wallet_allowlist:
            if wname not in known_wallet_names:
                errors.append(f"fsp_permissions '{fperm_path}' allowlists unknown wallet '{wname}'")

    evm_addrs: set[str] = set()
    for perm in policy.permissions.values():
        for wname in perm.wallet_allowlist:
            a = name_to_addr.get(wname)
            if a is not None:
                evm_addrs.add(a)
    fsp_addrs: set[str] = set()
    for fperm in policy.fsp_permissions.values():
        for wname in fperm.wallet_allowlist:
            a = name_to_addr.get(wname)
            if a is not None:
                fsp_addrs.add(a)
    # v1.1.0a6 bounded carve-out: an explicitly opted-in FSP signing-policy
    # wallet may be in BOTH domains iff its EVM authority is provably the
    # zero-value FlareSystemsManager signUptimeVote/signRewards path only.
    exempt_addrs: set[str] = set()
    fsp_allowlisted_names = {
        wn for fp in policy.fsp_permissions.values() for wn in fp.wallet_allowlist
    }
    for wname in policy.fsp_self_submit:
        if wname not in known_wallet_names:
            errors.append(f"fsp_self_submit names unknown wallet '{wname}'")
            continue
        if wname not in fsp_allowlisted_names:
            errors.append(
                f"fsp_self_submit wallet '{wname}' is not in any "
                f"fsp_permissions allowlist (meaningless carve-out)"
            )
            continue
        # Every permissions block that allowlists this wallet MUST match one of
        # the bounded exempt shapes in _FSP_SELF_SUBMIT_SHAPES, or the carve-out
        # is refused. A block matches iff: (a) its abi is in the shapes map,
        # (b) every method sig in the block is in that abi's allowed-method set,
        # and (c) every method rule has max_value_wei == "0".
        ok = True
        appeared = False
        for _pp, perm in policy.permissions.items():
            if wname not in perm.wallet_allowlist:
                continue
            appeared = True
            for _caddr, crule in perm.contracts.items():
                allowed_methods = _FSP_SELF_SUBMIT_SHAPES.get(crule.abi)
                if allowed_methods is None:
                    # ABI not in the exempt map — not an allowed cross-domain shape.
                    ok = False
                    continue
                for msig, mrule in crule.methods.items():
                    if msig not in allowed_methods:
                        ok = False
                    if str(mrule.max_value_wei) != "0":
                        ok = False
        if not appeared:
            errors.append(
                f"fsp_self_submit wallet '{wname}' is not in any EVM "
                f"permissions allowlist (carve-out declared but unused)"
            )
            continue
        if not ok:
            errors.append(
                f"fsp_self_submit wallet '{wname}' is allowlisted in an EVM "
                f"permissions block that is NOT the constrained "
                f"FlareSystemsManager signUptimeVote/signRewards "
                f"max_value_wei=0 self-submit shape — carve-out refused"
            )
            continue
        a = name_to_addr.get(wname)
        if a is not None:
            exempt_addrs.add(a)

    for shared in sorted((evm_addrs & fsp_addrs) - exempt_addrs):
        errors.append(
            f"address {shared} is reachable from BOTH an EVM permissions "
            f"allowlist and an fsp_permissions allowlist (key-domain "
            f"segmentation violation — one key must not sign in both domains)"
        )

    return errors


def policy_path_exists(policy: Policy, policy_path: str, kind: str) -> bool:
    """Return True iff *policy_path* is a valid key for the given *kind*.

    kind='caller': True iff policy_path is a key in policy.permissions,
      policy.fsp_permissions, or policy.native_transfers (a caller binding's
      policy_path must resolve to one of the three permission-block kinds;
      mirrors policy_loader.check_consistency Check 1c and policy_engine).
    kind='wallet': True iff policy_path is a key in policy.wallet_constraints.

    Used by the admin endpoints (v0.5.0a6) to validate policy_path on
    POST /v1/admin/callers and POST /v1/admin/wallets before inserting.
    """
    if kind == "caller":
        return (
            policy_path in policy.permissions
            or policy_path in policy.fsp_permissions
            or policy_path in policy.native_transfers
        )
    if kind == "wallet":
        return policy_path in policy.wallet_constraints
    return False
