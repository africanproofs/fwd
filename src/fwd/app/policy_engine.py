"""Policy engine — app layer orchestrator.

Implements the D14 10-step evaluation order for signing requests.
Takes a loaded Policy, ABI registry, RateRepo, Caller, Wallet, and
SignAndSendRequest; returns AllowDecision or DenyDecision.

Default-deny: the ONLY exit that returns Allow is step 10. Every other
evaluation path returns a DenyDecision. Unexpected exceptions are caught
and converted to Deny(step=0) — fail closed, never raise.

See decisions.md D14 for the authoritative evaluation order and D13 for
the caller-keyed policy ownership model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from fwd.domain.intent import DecodedIntent, decode_intent

if TYPE_CHECKING:
    from datetime import datetime

    from fwd.app.sign_and_send import SignAndSendRequest
    from fwd.domain.policy import Policy
    from fwd.infra.abi_registry import AbiRegistry
    from fwd.infra.caller_repo import Caller
    from fwd.infra.rate_repo import RateRepo
    from fwd.infra.wallet_repo import Wallet


@dataclass(frozen=True)
class AllowDecision:
    """The request passed all 10 evaluation steps and is permitted."""

    decoded: DecodedIntent
    matched_policy_path: str


@dataclass(frozen=True)
class DenyDecision:
    """The request was denied at a specific evaluation step."""

    step: int  # 0 = unexpected error; 1..9 = the failing D14 step
    reason: str  # human-readable, e.g. "policy_denied step=5: max_value_wei exceeded"


async def evaluate(
    *,
    caller: Caller,
    wallet: Wallet,
    request: SignAndSendRequest,
    policy: Policy,
    registry: AbiRegistry,
    rate_repo: RateRepo,
    now: datetime,
) -> AllowDecision | DenyDecision:
    """Evaluate a signing request against policy.

    Implements the D14 10-step evaluation order exactly. Returns at the
    first failing step. Wraps the entire body in try/except to guarantee
    no exception escapes (default-deny on unexpected errors).
    """
    try:
        return await _evaluate_inner(
            caller=caller,
            wallet=wallet,
            request=request,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            now=now,
        )
    except Exception as exc:  # noqa: BLE001
        return DenyDecision(step=0, reason=f"evaluation error: {exc}")


async def _evaluate_inner(
    *,
    caller: Caller,
    wallet: Wallet,
    request: SignAndSendRequest,
    policy: Policy,
    registry: AbiRegistry,
    rate_repo: RateRepo,
    now: datetime,
) -> AllowDecision | DenyDecision:
    """Inner evaluation — may raise; wrapped by evaluate()."""

    # Step 1: Resolve caller binding and permission block.
    binding = policy.callers.get(caller.name)
    if binding is None:
        return DenyDecision(step=1, reason="caller not in policy")

    # Cross-check: caller.policy_path must match the binding's policy_path.
    if caller.policy_path != binding.policy_path:
        return DenyDecision(step=1, reason="caller policy_path drift")

    perm = policy.permissions.get(binding.policy_path)
    if perm is None:
        return DenyDecision(
            step=1,
            reason=f"caller policy_path '{binding.policy_path}' has no permissions block",
        )

    # Step 2: Resolve contract rule by request.to (case-insensitive).
    to_lower = request.to.lower()
    crule = None
    for addr, cr in perm.contracts.items():
        if addr.lower() == to_lower:
            crule = cr
            break
    if crule is None:
        return DenyDecision(step=2, reason="contract not permitted for caller")

    # Step 3: Parse calldata and decode intent.
    data = request.data
    hex_data = data[2:] if data.startswith(("0x", "0X")) else data

    if len(hex_data) % 2 != 0:
        return DenyDecision(step=3, reason="calldata not hex: odd length")
    try:
        calldata = bytes.fromhex(hex_data)
    except ValueError:
        return DenyDecision(step=3, reason="calldata not hex: invalid characters")

    if len(calldata) < 4:
        return DenyDecision(step=3, reason="calldata too short")

    selector = "0x" + calldata[:4].hex()
    abi_method = registry.lookup(crule.abi, selector)
    if abi_method is None:
        return DenyDecision(step=3, reason="unknown selector for abi")

    decoded = decode_intent(request.to, calldata, abi_method.abi_fn_entry)
    if decoded is None:
        return DenyDecision(step=3, reason="intent decode failed")

    # Step 4: Resolve method rule by decoded signature.
    mrule = crule.methods.get(decoded.method_signature)
    if mrule is None:
        return DenyDecision(step=4, reason="method signature not permitted")

    # Step 5: Check max_value_wei.
    try:
        max_value = int(mrule.max_value_wei)
    except (ValueError, TypeError):
        return DenyDecision(step=5, reason="bad value_wei: max_value_wei is not decimal")
    try:
        request_value = int(request.value_wei)
    except (ValueError, TypeError):
        return DenyDecision(step=5, reason="bad value_wei: request value_wei is not decimal")
    if request_value > max_value:
        return DenyDecision(step=5, reason="max_value_wei exceeded")

    # Step 6: Evaluate arg_predicates.
    for pname, pval in mrule.arg_predicates.items():
        # String sentinel "any" — unconditionally pass this predicate.
        if pval == "any":
            continue

        if pname not in decoded.args:
            return DenyDecision(step=6, reason=f"arg '{pname}' not in decoded scalars")

        aval = decoded.args[pname]

        # Coerce predicate value against the actual Python type of the decoded arg.
        if isinstance(aval, bool):
            # Handle bool before int (bool is a subclass of int in Python).
            pval_bool = pval if isinstance(pval, bool) else str(pval).lower() in {"true", "1"}
            if pval_bool != aval:
                return DenyDecision(step=6, reason=f"arg '{pname}' predicate mismatch")
        elif isinstance(aval, int):
            try:
                pval_int = int(str(pval))
            except (ValueError, TypeError):
                return DenyDecision(step=6, reason=f"arg '{pname}' predicate not an int")
            if pval_int != aval:
                return DenyDecision(step=6, reason=f"arg '{pname}' predicate mismatch")
        elif isinstance(aval, str) and aval.startswith("0x") and len(aval) == 42:
            # Ethereum address — case-insensitive comparison.
            if str(pval).lower() != aval.lower():
                return DenyDecision(step=6, reason=f"arg '{pname}' predicate mismatch")
        else:
            # Plain string — exact match.
            if str(pval) != aval:
                return DenyDecision(step=6, reason=f"arg '{pname}' predicate mismatch")

    # Step 7: Check wallet allowlist.
    if request.wallet not in perm.wallet_allowlist:
        return DenyDecision(step=7, reason="wallet not in caller allowlist")

    # Step 8: Check and increment caller rate.
    caller_ok = await rate_repo.check_and_increment_caller(
        caller=caller.name,
        wallet=request.wallet,
        contract=to_lower,
        method=decoded.method_signature,
        rate=perm.rate,
        now=now,
    )
    if not caller_ok:
        return DenyDecision(step=8, reason="caller rate limit exceeded")

    # Step 9: Check wallet constraint (aggregate + rate).
    wb = policy.wallets.get(wallet.name)
    constraint = policy.wallet_constraints.get(wb.policy_path) if wb is not None else None
    wallet_ok = await rate_repo.check_and_increment_wallet(
        wallet=wallet.name,
        constraint=constraint,
        value_wei=request_value,
        now=now,
    )
    if not wallet_ok:
        # Undo step 8's increment before returning deny.
        await rate_repo.release_caller(
            caller=caller.name,
            wallet=request.wallet,
            contract=to_lower,
            method=decoded.method_signature,
            rate=perm.rate,
            now=now,
        )
        return DenyDecision(step=9, reason="wallet constraint exceeded")

    # Step 10: All checks passed — allow.
    return AllowDecision(decoded=decoded, matched_policy_path=binding.policy_path)
