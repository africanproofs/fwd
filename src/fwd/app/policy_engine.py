"""Policy engine — app layer orchestrator.

Implements the D14 10-step evaluation order for signing requests.
Takes a loaded Policy, ABI registry, RateRepo, Caller, Wallet, and
SignTransactionRequest; returns AllowDecision or DenyDecision.

Default-deny: the ONLY exit that returns Allow is step 10. Every other
evaluation path returns a DenyDecision. Unexpected exceptions are caught
and converted to Deny(step=0) — fail closed, never raise.

See decisions.md D14 for the authoritative evaluation order and D13 for
the caller-keyed policy ownership model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from fwd.domain.intent import DecodedIntent, decode_intent, has_nonscalar_args

if TYPE_CHECKING:
    from datetime import datetime

    from fwd.app.sign_transaction import SignTransactionRequest
    from fwd.domain.policy import NativeTransferBlock, Policy
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


# Synthetic method label for native (value-only) transfers — the rate-bucket
# "method" key and the audited intent signature (there is no ABI method).
_NT_METHOD = "nativeTransfer(address,uint256)"


async def evaluate(
    *,
    caller: Caller,
    wallet: Wallet,
    request: SignTransactionRequest,
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
    request: SignTransactionRequest,
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

    # Native-transfer branch: an empty-calldata request (value-only transfer) is
    # gated by a native_transfers rule, NOT the ABI decode path. If the caller's
    # policy_path names a native_transfers block, evaluate here and return.
    # (Default-deny preserved: no such block ⇒ fall through to the ABI path,
    # whose Step 3 denies empty calldata as before.)
    data = request.data
    hex_data = data[2:] if data.startswith(("0x", "0X")) else data
    is_value_only = len(hex_data) == 0
    nt_rule = policy.native_transfers.get(binding.policy_path)
    if nt_rule is not None:
        if not is_value_only:
            return DenyDecision(
                step=2, reason="native_transfers caller may sign value-only transfers only"
            )
        return await _evaluate_native_transfer(
            request=request,
            caller=caller,
            wallet=wallet,
            policy=policy,
            rule=nt_rule,
            rate_repo=rate_repo,
            now=now,
        )
    if is_value_only:
        return DenyDecision(step=3, reason="calldata too short")

    perm = policy.permissions.get(binding.policy_path)
    if perm is None:
        return DenyDecision(
            step=1,
            reason=f"caller policy_path '{binding.policy_path}' has no permissions block",
        )

    # Step 2: Resolve contract rule by request.to (case-insensitive) AND chain.
    # A contract address is not chain-unique, so the request.chain must match
    # one of the rule's declared chains — otherwise the same address on a
    # different network would be reachable under this rule (cross-chain).
    to_lower = request.to.lower()
    crule = None
    for addr, cr in perm.contracts.items():
        if addr.lower() == to_lower:
            crule = cr
            break
    if crule is None:
        return DenyDecision(step=2, reason="contract not permitted for caller")
    if request.chain not in crule.chains:
        return DenyDecision(
            step=2,
            reason=f"contract not permitted on chain {request.chain}",
        )

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

    # Step 4b: Fail closed on non-scalar (array/tuple) top-level args. Such args
    # are decoded but projected out of decoded.args (B1) and cannot be matched
    # by arg_predicates — so they are unconstrainable. Refuse unless the method
    # rule explicitly accepts that via allow_unconstrained_args.
    if has_nonscalar_args(abi_method.abi_fn_entry) and not mrule.allow_unconstrained_args:
        return DenyDecision(
            step=4,
            reason="method has unconstrainable non-scalar args; "
            "set allow_unconstrained_args: true to permit",
        )

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
    # Fail closed: a wallet that may be signed for MUST have a policy.wallets
    # binding resolving to a wallet_constraints block. Absent it, there is no
    # aggregate-value cap — so deny rather than sign unconstrained. The step-8
    # caller increment is released first (mirrors the wallet_ok=False path).
    wb = policy.wallets.get(wallet.name)
    if wb is None:
        await rate_repo.release_caller(
            caller=caller.name,
            wallet=request.wallet,
            contract=to_lower,
            method=decoded.method_signature,
            rate=perm.rate,
            now=now,
        )
        return DenyDecision(step=9, reason="wallet has no constraint binding")
    constraint = policy.wallet_constraints.get(wb.policy_path)
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


async def _evaluate_native_transfer(
    *,
    request: SignTransactionRequest,
    caller: Caller,
    wallet: Wallet,
    policy: Policy,
    rule: NativeTransferBlock,
    rate_repo: RateRepo,
    now: datetime,
) -> AllowDecision | DenyDecision:
    # chain
    if request.chain not in rule.chains:
        return DenyDecision(step=2, reason=f"native transfer not permitted on chain {request.chain}")
    # recipient allowlist (case-insensitive)
    to_lower = request.to.lower()
    if to_lower not in {r.lower() for r in rule.recipient_allowlist}:
        return DenyDecision(step=2, reason="recipient not in native_transfers allowlist")
    # per-tx value cap; value must be > 0 (a zero-value empty-calldata tx funds nothing)
    try:
        max_value = int(rule.max_value_wei)
        request_value = int(request.value_wei)
    except (ValueError, TypeError):
        return DenyDecision(step=5, reason="bad value_wei")
    if request_value <= 0:
        return DenyDecision(step=5, reason="native transfer value must be > 0")
    if request_value > max_value:
        return DenyDecision(step=5, reason="max_value_wei exceeded")
    # wallet allowlist
    if request.wallet not in rule.wallet_allowlist:
        return DenyDecision(step=7, reason="wallet not in native_transfers allowlist")
    # Step 8: per-caller rate (reuse the same limiter as the ABI path; the
    # synthesized method label doubles as the rate-bucket "method" key and the
    # recipient as "contract" — mirrors the ABI path's Step 8 call site).
    if rule.rate is not None:
        caller_ok = await rate_repo.check_and_increment_caller(
            caller=caller.name,
            wallet=request.wallet,
            contract=to_lower,
            method=_NT_METHOD,
            rate=rule.rate,
            now=now,
        )
        if not caller_ok:
            return DenyDecision(step=8, reason="native transfer caller rate limit exceeded")
    # Step 9: per-wallet aggregate + rate constraint. This is THE value-moving
    # path, so the wallet's daily aggregate-value cap MUST bind here exactly as
    # the ABI path (Step 9); fail closed if there is no constraint binding. On a
    # deny after Step 8 incremented, release the caller increment first (mirrors
    # the ABI path).
    wb = policy.wallets.get(wallet.name)
    if wb is None:
        if rule.rate is not None:
            await rate_repo.release_caller(
                caller=caller.name,
                wallet=request.wallet,
                contract=to_lower,
                method=_NT_METHOD,
                rate=rule.rate,
                now=now,
            )
        return DenyDecision(step=9, reason="wallet has no constraint binding")
    constraint = policy.wallet_constraints.get(wb.policy_path)
    wallet_ok = await rate_repo.check_and_increment_wallet(
        wallet=wallet.name,
        constraint=constraint,
        value_wei=request_value,
        now=now,
    )
    if not wallet_ok:
        if rule.rate is not None:
            await rate_repo.release_caller(
                caller=caller.name,
                wallet=request.wallet,
                contract=to_lower,
                method=_NT_METHOD,
                rate=rule.rate,
                now=now,
            )
        return DenyDecision(step=9, reason="wallet constraint exceeded")
    # Synthesize the decoded intent for the audit + response (Core #3/#5): the
    # intent IS the transfer. No opaque bytes — to + value fully specify it.
    decoded = DecodedIntent(
        contract=to_lower,
        method_signature=_NT_METHOD,
        selector="0x",
        args={"to": to_lower, "value": request_value},
    )
    return AllowDecision(decoded=decoded, matched_policy_path=caller.policy_path)
