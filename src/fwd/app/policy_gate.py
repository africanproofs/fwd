"""Policy gate — wraps app/policy_engine.evaluate for the signing path.

Calls the D14 engine once (it decodes + evaluates + increments rate),
maps a DenyDecision to PolicyDenied, and exposes a release helper for
the post-Allow / pre-broadcast-failure path (rate release-on-failure
mirrors the nonce release; D14 / v0.5.0a2 doctrine).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fwd.app.policy_engine import AllowDecision, DenyDecision, evaluate

if TYPE_CHECKING:
    from datetime import datetime

    from fwd.app.sign_transaction import SignTransactionRequest
    from fwd.domain.policy import Policy
    from fwd.infra.abi_registry import AbiRegistry
    from fwd.infra.caller_repo import Caller
    from fwd.infra.rate_repo import RateRepo
    from fwd.infra.wallet_repo import Wallet


class PolicyDenied(Exception):  # noqa: N818
    """403 — policy engine denied the request. Carries the D14 step."""

    def __init__(self, step: int, reason: str) -> None:
        super().__init__(f"policy_denied step={step}: {reason}")
        self.step = step
        self.reason = reason


async def gate(
    *,
    caller: Caller,
    wallet: Wallet,
    request: SignTransactionRequest,
    policy: Policy,
    registry: AbiRegistry,
    rate_repo: RateRepo,
    now: datetime,
) -> AllowDecision:
    """Evaluate; raise PolicyDenied on a DenyDecision; else return Allow."""
    decision = await evaluate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=now,
    )
    if isinstance(decision, DenyDecision):
        raise PolicyDenied(decision.step, decision.reason)
    return decision  # AllowDecision


async def release_rate_after_failure(
    *,
    allow: AllowDecision,
    caller: Caller,
    wallet: Wallet,
    request: SignTransactionRequest,
    policy: Policy,
    rate_repo: RateRepo,
    now: datetime,
) -> None:
    """Undo the engine's step-8/9 rate increments when a request that was
    ALLOWED then fails before broadcast (RPC/Vault/sign). Mirrors the
    nonce release. Keys are re-derived from the AllowDecision + policy
    (no engine change). aggregate_value is NOT touched here — it is only
    ever added on broadcast success via rate_repo.add_committed_value.
    Best-effort: never raises (a failing release must not mask the
    original error).
    """
    try:
        perm = policy.permissions.get(allow.matched_policy_path)
        if perm is None:
            return
        await rate_repo.release_caller(
            caller=caller.name,
            wallet=request.wallet,
            contract=request.to.lower(),
            method=allow.decoded.method_signature,
            rate=perm.rate,
            now=now,
        )
        wb = policy.wallets.get(wallet.name)
        constraint = policy.wallet_constraints.get(wb.policy_path) if wb is not None else None
        await rate_repo.release_wallet(
            wallet=wallet.name,
            constraint=constraint,
            now=now,
        )
    except Exception:  # noqa: BLE001 — release is best-effort
        pass
