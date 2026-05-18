"""FSP policy evaluation + gate (parallel to policy_engine/policy_gate).

A small, FSP-shaped authorization path. Default-deny: the ONLY non-deny exit
is the final step. Reuses DenyDecision and PolicyDenied (no new error types).
Address-level cross-domain key segmentation is enforced comprehensively at
startup by policy_loader.check_consistency (sees all wallets); the runtime
guard here is the cheap policy_path-disjointness belt-and-suspenders.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fwd.app.policy_engine import DenyDecision
from fwd.app.policy_gate import PolicyDenied

if TYPE_CHECKING:
    from datetime import datetime

    from fwd.app.sign_fsp_message import SignFspMessageRequest
    from fwd.domain.policy import Policy
    from fwd.infra.caller_repo import Caller
    from fwd.infra.rate_repo import RateRepo


@dataclass(frozen=True)
class FspAllowDecision:
    """FSP request passed all checks. Carries the exact rate-release key."""

    caller: str
    wallet: str
    message_type: str
    matched_policy_path: str
    rate: object | None  # RateLimit | None (avoid runtime import)


async def evaluate_fsp(
    *,
    caller: Caller,
    request: SignFspMessageRequest,
    policy: Policy,
    rate_repo: RateRepo,
    now: datetime,
) -> FspAllowDecision | DenyDecision:
    """FSP authorization. Wrapped fail-closed (any exception -> Deny step 0)."""
    try:
        binding = policy.callers.get(caller.name)
        if binding is None:
            return DenyDecision(step=1, reason="caller not in policy")
        if caller.policy_path != binding.policy_path:
            return DenyDecision(step=1, reason="caller policy_path drift")
        perm = policy.fsp_permissions.get(binding.policy_path)
        if perm is None:
            return DenyDecision(
                step=2,
                reason=f"caller policy_path '{binding.policy_path}' has no fsp_permissions block",
            )
        # Belt-and-suspenders cross-domain guard (loader is the comprehensive
        # address-level gate; this is the cheap policy-only runtime check).
        if binding.policy_path in policy.permissions:
            return DenyDecision(
                step=3,
                reason="policy_path is also an EVM permissions block (cross-domain forbidden)",
            )
        if request.message_type not in perm.message_types:
            return DenyDecision(step=4, reason="message_type not permitted")
        if request.wallet not in perm.wallet_allowlist:
            return DenyDecision(step=5, reason="wallet not in fsp allowlist")
        ok = await rate_repo.check_and_increment_fsp_caller(
            caller=caller.name,
            wallet=request.wallet,
            message_type=request.message_type,
            rate=perm.rate,
            now=now,
        )
        if not ok:
            return DenyDecision(step=6, reason="fsp caller rate limit exceeded")
        return FspAllowDecision(
            caller=caller.name,
            wallet=request.wallet,
            message_type=request.message_type,
            matched_policy_path=binding.policy_path,
            rate=perm.rate,
        )
    except Exception as exc:  # noqa: BLE001 — fail closed
        return DenyDecision(step=0, reason=f"fsp evaluation error: {exc}")


async def fsp_gate(
    *,
    caller: Caller,
    request: SignFspMessageRequest,
    policy: Policy,
    rate_repo: RateRepo,
    now: datetime,
) -> FspAllowDecision:
    """Evaluate; raise PolicyDenied on a DenyDecision; else return Allow."""
    decision = await evaluate_fsp(
        caller=caller, request=request, policy=policy, rate_repo=rate_repo, now=now
    )
    if isinstance(decision, DenyDecision):
        raise PolicyDenied(decision.step, decision.reason)
    return decision


async def release_fsp_rate_after_failure(
    *,
    allow: FspAllowDecision,
    rate_repo: RateRepo,
    now: datetime,
) -> None:
    """Undo the evaluate_fsp rate increment when an ALLOWED request then
    fails before completion (sign/decrypt). Best-effort; never raises."""
    with contextlib.suppress(Exception):
        await rate_repo.release_fsp_caller(
            caller=allow.caller,
            wallet=allow.wallet,
            message_type=allow.message_type,
            rate=allow.rate,  # type: ignore[arg-type]
            now=now,
        )
