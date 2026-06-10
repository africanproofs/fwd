"""Granted-capabilities read use case (admin-only) — the doctor 'fwd=granted' leg.

The granted set is derived from the LIVE POLICY's `CallerBinding`s
(`app.state.policy`), NOT from the caller-create audit trail. This is
load-bearing: a *hand-edited* policy block (a `CallerBinding` with a
`capability_id` added directly, never via `capability grant`) is the doctor's
worst drift ("ungoverned grant") — it is in the live policy but NOT in the audit
log, so reading the live policy is the only way to surface it (ADR-0001 §6).

Each policy `CallerBinding` with a non-null `capability_id` is joined with its
caller row (by name) for status/timestamps. Pure read — zero custody mutation;
NEVER an api_key value or hash. Sorted by `capability_id` (R6) so the doctor
diff is byte-stable across re-runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fwd.domain.policy import Policy
    from fwd.infra.caller_repo import CallerRepo


@dataclass(frozen=True)
class GrantedCapability:
    """One granted capability_id, joined with its caller's status.

    `status` is 'active' | 'revoked'. A policy binding with NO matching caller
    row (granted in policy, no token minted) is reported 'active' with
    `granted_at=None` (the None marks the absence of a mint).
    """

    capability_id: str
    caller_name: str
    policy_path: str
    status: str
    granted_at: str | None
    revoked_at: str | None


async def list_capabilities(
    policy: Policy | None, caller_repo: CallerRepo
) -> list[GrantedCapability]:
    """Return the capability_ids the LIVE POLICY governs, joined with caller status.

    Read-only. Returns [] when no policy is loaded. Sorted by `capability_id`.
    """
    if policy is None:
        return []

    callers = await caller_repo.list_all(include_revoked=True)
    by_name = {c.name: c for c in callers}

    out: list[GrantedCapability] = []
    for name, binding in policy.callers.items():
        cid = binding.capability_id
        if cid is None:
            continue  # name-only grant — not part of the granted-capability set
        caller = by_name.get(name)
        if caller is None:
            status, granted_at, revoked_at = "active", None, None
        elif caller.revoked_at is not None:
            status = "revoked"
            granted_at = caller.created_at.isoformat()
            revoked_at = caller.revoked_at.isoformat()
        else:
            status = "active"
            granted_at = caller.created_at.isoformat()
            revoked_at = None
        out.append(
            GrantedCapability(
                capability_id=cid,
                caller_name=name,
                policy_path=binding.policy_path,
                status=status,
                granted_at=granted_at,
                revoked_at=revoked_at,
            )
        )

    out.sort(key=lambda g: g.capability_id)
    return out
