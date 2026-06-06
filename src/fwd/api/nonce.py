"""Admin nonce endpoints.

POST /v1/admin/nonce-init  — seed a (wallet, chain) nonce row (idempotent guard).
POST /v1/admin/nonce-sync  — bounded-monotonic advance of fwd's nonce view to chain truth.
GET  /v1/admin/nonce/holes — surface orphaned pending reservations for operator review.

Seeds the nonces row so a (wallet, chain) can sign. fwd is zero-egress and
never probes the chain; the operator provides the initial on-chain nonce.
Idempotent guard: 409 if already initialized. 404 if the wallet does
not exist. Writes a D16 audit row on the shared AdminScope session; the
forensic row on a refusal is committed before the HTTPException propagates
(Core invariant #5 / #19).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from fwd.api.admin_auth import admin_required
from fwd.app.dependencies import (
    AdminScopeCM,
    NonceRepoCM,
    NonceWalletNotFoundError,
    TransactionRepoCM,
    _canonical_json,
    get_admin_scope,
    get_nonce_repo,
    get_transaction_repo,
)
from fwd.settings import get_settings

router = APIRouter()


class NonceInitBody(BaseModel):
    wallet: str = Field(..., min_length=1, max_length=64)
    chain: int = Field(..., ge=1)
    starting_nonce: int = Field(..., ge=0)
    force: bool = Field(False)
    force_with_in_flight: bool = Field(
        False,
        description=(
            "When force=true and in-flight (pending/submitted) nonces exist, "
            "set this to true to override the in-flight guard. Default False "
            "causes a 409 to protect against nonce collisions."
        ),
    )


class NonceInitResponse(BaseModel):
    wallet: str
    chain: int
    next_nonce: int


def _req_json(body: NonceInitBody) -> str:
    return _canonical_json(
        {
            "wallet": body.wallet,
            "chain": body.chain,
            "starting_nonce": body.starting_nonce,
            "force": body.force,
            "force_with_in_flight": body.force_with_in_flight,
        }
    )


@router.post(
    "/v1/admin/nonce-init",
    response_model=NonceInitResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[admin_required],
)
async def post_nonce_init(
    body: NonceInitBody,
    admin_scope_cm: AdminScopeCM = Depends(get_admin_scope),  # noqa: B008
) -> NonceInitResponse:
    async with admin_scope_cm as scope:
        existing = await scope.nonce_repo.get(body.wallet, body.chain, missing_ok=True)
        if existing is not None and not body.force:
            await scope.audit_repo.append(
                action="nonce-init",
                decision="denied",
                caller=None,
                request_json=_req_json(body),
                decision_reason="already_initialized",
                outcome=_canonical_json({"next_nonce": existing.next_nonce}),
            )
            await scope.audit_repo.commit()  # survive session_scope rollback (Core #5/#19)
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "nonce_already_initialized",
                    "message": (
                        f"(wallet={body.wallet}, chain={body.chain}) already "
                        f"initialized at next_nonce={existing.next_nonce}"
                    ),
                },
            )
        # Guard: when force=true, refuse if in-flight nonces exist unless the
        # caller explicitly acknowledges the risk with force_with_in_flight=true.
        if body.force and existing is not None and not body.force_with_in_flight:
            in_flight = await scope.tx_repo.count_in_flight(body.wallet, body.chain)
            if in_flight > 0:
                await scope.audit_repo.append(
                    action="nonce-init",
                    decision="denied",
                    caller=None,
                    request_json=_req_json(body),
                    decision_reason=f"in_flight_nonces:{in_flight}",
                )
                await scope.audit_repo.commit()  # Core #5/#19
                raise HTTPException(
                    status_code=409,
                    detail={
                        "error": "in_flight_nonces",
                        "message": (
                            f"{in_flight} in-flight nonce(s) exist for "
                            f"(wallet={body.wallet}, chain={body.chain}); "
                            "use force_with_in_flight=true to override"
                        ),
                    },
                )

        try:
            row = await scope.nonce_repo.init_for_wallet(
                body.wallet, body.chain, body.starting_nonce, force=body.force
            )
        except NonceWalletNotFoundError as exc:
            await scope.audit_repo.append(
                action="nonce-init",
                decision="denied",
                caller=None,
                request_json=_req_json(body),
                decision_reason="wallet_not_found",
                outcome=None,
            )
            await scope.audit_repo.commit()  # survive session_scope rollback (Core #5/#19)
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "wallet_not_found",
                    "message": f"wallet '{body.wallet}' not found",
                },
            ) from exc
        if existing is not None:
            # Force-overwrite path: approved with before→after outcome (sensitive, Core #5).
            await scope.audit_repo.append(
                action="nonce-init",
                decision="approved",
                caller=None,
                request_json=_req_json(body),
                decision_reason="force_overwrite",
                outcome=_canonical_json({"from": existing.next_nonce, "to": row.next_nonce}),
            )
        else:
            # Create path: approved with next_nonce outcome.
            await scope.audit_repo.append(
                action="nonce-init",
                decision="approved",
                caller=None,
                request_json=_req_json(body),
                decision_reason=None,
                outcome=_canonical_json({"next_nonce": row.next_nonce}),
            )
        # Approved path: no explicit commit — AdminScopeCM.__aexit__ commits the
        # shared session once (seed/overwrite + audit row atomic under one BEGIN IMMEDIATE).
    return NonceInitResponse(wallet=row.wallet, chain=row.chain, next_nonce=row.next_nonce)


# ---------------------------------------------------------------------------
# POST /v1/admin/nonce-sync
# ---------------------------------------------------------------------------


class NonceSyncBody(BaseModel):
    wallet: str = Field(..., min_length=1, max_length=64)
    chain: int = Field(..., ge=1)
    on_chain_count: int = Field(..., ge=0)


class NonceSyncResponse(BaseModel):
    wallet: str
    chain: int
    from_nonce: int
    to_nonce: int
    status: str  # "in_sync" | "advanced"


@router.post(
    "/v1/admin/nonce-sync",
    response_model=NonceSyncResponse,
    dependencies=[admin_required],
)
async def post_nonce_sync(
    body: NonceSyncBody,
    admin_scope_cm: AdminScopeCM = Depends(get_admin_scope),  # noqa: B008
) -> NonceSyncResponse:
    """Bounded-monotonic advance of fwd's nonce view to chain truth.

    The operator/an egressing client supplies the on-chain tx count.
    fwd cannot self-probe (zero-egress). The advance is bounded by
    FWD_NONCE_SYNC_MAX_ADVANCE to prevent accidental large jumps.
    Core invariant #5/#19: forensic audit rows committed before raising.
    """
    s = get_settings()

    async with admin_scope_cm as scope:
        row = await scope.nonce_repo.get(body.wallet, body.chain, missing_ok=True)
        if row is None:
            req_json = _canonical_json(
                {"wallet": body.wallet, "chain": body.chain, "on_chain_count": body.on_chain_count}
            )
            await scope.audit_repo.append(
                action="nonce-sync",
                decision="denied",
                caller=None,
                request_json=req_json,
                decision_reason="nonce_not_initialized",
            )
            await scope.audit_repo.commit()  # Core #5/#19
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "nonce_not_initialized",
                    "message": (
                        f"(wallet={body.wallet}, chain={body.chain}) has no nonce row; "
                        "call POST /v1/admin/nonce-init first"
                    ),
                },
            )

        cur = row.next_nonce
        req_json = _canonical_json(
            {"wallet": body.wallet, "chain": body.chain, "on_chain_count": body.on_chain_count}
        )

        if body.on_chain_count == cur:
            # In sync — no-op.
            await scope.audit_repo.append(
                action="nonce-sync",
                decision="approved",
                caller=None,
                request_json=req_json,
                decision_reason="in_sync",
                outcome=_canonical_json({"from": cur, "to": cur}),
            )
            return NonceSyncResponse(
                wallet=body.wallet,
                chain=body.chain,
                from_nonce=cur,
                to_nonce=cur,
                status="in_sync",
            )

        max_advance = s.fwd_nonce_sync_max_advance
        if body.on_chain_count < cur or body.on_chain_count > cur + max_advance:
            await scope.audit_repo.append(
                action="nonce-sync",
                decision="denied",
                caller=None,
                request_json=req_json,
                decision_reason=(
                    f"nonce_sync_out_of_bounds:cur={cur}"
                    f",requested={body.on_chain_count}"
                    f",max_advance={max_advance}"
                ),
            )
            await scope.audit_repo.commit()  # Core #5/#19
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "nonce_sync_out_of_bounds",
                    "message": (
                        f"on_chain_count={body.on_chain_count} is outside "
                        f"allowed range [{cur}, {cur + max_advance}]; "
                        "a large jump or rewind requires deliberate operator action"
                    ),
                },
            )

        # Bounded advance — heal the gap.
        await scope.nonce_repo.set_next_nonce(body.wallet, body.chain, body.on_chain_count)
        await scope.audit_repo.append(
            action="nonce-sync",
            decision="approved",
            caller=None,
            request_json=req_json,
            outcome=_canonical_json({"from": cur, "to": body.on_chain_count}),
        )
        # Approved path: AdminScopeCM.__aexit__ commits atomically.

    return NonceSyncResponse(
        wallet=body.wallet,
        chain=body.chain,
        from_nonce=cur,
        to_nonce=body.on_chain_count,
        status="advanced",
    )


# ---------------------------------------------------------------------------
# GET /v1/admin/nonce/holes
# ---------------------------------------------------------------------------


class NoncHoleItem(BaseModel):
    tx_id: str
    wallet: str
    chain: int
    nonce: int
    reserved_at: str | None  # ISO-8601
    caller: str


@router.get(
    "/v1/admin/nonce/holes",
    response_model=list[NoncHoleItem],
    dependencies=[admin_required],
)
async def get_nonce_holes(
    tx_repo_cm: TransactionRepoCM = Depends(get_transaction_repo),  # noqa: B008
) -> list[Any]:
    """Return stale pending reservations as the operator alarm for orphan nonces.

    A pending tx whose reserved_at is older than FWD_RESERVATION_LEASE_SEC is
    surfaced here. fwd does NOT auto-reissue — the operator decides to:
      (a) broadcast the original signed_raw (attempt 1 is still in signed_raw),
      (b) call sign-replacement if submitted first, or
      (c) manually release via broadcast-result rejected_releaseable.
    Read-only; no audit row needed.
    """
    s = get_settings()
    lease = timedelta(seconds=s.fwd_reservation_lease_sec)
    cutoff = datetime.now(UTC) - lease

    async with tx_repo_cm as repo:
        stale = await repo.list_stale_reservations(cutoff)

    return [
        NoncHoleItem(
            tx_id=tx.tx_id,
            wallet=tx.wallet,
            chain=tx.chain,
            nonce=tx.nonce,
            reserved_at=tx.reserved_at.isoformat() if tx.reserved_at else None,
            caller=tx.caller,
        )
        for tx in stale
    ]


# ---------------------------------------------------------------------------
# GET /v1/admin/nonce/{wallet}/{chain}
# ---------------------------------------------------------------------------


class NonceGetResponse(BaseModel):
    wallet: str
    chain: int
    next_nonce: int
    last_confirmed: int | None


@router.get(
    "/v1/admin/nonce/{wallet}/{chain}",
    response_model=NonceGetResponse,
    dependencies=[admin_required],
)
async def get_nonce(
    wallet: str,
    chain: int,
    nonce_repo_cm: NonceRepoCM = Depends(get_nonce_repo),  # noqa: B008
) -> NonceGetResponse:
    """Read the current next_nonce + last_confirmed for a (wallet, chain).

    Lets an egressing client / the onboarding wizard branch absent vs in-sync
    vs ahead/behind WITHOUT a write or an audit row (read-only, mirrors GET
    /v1/admin/nonce/holes). 404 if the row does not exist.
    """
    async with nonce_repo_cm as repo:
        row = await repo.get(wallet, chain, missing_ok=True)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "nonce_not_initialized",
                "message": f"(wallet={wallet}, chain={chain}) has no nonce row",
            },
        )
    return NonceGetResponse(
        wallet=row.wallet,
        chain=row.chain,
        next_nonce=row.next_nonce,
        last_confirmed=row.last_confirmed,
    )
