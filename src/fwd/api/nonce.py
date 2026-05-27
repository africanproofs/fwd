"""POST /v1/admin/nonce-init — admin-only nonce seeding for a (wallet, chain).

Seeds the nonces row so a (wallet, chain) can sign without an on-chain
transaction-count probe (the RPC-free replacement for sign_and_send's lazy
seed). Idempotent guard: 409 if already initialized. 404 if the wallet does
not exist. Writes a D16 audit row on the shared AdminScope session; the
forensic row on a refusal is committed before the HTTPException propagates
(Core invariant #5 / #19).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from fwd.api.admin_auth import admin_required
from fwd.app.dependencies import (
    AdminScopeCM,
    NonceWalletNotFoundError,
    _canonical_json,
    get_admin_scope,
)

router = APIRouter()


class NonceInitBody(BaseModel):
    wallet: str = Field(..., min_length=1, max_length=64)
    chain: int = Field(..., ge=1)
    starting_nonce: int = Field(..., ge=0)


class NonceInitResponse(BaseModel):
    wallet: str
    chain: int
    next_nonce: int


def _req_json(body: NonceInitBody) -> str:
    return _canonical_json(
        {"wallet": body.wallet, "chain": body.chain, "starting_nonce": body.starting_nonce}
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
        if existing is not None:
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
        try:
            row = await scope.nonce_repo.init_for_wallet(
                body.wallet, body.chain, body.starting_nonce
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
                detail={"error": "wallet_not_found", "message": f"wallet '{body.wallet}' not found"},
            ) from exc
        await scope.audit_repo.append(
            action="nonce-init",
            decision="approved",
            caller=None,
            request_json=_req_json(body),
            decision_reason=None,
            outcome=_canonical_json({"next_nonce": row.next_nonce}),
        )
        # Approved path: no explicit commit — AdminScopeCM.__aexit__ commits the
        # shared session once (seed + audit row atomic under one BEGIN IMMEDIATE).
    return NonceInitResponse(wallet=row.wallet, chain=row.chain, next_nonce=row.next_nonce)
