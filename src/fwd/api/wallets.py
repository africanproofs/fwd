"""POST /v1/admin/wallets — admin-only wallet provisioning.

Per architecture.md § Wallet provisioning (create flow) + decisions.md D9.
Phase 3b: create only; list/import/delete are Phase 4+.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from fwd.api.admin_auth import admin_required
from fwd.app.dependencies import SignerCM, get_signer
from fwd.app.wallet_create import (
    VaultUnavailableError,
    WalletCreateRequest,
    WalletNameTaken,
    create_wallet,
)

router = APIRouter()

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class CreateWalletBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    policy_path: str = Field(..., min_length=1, max_length=128)


class CreateWalletResponse(BaseModel):
    name: str
    address: str


@router.post(
    "/v1/admin/wallets",
    response_model=CreateWalletResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[admin_required],
)
async def post_wallets(
    body: CreateWalletBody,
    signer_cm: SignerCM = Depends(get_signer),  # noqa: B008
) -> CreateWalletResponse:
    if not _NAME_RE.match(body.name):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_name",
                "message": "name must match ^[a-z0-9][a-z0-9_-]{0,63}$",
            },
        )

    try:
        async with signer_cm as signer:
            result = await create_wallet(
                WalletCreateRequest(name=body.name, policy_path=body.policy_path),
                signer,
            )
    except WalletNameTaken:
        raise HTTPException(
            status_code=409,
            detail={"error": "wallet_exists", "message": f"wallet '{body.name}' already exists"},
        ) from None
    except VaultUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "vault_unavailable", "message": str(exc)},
        ) from exc

    return CreateWalletResponse(name=result.name, address=result.address)
