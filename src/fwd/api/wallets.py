"""POST / GET /v1/admin/wallets -- admin-only wallet provisioning + inventory.

Per architecture.md § Wallet provisioning (create flow) + decisions.md D9.
Phase 3b shipped POST. v0.4.0a7 (this ship) adds GET to close audit
deferral F7.2: admin operators must be able to enumerate every wallet
fwd custodies.

GET response is public-safe -- NEVER includes privkey_ciphertext or
vault_master_key. Only name, address, policy_path, created_at.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from fwd.api.admin_auth import admin_required
from fwd.app.dependencies import SignerCM, WalletRepoCM, get_signer, get_wallet_repo
from fwd.app.wallet_create import (
    VaultUnavailableError,
    WalletCreateRequest,
    WalletNameTaken,
    create_wallet,
)
from fwd.app.wallet_list import list_wallets

router = APIRouter()

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class CreateWalletBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    policy_path: str = Field(..., min_length=1, max_length=128)


class CreateWalletResponse(BaseModel):
    name: str
    address: str


class WalletSummary(BaseModel):
    """Listing model. Public-safe -- NEVER includes privkey_ciphertext or
    vault_master_key. Those are internal-only; leaking them defeats the
    Vault Transit envelope-encryption custody property (Core invariant #1)."""

    name: str
    address: str
    policy_path: str
    created_at: str  # ISO-8601


class ListWalletsResponse(BaseModel):
    wallets: list[WalletSummary]


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


@router.get(
    "/v1/admin/wallets",
    response_model=ListWalletsResponse,
    dependencies=[admin_required],
)
async def list_wallets_endpoint(
    wallet_repo_cm: Annotated[WalletRepoCM, Depends(get_wallet_repo)],
) -> ListWalletsResponse:
    async with wallet_repo_cm as repo:
        items = await list_wallets(repo)
    return ListWalletsResponse(
        wallets=[
            WalletSummary(
                name=w.name,
                address=w.address,
                policy_path=w.policy_path,
                created_at=w.created_at.isoformat(),
            )
            for w in items
        ]
    )
