"""POST / GET /v1/admin/wallets -- admin-only wallet provisioning + inventory.

Per architecture.md § Wallet provisioning (create flow) + decisions.md D9.
Phase 3b shipped POST. v0.4.0a7 (this ship) adds GET to close audit
deferral F7.2: admin operators must be able to enumerate every wallet
fwd custodies.

GET response is public-safe -- NEVER includes privkey_ciphertext or
vault_master_key. Only name, address, policy_path, created_at.

v0.5.0a7: POST handler swapped to AdminScopeCM (D16 audit authorship) +
policy_path validation (D14 admin-endpoint validation).
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from fwd.api.admin_auth import admin_required
from fwd.app.dependencies import (
    AdminScopeCM,
    WalletRepoCM,
    get_admin_scope,
    get_wallet_repo,
    policy_path_exists,
)
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
    http_request: Request,
    admin_scope_cm: AdminScopeCM = Depends(get_admin_scope),  # noqa: B008
) -> CreateWalletResponse:
    if not _NAME_RE.match(body.name):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_name",
                "message": "name must match ^[a-z0-9][a-z0-9_-]{0,63}$",
            },
        )

    # policy_path validation: skip when no policy is loaded (bootstrap order).
    policy = getattr(http_request.app.state, "policy", None)
    if policy is not None and not policy_path_exists(policy, body.policy_path, "wallet"):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unknown_policy_path",
                "message": (
                    f"policy_path '{body.policy_path}' is not in the "
                    f"loaded policy (wallet_constraints)"
                ),
            },
        )

    try:
        async with admin_scope_cm as scope:
            result = await create_wallet(
                WalletCreateRequest(name=body.name, policy_path=body.policy_path),
                scope.signer,
                audit_repo=scope.audit_repo,
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


