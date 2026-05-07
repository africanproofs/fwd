"""POST/DELETE/GET /v1/admin/callers — admin-gated caller management.

Per docs/architecture.md § API surface. Admin-gated (D11): callers
themselves cannot create/revoke/list other callers.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from fwd.api.admin_auth import admin_required
from fwd.app.caller_create import (
    CallerCreateRequest,
    CallerNameTaken,
    create_caller,
)
from fwd.app.caller_list import list_callers
from fwd.app.caller_revoke import (
    CallerAlreadyRevoked,
    CallerNotFound,
    revoke_caller,
)
from fwd.app.dependencies import CallerRepoCM, get_caller_repo

router = APIRouter()

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class CreateCallerBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    policy_path: str = Field(..., min_length=1, max_length=128)


class CreateCallerResponse(BaseModel):
    name: str
    api_key: str  # plaintext, returned ONCE
    api_key_prefix: str
    policy_path: str


class CallerSummary(BaseModel):
    """Listing model. NEVER includes api_key_hash (we don't return hashes)."""

    name: str
    api_key_prefix: str
    policy_path: str
    created_at: str
    revoked_at: str | None


class ListCallersResponse(BaseModel):
    callers: list[CallerSummary]


@router.post(
    "/v1/admin/callers",
    response_model=CreateCallerResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[admin_required],
)
async def post_callers(
    body: CreateCallerBody,
    caller_repo_cm: Annotated[CallerRepoCM, Depends(get_caller_repo)],
) -> CreateCallerResponse:
    if not _NAME_RE.match(body.name):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_name",
                "message": "name must match ^[a-z0-9][a-z0-9_-]{0,63}$",
            },
        )

    try:
        async with caller_repo_cm as repo:
            result = await create_caller(
                CallerCreateRequest(name=body.name, policy_path=body.policy_path), repo
            )
    except CallerNameTaken:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "caller_exists",
                "message": f"caller '{body.name}' already exists",
            },
        ) from None

    return CreateCallerResponse(
        name=result.name,
        api_key=result.api_key,
        api_key_prefix=result.api_key_prefix,
        policy_path=result.policy_path,
    )


@router.delete(
    "/v1/admin/callers/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    dependencies=[admin_required],
)
async def delete_caller(
    name: str,
    caller_repo_cm: Annotated[CallerRepoCM, Depends(get_caller_repo)],
) -> None:
    try:
        async with caller_repo_cm as repo:
            await revoke_caller(name, repo)
    except CallerNotFound:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "caller_not_found",
                "message": f"caller '{name}' not found",
            },
        ) from None
    except CallerAlreadyRevoked:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "caller_already_revoked",
                "message": f"caller '{name}' is already revoked",
            },
        ) from None


@router.get(
    "/v1/admin/callers",
    response_model=ListCallersResponse,
    dependencies=[admin_required],
)
async def list_callers_endpoint(
    caller_repo_cm: Annotated[CallerRepoCM, Depends(get_caller_repo)],
) -> ListCallersResponse:
    async with caller_repo_cm as repo:
        items = await list_callers(repo, include_revoked=True)
    return ListCallersResponse(
        callers=[
            CallerSummary(
                name=c.name,
                api_key_prefix=c.api_key_prefix,
                policy_path=c.policy_path,
                created_at=c.created_at.isoformat(),
                revoked_at=c.revoked_at.isoformat() if c.revoked_at else None,
            )
            for c in items
        ]
    )
