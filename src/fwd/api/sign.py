"""POST /v1/sign-and-send — caller-auth in v0.4.0-alpha+ (was admin-gated in v0.3.0-v0.3.x).

Per architecture.md § API surface + § Signing flow + decisions.md D11.
v0.3.0 hardcoded allowlist: Coston2 (chain_id=114) only. Phase 7 lifts
with policy.yaml.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from fwd.api.caller_auth import require_caller
from fwd.app.dependencies import (
    Caller,
    NonceRepoCM,
    RpcManagerCM,
    SignerCM,
    TransactionRepoCM,
    get_nonce_repo,
    get_rpc_manager,
    get_signer,
    get_transaction_repo,
)
from fwd.app.sign_and_send import (
    ALLOWED_CHAINS,
    ChainNotAllowed,
    RpcUnreachable,
    SignAndSendRequest,
    VaultUnavailableError,
    WalletNotFound,
    sign_and_send,
)

router = APIRouter()

_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_DATA = re.compile(r"^0x([0-9a-fA-F]{2})*$")


class SignAndSendBody(BaseModel):
    wallet: str = Field(..., min_length=1, max_length=64)
    chain: int = Field(..., ge=1)
    to: str = Field(..., min_length=42, max_length=42)
    value_wei: str = Field(default="0")
    data: str = Field(default="0x")
    gas: int | None = Field(default=None, ge=21_000)

    @field_validator("to")
    @classmethod
    def _to_hex(cls, v: str) -> str:
        if not _HEX_ADDRESS.match(v):
            raise ValueError("to must be a 0x-prefixed 20-byte hex address")
        return v

    @field_validator("value_wei")
    @classmethod
    def _value_decimal(cls, v: str) -> str:
        try:
            n = int(v)
        except ValueError as exc:
            raise ValueError("value_wei must be a decimal string") from exc
        if n < 0:
            raise ValueError("value_wei must be non-negative")
        return v

    @field_validator("data")
    @classmethod
    def _data_hex(cls, v: str) -> str:
        if not _HEX_DATA.match(v):
            raise ValueError("data must be 0x or 0x-prefixed even-length hex")
        return v


class SignAndSendResponse(BaseModel):
    tx_id: str
    hash: str
    nonce: int


@router.post(
    "/v1/sign-and-send",
    response_model=SignAndSendResponse,
    status_code=status.HTTP_200_OK,
)
async def post_sign_and_send(
    body: SignAndSendBody,
    caller: Annotated[Caller, Depends(require_caller)],
    signer_cm: SignerCM = Depends(get_signer),  # noqa: B008
    rpc_cm: RpcManagerCM = Depends(get_rpc_manager),  # noqa: B008
    tx_repo_cm: TransactionRepoCM = Depends(get_transaction_repo),  # noqa: B008
    nonce_repo_cm: NonceRepoCM = Depends(get_nonce_repo),  # noqa: B008
) -> SignAndSendResponse:
    if body.chain not in ALLOWED_CHAINS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "chain_not_allowed",
                "message": f"chain_id={body.chain} not in v0.3.0 allowlist; Coston2 (114) only",
            },
        )
    request = SignAndSendRequest(
        wallet=body.wallet,
        caller=caller.name,
        chain=body.chain,
        to=body.to,
        value_wei=body.value_wei,
        data=body.data,
        gas=body.gas,
    )
    try:
        async with (
            signer_cm as signer,
            rpc_cm as rpc_mgr,
            tx_repo_cm as tx_repo,
            nonce_repo_cm as nonce_repo,
        ):
            rpc = rpc_mgr.for_chain(body.chain)
            result = await sign_and_send(request, signer, rpc, tx_repo, nonce_repo)
    except ChainNotAllowed as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "chain_not_allowed", "message": str(exc)},
        ) from exc
    except WalletNotFound:
        raise HTTPException(
            status_code=404,
            detail={"error": "wallet_not_found", "message": f"wallet '{body.wallet}' not found"},
        ) from None
    except VaultUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "vault_unavailable", "message": str(exc)},
        ) from exc
    except RpcUnreachable as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "rpc_unreachable", "message": str(exc)},
        ) from exc

    return SignAndSendResponse(tx_id=result.tx_id, hash=result.hash, nonce=result.nonce)
