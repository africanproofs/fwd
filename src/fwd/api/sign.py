"""POST /v1/sign-transaction — sign-only, zero-egress (v1.1.0a9).

fwd signs and returns the signed raw tx; the CALLER broadcasts. No RPC.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from fwd.api.caller_auth import require_caller
from fwd.app.dependencies import Caller, RequestScopeCM, get_request_scope
from fwd.app.policy_gate import PolicyDenied
from fwd.app.sign_transaction import (
    IdempotencyConflict,
    NonceNotInitialized,
    SignTransactionRequest,
    TxParamsRejected,
    VaultUnavailableError,
    WalletNotFound,
    sign_transaction,
)

router = APIRouter()

_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_DATA = re.compile(r"^0x([0-9a-fA-F]{2})*$")


class SignTransactionBody(BaseModel):
    wallet: str = Field(..., min_length=1, max_length=64)
    chain: int = Field(..., ge=1)
    to: str = Field(..., min_length=42, max_length=42)
    value_wei: str = Field(default="0")
    data: str = Field(default="0x")
    gas: int = Field(..., ge=21_000)
    max_fee_per_gas: int = Field(..., ge=1)
    max_priority_fee_per_gas: int = Field(..., ge=0)

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


class SignTransactionResponse(BaseModel):
    tx_id: str
    hash: str
    signed_raw_tx: str
    nonce: int


@router.post("/v1/sign-transaction", response_model=SignTransactionResponse,
             status_code=status.HTTP_200_OK)
async def post_sign_transaction(
    body: SignTransactionBody,
    caller: Annotated[Caller, Depends(require_caller)],
    http_request: Request,
    scope_cm: RequestScopeCM = Depends(get_request_scope),  # noqa: B008
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),  # noqa: B008
) -> SignTransactionResponse:
    if idempotency_key is not None and len(idempotency_key) > 128:
        raise HTTPException(status_code=400, detail={
            "error": "bad_idempotency_key", "message": "Idempotency-Key must be <=128 chars"})
    request = SignTransactionRequest(
        wallet=body.wallet, caller=caller.name, chain=body.chain, to=body.to,
        value_wei=body.value_wei, data=body.data, gas=body.gas,
        max_fee_per_gas=body.max_fee_per_gas,
        max_priority_fee_per_gas=body.max_priority_fee_per_gas,
        idempotency_key=idempotency_key,
    )
    try:
        async with scope_cm as scope:
            wallet_obj = await scope.wallet_repo.get_by_name(body.wallet, missing_ok=True)
            if wallet_obj is None:
                raise HTTPException(status_code=403, detail={"error": "policy_denied"})
            policy = http_request.app.state.policy
            registry = http_request.app.state.abi_registry
            result = await sign_transaction(
                request, scope.signer, scope.tx_repo, scope.nonce_repo,
                caller=caller, wallet=wallet_obj, policy=policy, registry=registry,
                rate_repo=scope.rate_repo, audit_repo=scope.audit_repo,
                attempt_repo=scope.attempt_repo,
            )
    except PolicyDenied:
        raise HTTPException(status_code=403, detail={"error": "policy_denied"}) from None
    except TxParamsRejected as exc:
        raise HTTPException(status_code=400, detail={"error": "tx_params_rejected", "message": str(exc)}) from exc
    except WalletNotFound:
        raise HTTPException(status_code=403, detail={"error": "policy_denied"}) from None
    except IdempotencyConflict as exc:
        raise HTTPException(status_code=409, detail={"error": "idempotency_conflict", "message": f"Idempotency-Key reused with a different request body: {exc}"}) from exc
    except NonceNotInitialized as exc:
        raise HTTPException(status_code=409, detail={"error": "nonce_not_initialized", "message": str(exc)}) from exc
    except VaultUnavailableError:
        raise HTTPException(status_code=503, detail={"error": "vault_unavailable", "message": "sealed master unavailable"}) from None

    return SignTransactionResponse(tx_id=result.tx_id, hash=result.hash,
                                   signed_raw_tx=result.signed_raw_tx, nonce=result.nonce)
