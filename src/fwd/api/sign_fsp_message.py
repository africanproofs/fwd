"""POST /v1/sign-fsp-message — caller-auth. EIP-191 FSP message signing.

Distinct lifecycle from /v1/sign-transaction (no nonce/receipt) ->
its own route. No digest field: fwd reconstructs the messageHash from typed
fields.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator

from fwd.api.caller_auth import require_caller
from fwd.app.dependencies import Caller, RequestScopeCM, get_request_scope
from fwd.app.policy_gate import PolicyDenied
from fwd.app.sign_fsp_message import (
    FspMessageMalformed,
    SignFspMessageRequest,
    VaultUnavailableError,
    WalletNotFound,
    sign_fsp_message,
)

router = APIRouter()

_HEX32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
_MAX_UINT24 = 16_777_215


_HEX_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


class SignFspMessageBody(BaseModel):
    wallet: str = Field(..., min_length=1, max_length=64)
    message_type: Literal[
        "UPTIME",
        "REWARD_DISTRIBUTION",
        "SIGNING_POLICY",
        "VOTER_REGISTRATION",
        "PROTOCOL_PAYLOAD",
    ]
    reward_epoch_id: int = Field(..., ge=0, le=_MAX_UINT24)
    chain_id: int | None = Field(default=None, ge=1)
    no_of_weight_based_claims: int | None = Field(default=None, ge=0)
    rewards_hash: str | None = Field(default=None)
    address: str | None = Field(default=None)
    signing_policy: str | None = Field(default=None)
    payload: str | None = Field(default=None)
    protocol_id: int | None = Field(default=None, ge=0)
    registration_variant: Literal["legacy", "chain_scoped"] | None = None

    @model_validator(mode="after")
    def _shape(self) -> SignFspMessageBody:
        if self.message_type == "UPTIME":
            if (
                self.chain_id is not None
                or self.no_of_weight_based_claims is not None
                or self.rewards_hash is not None
                or self.address is not None
                or self.signing_policy is not None
                or self.payload is not None
                or self.protocol_id is not None
                or self.registration_variant is not None
            ):
                raise ValueError("UPTIME takes only reward_epoch_id")
        elif self.message_type == "REWARD_DISTRIBUTION":
            if (
                self.chain_id is None
                or self.no_of_weight_based_claims is None
                or self.rewards_hash is None
            ):
                raise ValueError(
                    "REWARD_DISTRIBUTION requires chain_id, "
                    "no_of_weight_based_claims, rewards_hash"
                )
            if not _HEX32.match(self.rewards_hash):
                raise ValueError("rewards_hash must be 0x + 64 hex")
            if (
                self.address is not None
                or self.signing_policy is not None
                or self.payload is not None
                or self.protocol_id is not None
                or self.registration_variant is not None
            ):
                raise ValueError("REWARD_DISTRIBUTION does not accept address/signing_policy/payload/protocol_id/registration_variant")
        elif self.message_type == "VOTER_REGISTRATION":
            if self.address is None:
                raise ValueError("VOTER_REGISTRATION requires address")
            if not _HEX_ADDR.match(self.address):
                raise ValueError("address must be 0x + 40 hex")
            if self.registration_variant not in ("legacy", "chain_scoped"):
                raise ValueError("VOTER_REGISTRATION requires registration_variant: legacy or chain_scoped")
            if self.registration_variant == "chain_scoped" and self.chain_id is None:
                raise ValueError("VOTER_REGISTRATION chain_scoped requires chain_id")
            if self.registration_variant == "legacy" and self.chain_id is not None:
                raise ValueError("VOTER_REGISTRATION legacy must not include chain_id")
            if (
                self.no_of_weight_based_claims is not None
                or self.rewards_hash is not None
                or self.signing_policy is not None
                or self.payload is not None
                or self.protocol_id is not None
            ):
                raise ValueError("VOTER_REGISTRATION does not accept reward fields, signing_policy, payload, or protocol_id")
        elif self.message_type == "SIGNING_POLICY":
            if self.signing_policy is None:
                raise ValueError("SIGNING_POLICY requires signing_policy")
            if (
                self.chain_id is not None
                or self.address is not None
                or self.no_of_weight_based_claims is not None
                or self.rewards_hash is not None
                or self.payload is not None
                or self.protocol_id is not None
                or self.registration_variant is not None
            ):
                raise ValueError("SIGNING_POLICY does not accept chain_id/address/reward/payload/protocol_id/registration_variant fields")
        else:  # PROTOCOL_PAYLOAD
            if self.payload is None:
                raise ValueError("PROTOCOL_PAYLOAD requires payload")
            if (
                self.address is not None
                or self.no_of_weight_based_claims is not None
                or self.rewards_hash is not None
                or self.signing_policy is not None
                or self.registration_variant is not None
            ):
                raise ValueError("PROTOCOL_PAYLOAD does not accept address/reward/signing_policy/registration_variant fields")
        return self


class SignFspMessageResponse(BaseModel):
    message_hash: str
    v: int
    r: str
    s: str
    signature: str


@router.post(
    "/v1/sign-fsp-message",
    response_model=SignFspMessageResponse,
    status_code=status.HTTP_200_OK,
)
async def post_sign_fsp_message(
    body: SignFspMessageBody,
    caller: Annotated[Caller, Depends(require_caller)],
    http_request: Request,
    scope_cm: RequestScopeCM = Depends(get_request_scope),  # noqa: B008
) -> SignFspMessageResponse:
    request = SignFspMessageRequest(
        wallet=body.wallet,
        caller=caller.name,
        message_type=body.message_type,
        reward_epoch_id=body.reward_epoch_id,
        chain_id=body.chain_id,
        no_of_weight_based_claims=body.no_of_weight_based_claims,
        rewards_hash=body.rewards_hash,
        address=body.address,
        signing_policy=body.signing_policy,
        payload=body.payload,
        protocol_id=body.protocol_id,
        registration_variant=body.registration_variant,
    )
    try:
        async with scope_cm as scope:
            policy = http_request.app.state.policy
            result = await sign_fsp_message(
                request,
                scope.signer,
                caller=caller,
                policy=policy,
                rate_repo=scope.rate_repo,
                audit_repo=scope.audit_repo,
            )
    except PolicyDenied:
        raise HTTPException(status_code=403, detail={"error": "policy_denied"}) from None
    except WalletNotFound:
        raise HTTPException(status_code=403, detail={"error": "policy_denied"}) from None
    except FspMessageMalformed as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "fsp_message_malformed", "message": str(exc)},
        ) from exc
    except VaultUnavailableError:
        raise HTTPException(
            status_code=503,
            detail={"error": "vault_unavailable", "message": "sealed master unavailable"},
        ) from None

    return SignFspMessageResponse(
        message_hash=result.message_hash,
        v=result.v,
        r=result.r,
        s=result.s,
        signature=result.signature,
    )
