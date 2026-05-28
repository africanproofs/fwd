"""Transaction endpoints — GET status lookup + client report-back.

GET  /v1/transactions/{tx_id}                          — caller-gated status
POST /v1/transactions/{tx_id}/broadcast-result         — client reports broadcast outcome
POST /v1/transactions/{tx_id}/receipt                  — client reports on-chain receipt
POST /v1/transactions/{tx_id}/sign-replacement         — client-triggered stuck-tx replacement

Per architecture.md § API surface. Cross-caller isolation: a caller querying
another caller's tx_id receives 404 (NOT 403) so we don't leak the existence
of other callers' transactions.

Trust boundary (§4.1):
1. Caller ownership — 404 on miss or mismatch.
2. tx_hash validation — 409 + forensic audit row on mismatch.
3. Legal transition guard — 409 + forensic audit row on illegal source status.

Core invariant #5/#19: on denied paths (tx_hash mismatch, illegal transition),
append the audit row then `await scope.audit_repo.commit()` BEFORE raising so the
forensic row survives the session rollback on exception.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from fwd.api.caller_auth import require_caller
from fwd.app.dependencies import (
    Caller,
    ReplacementScopeCM,
    ReportScope,
    ReportScopeCM,
    TransactionRepoCM,
    _canonical_json,
    get_replacement_scope,
    get_report_scope,
    get_transaction_repo,
)
from fwd.app.sign_transaction import VaultUnavailableError
from fwd.settings import get_settings

router = APIRouter()


# ---------------------------------------------------------------------------
# Response / request models
# ---------------------------------------------------------------------------


class TxHashItem(BaseModel):
    sequence_num: int
    hash_hex: str
    submitted_at: str  # ISO-8601


class TxStatusResponse(BaseModel):
    tx_id: str
    wallet: str
    chain: int
    nonce: int
    contract_address: str
    method_name: str
    value_wei: str
    status: str
    submitted_at: str | None
    confirmed_at: str | None
    hashes: list[TxHashItem]


class TxReportResponse(BaseModel):
    tx_id: str
    status: str


class BroadcastResultBody(BaseModel):
    tx_hash: str = Field(..., min_length=66, max_length=66)  # 0x + 64 hex
    outcome: Literal["accepted", "rejected_releaseable", "rejected_nonce_too_low"]
    error_class: str | None = Field(default=None, max_length=128)


class ReceiptBody(BaseModel):
    tx_hash: str = Field(..., min_length=66, max_length=66)
    outcome: Literal["mined_success", "mined_reverted"]
    block_number: int = Field(..., ge=0)


class SignReplacementBody(BaseModel):
    gas: int = Field(..., ge=21_000)
    max_fee_per_gas: int = Field(..., ge=1)
    max_priority_fee_per_gas: int = Field(..., ge=0)


class SignReplacementResponse(BaseModel):
    tx_id: str
    signed_raw_tx: str
    hash: str
    nonce: int
    attempt: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _ownership_check(
    tx_id: str,
    caller: Caller,
    scope: ReportScope,
) -> Any:
    """Load tx and enforce caller ownership. Returns the Transaction dataclass.

    Raises HTTP 404 if not found or belongs to a different caller.
    No audit row — a 404 is a non-event.
    """
    tx = await scope.tx_repo.get_by_id(tx_id, missing_ok=True)
    if tx is None or tx.caller != caller.name:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "transaction_not_found", "message": f"tx_id={tx_id} not found"},
        )
    return tx


async def _hash_check(
    tx_id: str,
    reported_hash: str,
    action: str,
    caller_name: str,
    scope: ReportScope,
) -> None:
    """Verify reported tx_hash is one fwd recorded for this tx_id.

    On mismatch: append denied forensic audit row, commit (Core #5/#19), then raise 409.
    """
    known_hashes = await scope.tx_repo.list_hashes_by_tx(tx_id)
    known_hex = {h.hash_hex for h in known_hashes}
    if reported_hash not in known_hex:
        await scope.audit_repo.append(
            action=action,
            decision="denied",
            caller=caller_name,
            request_json=_canonical_json({"tx_id": tx_id, "tx_hash": reported_hash}),
            decision_reason="tx_hash_mismatch",
        )
        await scope.audit_repo.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "tx_hash_mismatch",
                "message": "tx_hash not recorded for this tx_id",
            },
        )


async def _transition_check(
    tx_id: str,
    current_status: str,
    required_status: str,
    intent: str,
    action: str,
    caller_name: str,
    scope: ReportScope,
) -> None:
    """Guard legal source status for a transition.

    On mismatch: append denied forensic audit row, commit, then raise 409.
    """
    if current_status != required_status:
        await scope.audit_repo.append(
            action=action,
            decision="denied",
            caller=caller_name,
            request_json=_canonical_json({"tx_id": tx_id}),
            decision_reason=f"illegal_transition:{current_status}->{intent}",
        )
        await scope.audit_repo.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "illegal_transition",
                "message": f"tx is {current_status!r}; expected {required_status!r}",
            },
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/v1/transactions/{tx_id}", response_model=TxStatusResponse)
async def get_transaction(
    tx_id: str,
    caller: Annotated[Caller, Depends(require_caller)],
    tx_repo_cm: Annotated[TransactionRepoCM, Depends(get_transaction_repo)] = ...,  # type: ignore[assignment]
) -> TxStatusResponse:
    async with tx_repo_cm as repo:
        tx = await repo.get_by_id(tx_id, missing_ok=True)
        if tx is None or tx.caller != caller.name:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "transaction_not_found", "message": f"tx_id={tx_id} not found"},
            )
        hashes = await repo.list_hashes_by_tx(tx_id)

    return TxStatusResponse(
        tx_id=tx.tx_id,
        wallet=tx.wallet,
        chain=tx.chain,
        nonce=tx.nonce,
        contract_address=tx.contract_address,
        method_name=tx.method_name,
        value_wei=tx.value_wei,
        status=tx.status,
        submitted_at=tx.submitted_at.isoformat() if tx.submitted_at else None,
        confirmed_at=tx.confirmed_at.isoformat() if tx.confirmed_at else None,
        hashes=[
            TxHashItem(
                sequence_num=h.sequence_num,
                hash_hex=h.hash_hex,
                submitted_at=h.submitted_at.isoformat(),
            )
            for h in hashes
        ],
    )


@router.post("/v1/transactions/{tx_id}/broadcast-result", response_model=TxReportResponse)
async def post_broadcast_result(
    tx_id: str,
    body: BroadcastResultBody,
    caller: Annotated[Caller, Depends(require_caller)],
    scope_cm: ReportScopeCM = Depends(get_report_scope),  # noqa: B008
) -> TxReportResponse:
    """Report the broadcast outcome for a signed tx back to fwd.

    Trust boundary: caller ownership + tx_hash validation + legal transition guard.
    On approved path: ReportScopeCM.__aexit__ commits the session (state mutation +
    audit row atomic). Do NOT call commit() on the approved path.
    """
    async with scope_cm as scope:
        tx = await _ownership_check(tx_id, caller, scope)
        await _hash_check(tx_id, body.tx_hash, "tx-broadcast-result", caller.name, scope)
        await _transition_check(
            tx_id,
            tx.status,
            "pending",
            body.outcome,
            "tx-broadcast-result",
            caller.name,
            scope,
        )

        now = datetime.now(UTC)

        if body.outcome == "accepted":
            await scope.tx_repo.update_status(tx_id, "submitted", submitted_at=now)
            await scope.audit_repo.append(
                action="tx-broadcast-result",
                decision="approved",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id, "tx_hash": body.tx_hash}),
                decision_reason="broadcast_accepted",
                outcome=_canonical_json({"tx_hash": body.tx_hash}),
            )
            new_status = "submitted"

        elif body.outcome == "rejected_releaseable":
            released = await scope.nonce_repo.release_if_unused(
                tx.wallet,
                tx.chain,
                tx.nonce,
            )
            await scope.tx_repo.update_status(tx_id, "failed")
            await scope.audit_repo.append(
                action="tx-broadcast-result",
                decision="approved",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id, "tx_hash": body.tx_hash}),
                decision_reason="broadcast_rejected_releaseable",
                outcome=_canonical_json(
                    {
                        "tx_hash": body.tx_hash,
                        "error_class": body.error_class,
                        "released": released,
                    }
                ),
            )
            new_status = "failed"

        else:  # rejected_nonce_too_low
            await scope.tx_repo.update_status(tx_id, "failed")
            await scope.audit_repo.append(
                action="tx-broadcast-result",
                decision="approved",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id, "tx_hash": body.tx_hash}),
                decision_reason="broadcast_rejected_nonce_too_low",
                outcome=_canonical_json(
                    {
                        "tx_hash": body.tx_hash,
                        "error_class": body.error_class,
                        "hint": "chain ahead of fwd; admin nonce-sync required (ship a11+)",
                    }
                ),
            )
            new_status = "failed"

    return TxReportResponse(tx_id=tx_id, status=new_status)


@router.post("/v1/transactions/{tx_id}/receipt", response_model=TxReportResponse)
async def post_receipt(
    tx_id: str,
    body: ReceiptBody,
    caller: Annotated[Caller, Depends(require_caller)],
    scope_cm: ReportScopeCM = Depends(get_report_scope),  # noqa: B008
) -> TxReportResponse:
    """Report on-chain receipt for a submitted tx back to fwd.

    Trust boundary: caller ownership + tx_hash validation + legal transition guard.
    On approved path: ReportScopeCM.__aexit__ commits atomically.
    """
    async with scope_cm as scope:
        tx = await _ownership_check(tx_id, caller, scope)
        await _hash_check(tx_id, body.tx_hash, "tx-receipt", caller.name, scope)
        await _transition_check(
            tx_id,
            tx.status,
            "submitted",
            body.outcome,
            "tx-receipt",
            caller.name,
            scope,
        )

        now = datetime.now(UTC)

        if body.outcome == "mined_success":
            receipt = _canonical_json(
                {"block_number": body.block_number, "tx_hash": body.tx_hash, "status": 1}
            )
            await scope.tx_repo.update_status(
                tx_id, "mined", confirmed_at=now, receipt_json=receipt
            )
            await scope.nonce_repo.mark_confirmed(tx.wallet, tx.chain, tx.nonce)
            await scope.audit_repo.append(
                action="tx-receipt",
                decision="approved",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id, "tx_hash": body.tx_hash}),
                decision_reason="receipt_mined_success",
            )
            new_status = "mined"

        else:  # mined_reverted
            receipt = _canonical_json(
                {"block_number": body.block_number, "tx_hash": body.tx_hash, "status": 0}
            )
            await scope.tx_repo.update_status(
                tx_id, "reverted", confirmed_at=now, receipt_json=receipt
            )
            await scope.nonce_repo.mark_confirmed(tx.wallet, tx.chain, tx.nonce)
            await scope.audit_repo.append(
                action="tx-receipt",
                decision="approved",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id, "tx_hash": body.tx_hash}),
                decision_reason="receipt_mined_reverted",
            )
            new_status = "reverted"

    return TxReportResponse(tx_id=tx_id, status=new_status)


@router.post(
    "/v1/transactions/{tx_id}/sign-replacement",
    response_model=SignReplacementResponse,
)
async def post_sign_replacement(
    tx_id: str,
    body: SignReplacementBody,
    caller: Annotated[Caller, Depends(require_caller)],
    scope_cm: ReplacementScopeCM = Depends(get_replacement_scope),  # noqa: B008
) -> SignReplacementResponse:
    """Re-sign the same tx intent at the same nonce with new gas/fee params.

    Only allowed when the tx is in 'submitted' state (broadcast but stuck).
    Enforces: caller ownership, replaceable-state guard, bump rule, retry cap.
    Same intent (to, value, data, chainId, nonce) — NEVER a different intent.
    Core invariant #5/#19: forensic audit rows are committed before raising.
    """
    import json as _json

    from eth_utils.address import to_checksum_address

    s = get_settings()

    async with scope_cm as scope:
        # 1. Caller ownership.
        tx = await scope.tx_repo.get_by_id(tx_id, missing_ok=True)
        if tx is None or tx.caller != caller.name:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "transaction_not_found", "message": f"tx_id={tx_id} not found"},
            )

        # 2. Replaceable-state guard — must be 'submitted' (broadcast and stuck).
        if tx.status != "submitted":
            await scope.audit_repo.append(
                action="tx-replacement",
                decision="denied",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id}),
                decision_reason=f"illegal_transition:{tx.status}->replacement",
            )
            await scope.audit_repo.commit()  # Core #5/#19
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "illegal_transition",
                    "message": f"tx is {tx.status!r}; expected 'submitted'",
                },
            )

        # 3. Bump rule — read latest attempt and enforce min fee increase.
        prev = await scope.attempt_repo.latest_attempt(tx_id)
        if prev is not None:
            min_priority = math.ceil(prev.max_priority_fee_per_gas * 1.125)
            if body.max_priority_fee_per_gas < min_priority:
                await scope.audit_repo.append(
                    action="tx-replacement",
                    decision="denied",
                    caller=caller.name,
                    request_json=_canonical_json(
                        {
                            "tx_id": tx_id,
                            "max_priority_fee_per_gas": body.max_priority_fee_per_gas,
                            "min_required": min_priority,
                        }
                    ),
                    decision_reason="replacement_bump_too_low",
                )
                await scope.audit_repo.commit()  # Core #5/#19
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "replacement_bump_too_low",
                        "message": (
                            f"max_priority_fee_per_gas must be >= {min_priority} "
                            f"(ceil(prev={prev.max_priority_fee_per_gas} * 1.125))"
                        ),
                    },
                )
            if body.max_fee_per_gas < prev.max_fee_per_gas:
                await scope.audit_repo.append(
                    action="tx-replacement",
                    decision="denied",
                    caller=caller.name,
                    request_json=_canonical_json(
                        {
                            "tx_id": tx_id,
                            "max_fee_per_gas": body.max_fee_per_gas,
                            "prev_max_fee_per_gas": prev.max_fee_per_gas,
                        }
                    ),
                    decision_reason="replacement_bump_too_low",
                )
                await scope.audit_repo.commit()  # Core #5/#19
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "replacement_bump_too_low",
                        "message": (
                            f"max_fee_per_gas must be >= prev={prev.max_fee_per_gas}"
                        ),
                    },
                )

        # Global caps.
        if body.max_priority_fee_per_gas > body.max_fee_per_gas:
            await scope.audit_repo.append(
                action="tx-replacement",
                decision="denied",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id}),
                decision_reason="tx_params_rejected:priority_exceeds_maxfee",
            )
            await scope.audit_repo.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "tx_params_rejected",
                    "message": "max_priority_fee_per_gas exceeds max_fee_per_gas",
                },
            )
        if body.gas > s.fwd_max_gas:
            await scope.audit_repo.append(
                action="tx-replacement",
                decision="denied",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id}),
                decision_reason=f"tx_params_rejected:gas_exceeds_cap:{body.gas}>{s.fwd_max_gas}",
            )
            await scope.audit_repo.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "tx_params_rejected",
                    "message": f"gas {body.gas} exceeds FWD_MAX_GAS {s.fwd_max_gas}",
                },
            )
        if body.max_fee_per_gas > s.fwd_max_fee_per_gas:
            await scope.audit_repo.append(
                action="tx-replacement",
                decision="denied",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id}),
                decision_reason=(
                    f"tx_params_rejected:max_fee_exceeds_cap:"
                    f"{body.max_fee_per_gas}>{s.fwd_max_fee_per_gas}"
                ),
            )
            await scope.audit_repo.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "tx_params_rejected",
                    "message": (
                        f"max_fee_per_gas {body.max_fee_per_gas} exceeds "
                        f"FWD_MAX_FEE_PER_GAS {s.fwd_max_fee_per_gas}"
                    ),
                },
            )

        # 4. Retry cap — at most 5 attempts total (original + 4 replacements).
        all_attempts = await scope.attempt_repo.list_attempts(tx_id)
        if len(all_attempts) >= 5:
            await scope.audit_repo.append(
                action="tx-replacement",
                decision="denied",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id}),
                decision_reason="replacement_cap_exhausted",
            )
            await scope.audit_repo.commit()  # Core #5/#19
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "replacement_cap_exhausted",
                    "message": "maximum 5 attempts reached (Core invariant #11)",
                },
            )

        new_seq = len(all_attempts) + 1

        # 5. Re-sign same intent, same nonce.
        # Extract original calldata from the stored request_json.
        try:
            req = _json.loads(tx.request_json)
            original_data = req.get("data", "0x")
        except (ValueError, TypeError, AttributeError):
            original_data = "0x"

        tx_dict = {
            "type": 2,
            "chainId": tx.chain,
            "nonce": tx.nonce,
            "to": to_checksum_address(tx.contract_address),
            "value": int(tx.value_wei),
            "data": original_data,
            "gas": body.gas,
            "maxFeePerGas": body.max_fee_per_gas,
            "maxPriorityFeePerGas": body.max_priority_fee_per_gas,
        }

        try:
            signed = await scope.signer.sign_transaction(tx.wallet, tx_dict)
        except (VaultUnavailableError, ValueError, TypeError, Exception) as exc:  # noqa: BLE001
            # Sign failure: do NOT release nonce — original attempt may be in mempools.
            # Catches VaultUnavailableError, ValueError, TypeError, and any infra-layer
            # exception (e.g. SealError from EnvelopeSigner) without importing infra in api/.
            await scope.audit_repo.append(
                action="tx-replacement",
                decision="error",
                caller=caller.name,
                request_json=_canonical_json({"tx_id": tx_id}),
                decision_reason=f"sign_failure:{type(exc).__name__}",
            )
            await scope.audit_repo.commit()  # Core #5/#19
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "vault_unavailable",
                    "message": "signing failed; original attempt reservation intact",
                },
            ) from exc

        new_hash = "0x" + signed.hash.hex()
        new_signed_raw = "0x" + signed.raw_transaction.hex()
        now = datetime.now(UTC)

        # 6. Persist — attempt + hash + status update.
        await scope.attempt_repo.add_attempt(
            tx_id=tx_id,
            sequence_num=new_seq,
            gas=body.gas,
            max_fee_per_gas=body.max_fee_per_gas,
            max_priority_fee_per_gas=body.max_priority_fee_per_gas,
            signed_raw=new_signed_raw,
            hash=new_hash,
            created_at=now,
        )
        await scope.tx_repo.add_hash(tx_id, new_hash, sequence_num=new_seq)
        await scope.audit_repo.append(
            action="tx-replacement",
            decision="approved",
            caller=caller.name,
            request_json=_canonical_json({"tx_id": tx_id}),
            outcome=_canonical_json(
                {
                    "prev_seq": new_seq - 1,
                    "new_seq": new_seq,
                    "new_hash": new_hash,
                    "nonce": tx.nonce,
                }
            ),
        )
        # Approved path: ReplacementScopeCM.__aexit__ commits atomically.

    return SignReplacementResponse(
        tx_id=tx_id,
        signed_raw_tx=new_signed_raw,
        hash=new_hash,
        nonce=tx.nonce,
        attempt=new_seq,
    )
