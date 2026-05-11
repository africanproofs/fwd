"""GET /v1/transactions/{tx_id} — caller-gated transaction status lookup.

Per architecture.md § API surface. Cross-caller isolation: a caller
querying another caller's tx_id receives 404 (NOT 403) so we don't leak
the existence of other callers' transactions.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from fwd.api.caller_auth import require_caller
from fwd.app.dependencies import Caller, TransactionRepoCM, get_transaction_repo

router = APIRouter()


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
