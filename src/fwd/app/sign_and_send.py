"""Sign-and-send use case (Phase 3c).

Per architecture.md § Signing flow:
  1. Resolve wallet -> from_address (signer.address).
  2. Verify chain_id against the RPC node (rpc.verify_chain_id).
  3. Fetch nonce (rpc.transaction_count, "pending").
  4. Fetch fee suggestion (rpc.fee_history).
  5. Estimate gas if not provided.
  6. Build EIP-1559 tx_dict.
  7. Sign in-process (signer.sign_transaction).
  8. Broadcast (rpc.send_raw_transaction).
  9. Persist transaction row + hash (tx_repo.create + add_hash).
  10. Return tx_id + tx hash + nonce.

Phase 3c does NOT include:
- Policy evaluation (Phase 7)
- Hash-chained audit row (Phase 7; we structlog only)
- BEGIN IMMEDIATE nonce serialization (Phase 5a4; race condition exists)
- Receipt watcher / replacement-on-stuck (Phase 5a5)
- Idempotency-Key handling (Phase 5a5 or Phase 7)

v0.4.0a3 adds:
- caller: str field on SignAndSendRequest (F8.1 — explicit, not via request.state).
- tx_id: str field on SignAndSendResult.
- tx_repo: TransactionRepo as 4th positional arg.
- Transaction row + hash persisted after successful broadcast.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from fwd.infra.rpc import ALLOWED_CHAINS as ALLOWED_CHAINS
from fwd.infra.rpc import RpcError, RpcUnavailable
from fwd.infra.uuidv7 import uuid7_str
from fwd.infra.vault_client import VaultError
from fwd.infra.wallet_repo import WalletNotFoundError

if TYPE_CHECKING:
    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.rpc import RpcClient
    from fwd.infra.transaction_repo import TransactionRepo

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class SignAndSendRequest:
    wallet: str
    caller: str  # F8.1: explicit caller identity, not from request.state
    chain: int
    to: str  # 0x-prefixed 20-byte hex
    value_wei: str  # decimal string (no SQLite uint256 in 3c, but stay consistent)
    data: str  # 0x-prefixed even-length hex (or "0x" for empty)
    gas: int | None = None  # optional override; otherwise estimate_gas + 25% buffer


@dataclass(frozen=True)
class SignAndSendResult:
    tx_id: str
    hash: str
    nonce: int


class WalletNotFound(Exception):  # noqa: N818
    """404 - wallet name not in the wallets table."""


class ChainNotAllowed(Exception):  # noqa: N818
    """400 - chain_id is not in v0.3.0's allowlist (Coston2-only)."""


class RpcUnreachable(Exception):  # noqa: N818
    """502 - RPC node unreachable, non-200, or returned an unexpected shape.

    Wraps both RpcUnavailable (transport) and RpcError (response shape)
    from infra into a single app-layer exception. The api layer maps to 502.
    """


class VaultUnavailableError(Exception):
    """503 - Vault unreachable or returned an error during decrypt/encrypt.

    Defined here (not re-imported from app/wallet_create) because the sign
    endpoint catches at its own boundary; importing across use cases would
    couple them unnecessarily.
    """


# Phase 3c fee defaults. Phase 7 may tune per chain.
_DEFAULT_TIP_WEI = 1_000_000_000  # 1 gwei
_GAS_ESTIMATE_BUFFER = 1.25  # +25% on estimate_gas


async def sign_and_send(
    request: SignAndSendRequest,
    signer: EnvelopeSigner,
    rpc: RpcClient,
    tx_repo: TransactionRepo,
) -> SignAndSendResult:
    # Defense-in-depth: caller must be a non-empty string <= 64 chars.
    if not request.caller or len(request.caller) > 64:
        raise ValueError("caller must be a non-empty string with len <= 64")

    if request.chain not in ALLOWED_CHAINS:
        raise ChainNotAllowed(
            f"chain_id={request.chain} not in v0.3.0 allowlist; "
            f"Phase 7 lifts this with policy.yaml"
        )

    # 1. Resolve wallet -> address.
    try:
        from_address = await signer.address(request.wallet)
    except WalletNotFoundError as exc:
        raise WalletNotFound(request.wallet) from exc

    # 2. Verify chain_id against RPC. 3. Fetch nonce. 4. Fetch fee suggestion.
    try:
        await rpc.verify_chain_id()
        nonce = await rpc.transaction_count(from_address, block="pending")
        fee = await rpc.fee_history(blocks=5)
    except (RpcUnavailable, RpcError) as exc:
        raise RpcUnreachable(str(exc)) from exc

    try:
        # baseFeePerGas[-1] is the projected next-block base fee.
        base_fee = int(fee["baseFeePerGas"][-1], 16)
    except (KeyError, ValueError, IndexError, TypeError) as exc:
        raise RpcUnreachable(f"unexpected eth_feeHistory shape: {exc}") from exc

    tip = _DEFAULT_TIP_WEI
    max_fee = base_fee * 2 + tip

    # 5. Estimate gas if caller didn't provide.
    if request.gas is None:
        call_obj = {
            "from": from_address,
            "to": request.to,
            "value": hex(int(request.value_wei)),
            "data": request.data,
        }
        try:
            estimated = await rpc.estimate_gas(call_obj)
        except (RpcUnavailable, RpcError) as exc:
            raise RpcUnreachable(str(exc)) from exc
        gas = int(estimated * _GAS_ESTIMATE_BUFFER)
    else:
        gas = request.gas

    # 6. Build EIP-1559 tx_dict.
    tx_dict = {
        "type": 2,
        "chainId": request.chain,
        "nonce": nonce,
        "to": request.to,
        "value": int(request.value_wei),
        "data": request.data,
        "gas": gas,
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": tip,
    }

    # 7. Sign in-process.
    try:
        signed = await signer.sign_transaction(request.wallet, tx_dict)
    except VaultError as exc:
        raise VaultUnavailableError(str(exc)) from exc

    # 8. Broadcast.
    try:
        tx_hash = await rpc.send_raw_transaction(signed.raw_transaction)
    except (RpcUnavailable, RpcError) as exc:
        raise RpcUnreachable(str(exc)) from exc

    # 9. Persist transaction row + hash.
    # DB write is after broadcast: if broadcast succeeds but DB write fails,
    # we have an on-chain tx with no DB row. Accepted in a3; a4 rearranges
    # to nonce-reserve-then-broadcast to eliminate this window.
    tx_id = uuid7_str()
    contract_address = request.to
    method_name = request.data[:10] if len(request.data) >= 10 else request.data
    request_json = json.dumps(
        {
            "wallet": request.wallet,
            "chain": request.chain,
            "to": request.to,
            "value_wei": request.value_wei,
            "data": request.data,
            "gas": request.gas,
        },
        sort_keys=True,
    )
    signed_raw_hex = "0x" + signed.raw_transaction.hex()

    await tx_repo.create(
        tx_id=tx_id,
        wallet=request.wallet,
        chain=request.chain,
        caller=request.caller,
        nonce=nonce,
        contract_address=contract_address,
        method_name=method_name,
        value_wei=request.value_wei,
        request_json=request_json,
        signed_raw=signed_raw_hex,
        status="submitted",
        submitted_at=datetime.now(UTC),
    )
    await tx_repo.add_hash(tx_id, tx_hash, sequence_num=1)

    # Per architecture.md hazards #3: log only non-secret fields.
    # NEVER log signed.raw_transaction, plaintext privkeys, or wallet
    # ciphertexts. tx_hash, nonce, addresses, and gas params are public.
    logger.info(
        "sign_and_send.ok",
        wallet=request.wallet,
        chain=request.chain,
        from_address=from_address,
        to=request.to,
        nonce=nonce,
        gas=gas,
        max_fee_per_gas=max_fee,
        tx_hash=tx_hash,
        tx_id=tx_id,
        caller=request.caller,
    )

    return SignAndSendResult(tx_id=tx_id, hash=tx_hash, nonce=nonce)
