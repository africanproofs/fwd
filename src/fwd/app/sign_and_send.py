"""Sign-and-send use case (Phase 3c).

Per architecture.md § Signing flow:
  1. Resolve wallet -> from_address (signer.address).
  2. Verify chain_id against the RPC node (rpc.verify_chain_id).
  3. Reserve nonce from DB (nonce_repo.reserve_next; lazy init via RPC on
     NonceNotInitializedError per architecture.md step 6).
  4. Fetch fee suggestion (rpc.fee_history).
  5. Estimate gas if not provided.
  6. Build EIP-1559 tx_dict.
  7. Sign in-process (signer.sign_transaction).
  8. Broadcast (rpc.send_raw_transaction).
  9. Persist transaction row + hash (tx_repo.create + add_hash).
  10. Return tx_id + tx hash + nonce.

Phase 3c does NOT include:
- Receipt watcher / replacement-on-stuck (Phase 5a6)
- Idempotency-Key handling (Phase 7; deferred from a6 to a7)

v0.4.0a3 adds:
- caller: str field on SignAndSendRequest (F8.1 — explicit, not via request.state).
- tx_id: str field on SignAndSendResult.
- tx_repo: TransactionRepo as 4th positional arg.
- Transaction row + hash persisted after successful broadcast.

v0.4.0a5 adds:
- nonce_repo: NonceRepo as 5th positional arg (BEGIN IMMEDIATE reservation).
- Reserve nonce from DB; lazy-init from RPC on first use per arch step 6.
- Pre-broadcast failure (steps 7, 10, 11) releases the reserved nonce.
- Broadcast failure (step 13) does NOT release — receipt watcher decides.

v0.5.0a6 adds:
- Policy gate (D14): caller/wallet/policy/registry/rate_repo/audit_repo
  keyword args; default-deny enforced before nonce reservation.
- Rate release-on-failure: pre-broadcast failures release rate buckets.
- Rate add_committed_value: post-broadcast-success increments wallet agg.
- Hash-chained audit row (D16): every request outcome appended to audit_log.
- Coston2 hardcoded-allowlist gate removed: policy is now sole authZ.
- ALLOWED_CHAINS import removed (no longer an authZ gate here).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from fwd.app.policy_gate import PolicyDenied as PolicyDenied  # re-export for api/sign.py
from fwd.app.policy_gate import gate, release_rate_after_failure
from fwd.infra.audit_repo import _canonical_json
from fwd.infra.nonce_repo import NonceNotInitializedError
from fwd.infra.rpc import RpcError, RpcUnavailable
from fwd.infra.uuidv7 import uuid7_str
from fwd.infra.vault_client import VaultError
from fwd.infra.wallet_repo import WalletNotFoundError

if TYPE_CHECKING:
    from fwd.domain.policy import Policy
    from fwd.infra.abi_registry import AbiRegistry
    from fwd.infra.audit_repo import AuditRepo
    from fwd.infra.caller_repo import Caller
    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.nonce_repo import NonceRepo
    from fwd.infra.rate_repo import RateRepo
    from fwd.infra.rpc import RpcClient
    from fwd.infra.transaction_repo import TransactionRepo
    from fwd.infra.wallet_repo import Wallet

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
    idempotency_key: str | None = None  # D14: per-caller scoped; missing = normal path


@dataclass(frozen=True)
class SignAndSendResult:
    tx_id: str
    hash: str
    nonce: int


class WalletNotFound(Exception):  # noqa: N818
    """404 - wallet name not in the wallets table."""


class ChainNotAllowed(Exception):  # noqa: N818
    """400 - chain_id is not in v0.3.0's allowlist (Coston2-only).

    Kept for backward-compat import from api/sign.py. Policy engine is now
    the sole authZ gate (v0.5.0a6); this class is effectively dead but
    harmless to keep.
    """


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


async def _audit(
    audit_repo: AuditRepo,
    request: SignAndSendRequest,
    caller: Caller,
    *,
    decision: str,
    decision_reason: str | None,
    outcome: str | None,
) -> None:
    """Append one audit row for this sign-and-send operation (D16)."""
    await audit_repo.append(
        action="sign-and-send",
        decision=decision,
        caller=caller.name,
        request_json=_canonical_json(
            {
                "wallet": request.wallet,
                "chain": request.chain,
                "to": request.to,
                "value_wei": request.value_wei,
                "data": request.data,
                "gas": request.gas,
            }
        ),
        decision_reason=decision_reason,
        outcome=outcome,
    )


async def sign_and_send(
    request: SignAndSendRequest,
    signer: EnvelopeSigner,
    rpc: RpcClient,
    tx_repo: TransactionRepo,
    nonce_repo: NonceRepo,
    *,
    caller: Caller,
    wallet: Wallet,
    policy: Policy,
    registry: AbiRegistry,
    rate_repo: RateRepo,
    audit_repo: AuditRepo,
) -> SignAndSendResult:
    # Defense-in-depth: caller must be a non-empty string <= 64 chars.
    if not request.caller or len(request.caller) > 64:
        raise ValueError("caller must be a non-empty string with len <= 64")

    # D14 idempotency replay — check BEFORE step 1 and BEFORE the policy gate.
    # If caller+key matches a prior transaction, return the cached result without
    # re-evaluating policy, reserving a nonce, or touching rate buckets.
    if request.idempotency_key is not None:
        existing = await tx_repo.get_by_idempotency_key(request.caller, request.idempotency_key)
        if existing is not None:
            hashes = await tx_repo.list_hashes_by_tx(existing.tx_id)
            cached_hash = hashes[0].hash_hex if hashes else ""
            orig_seq = await audit_repo.find_sign_and_send_seq(existing.tx_id)
            await audit_repo.append(
                action="sign-and-send-duplicate",
                decision="approved",
                caller=request.caller,
                request_json=_canonical_json(
                    {
                        "wallet": request.wallet,
                        "chain": request.chain,
                        "to": request.to,
                        "value_wei": request.value_wei,
                        "data": request.data,
                        "gas": request.gas,
                        "idempotency_key": request.idempotency_key,
                    }
                ),
                decision_reason="idempotency_replay",
                outcome=_canonical_json(
                    {
                        "original_tx_id": existing.tx_id,
                        "original_audit_seq": orig_seq,
                    }
                ),
            )
            return SignAndSendResult(
                tx_id=existing.tx_id,
                hash=cached_hash,
                nonce=existing.nonce,
            )

    # 1. Resolve wallet -> address.
    try:
        from_address = await signer.address(request.wallet)
    except WalletNotFoundError as exc:
        raise WalletNotFound(request.wallet) from exc

    # 2. Verify chain_id against RPC.
    try:
        await rpc.verify_chain_id()
    except (RpcUnavailable, RpcError) as exc:
        raise RpcUnreachable(str(exc)) from exc

    # Policy gate — BEFORE nonce reservation (D14 / v0.5.0a6).
    # The engine decodes intent + evaluates all 10 steps + increments rate buckets.
    now = datetime.now(UTC)
    try:
        allow = await gate(
            caller=caller,
            wallet=wallet,
            request=request,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            now=now,
        )
    except PolicyDenied as exc:
        await _audit(
            audit_repo,
            request,
            caller,
            decision="denied",
            decision_reason=str(exc),
            outcome=None,
        )
        # D16 / Core invariant #5: persist the forensic refusal row before
        # the exception propagates through session_scope (whose except-arm
        # rolls back). Gate runs BEFORE nonce reservation, so the only
        # other pending write is the D14 step-8/9 rate increment — which
        # SHOULD persist on a deny (the attempt is counted; deny does not
        # call release_rate_after_failure).
        await audit_repo.commit()
        raise

    # 3. Reserve nonce — DB is the source of truth (architecture.md step 6).
    try:
        nonce = await nonce_repo.reserve_next(request.wallet, request.chain)
    except NonceNotInitializedError:
        # First time signing for this (wallet, chain). Seed from chain.
        try:
            chain_count = await rpc.transaction_count(from_address, block="pending")
        except (RpcUnavailable, RpcError) as exc:
            raise RpcUnreachable(str(exc)) from exc
        await nonce_repo.init_for_wallet(request.wallet, request.chain, chain_count)
        nonce = await nonce_repo.reserve_next(request.wallet, request.chain)

    # 4-7. Pre-broadcast operations. On any failure here, release the reserved
    # nonce per architecture.md § Failure modes (steps 7, 10, 11).
    try:
        # 4. Fetch fee suggestion.
        try:
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

    except (RpcUnreachable, VaultUnavailableError, ValueError):
        # Pre-broadcast failure: release the reservation per architecture.md
        # § Failure modes (steps 7, 10, 11). Safe-conditional decrement;
        # may leave a gap if a concurrent reserver has advanced past us.
        released = await nonce_repo.release_if_unused(request.wallet, request.chain, nonce)
        logger.warning(
            "sign_and_send.pre_broadcast_failure",
            wallet=request.wallet,
            chain=request.chain,
            reserved_nonce=nonce,
            released=released,
        )
        # Release rate buckets (mirrors nonce release; D14 / v0.5.0a2 doctrine).
        await release_rate_after_failure(
            allow=allow,
            caller=caller,
            wallet=wallet,
            request=request,
            policy=policy,
            rate_repo=rate_repo,
            now=now,
        )
        await _audit(
            audit_repo,
            request,
            caller,
            decision="error",
            decision_reason="pre_broadcast_failure",
            outcome=None,
        )
        # Persist the forensic row + the just-applied nonce/rate releases
        # before the exception rolls back session_scope (D16 / Core #5).
        # reserve(+1) then release_if_unused(-1) net to zero, so the
        # committed nonce/rate state is correct.
        await audit_repo.commit()
        raise

    # 8. Broadcast (separate try; failure here does NOT release the nonce or rate —
    # the tx may have been seen by other nodes; receipt watcher decides).
    try:
        tx_hash = await rpc.send_raw_transaction(signed.raw_transaction)
    except (RpcUnavailable, RpcError) as exc:
        # Broadcast failure: do NOT release rate (tx may be in mempools).
        await _audit(
            audit_repo,
            request,
            caller,
            decision="error",
            decision_reason="broadcast_failure",
            outcome=None,
        )
        # Persist the forensic row before session_scope rolls back
        # (D16 / Core #5). Per the broadcast-failure doctrine the nonce/
        # rate are deliberately NOT released (the tx may be in mempools);
        # committing here keeps the reserved nonce, which is the intended
        # behavior — the receipt watcher decides the tx's fate.
        await audit_repo.commit()
        raise RpcUnreachable(str(exc)) from exc

    # 9. Persist transaction row + hash.
    tx_id = uuid7_str()
    contract_address = request.to
    method_name = request.data[:10] if len(request.data) >= 10 else request.data
    request_json = _canonical_json(
        {
            "wallet": request.wallet,
            "chain": request.chain,
            "to": request.to,
            "value_wei": request.value_wei,
            "data": request.data,
            "gas": request.gas,
        }
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
        idempotency_key=request.idempotency_key,
    )
    await tx_repo.add_hash(tx_id, tx_hash, sequence_num=1)

    # Post-broadcast-success: add committed value to wallet aggregate (D14).
    await rate_repo.add_committed_value(
        wallet=wallet.name,
        value_wei=int(request.value_wei),
        now=now,
    )

    # Audit row: approved (D16).
    await _audit(
        audit_repo,
        request,
        caller,
        decision="approved",
        decision_reason=None,
        outcome=_canonical_json({"tx_id": tx_id, "hash": tx_hash, "nonce": nonce}),
    )

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
