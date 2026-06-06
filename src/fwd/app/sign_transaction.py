"""Sign-transaction use case (v1.1.0a9 — zero-egress, sign-only).

Per architecture.md § Signing flow (updated):
  1. Resolve wallet -> from_address (signer.address).
  2. Sanity-cap validation (gas / fee params).
  3. Policy gate — default-deny; BEFORE nonce reservation (D14).
  4. Reserve nonce from DB (nonce_repo.reserve_next; NonceNotInitialized
     if not seeded — caller must POST /v1/admin/nonce-init first).
  5. Build EIP-1559 tx_dict from caller-supplied gas/fee fields.
  6. Sign in-process (signer.sign_transaction).
  7. Persist transaction row + hash (tx_repo.create + add_hash).
  8. Return tx_id + signed_raw_tx + tx hash + nonce.

fwd no longer calls any RPC. Nonce seeding, fee estimation, and broadcast
are the CLIENT's responsibility. fwd signs and returns the raw bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog
from eth_utils.address import to_checksum_address

from fwd.app.policy_gate import PolicyDenied as PolicyDenied  # re-export for api/sign.py
from fwd.app.policy_gate import gate, release_rate_after_failure
from fwd.infra.audit_repo import _canonical_json
from fwd.infra.nonce_repo import NonceNotInitializedError
from fwd.infra.sealed_master import SealError
from fwd.infra.uuidv7 import uuid7_str
from fwd.infra.wallet_repo import WalletNotFoundError
from fwd.settings import get_settings

if TYPE_CHECKING:
    from fwd.domain.policy import Policy
    from fwd.infra.abi_registry import AbiRegistry
    from fwd.infra.audit_repo import AuditRepo
    from fwd.infra.caller_repo import Caller
    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.nonce_repo import NonceRepo
    from fwd.infra.rate_repo import RateRepo
    from fwd.infra.transaction_repo import TransactionAttemptRepo, TransactionRepo
    from fwd.infra.wallet_repo import Wallet

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class SignTransactionRequest:
    wallet: str
    caller: str
    chain: int
    to: str                        # 0x-prefixed 20-byte hex
    value_wei: str                 # decimal string
    data: str                      # 0x-prefixed even-length hex (or "0x")
    gas: int                       # REQUIRED (no estimate_gas)
    max_fee_per_gas: int           # REQUIRED (client supplies; fwd cannot fetch)
    max_priority_fee_per_gas: int  # REQUIRED
    idempotency_key: str | None = None


@dataclass(frozen=True)
class SignTransactionResult:
    tx_id: str
    hash: str            # locally computed: "0x" + signed.hash.hex()
    signed_raw_tx: str   # "0x" + signed.raw_transaction.hex() — the client broadcasts this
    nonce: int


class WalletNotFound(Exception):  # noqa: N818
    """404 - wallet name not in the wallets table."""


class VaultUnavailableError(Exception):
    """503 - sealed master unavailable or decrypt error during signing."""


class NonceNotInitialized(Exception):  # noqa: N818
    """409 - no nonces row for (wallet, chain); call POST /v1/admin/nonce-init
    (zero-egress: fwd cannot seed next_nonce from chain)."""


class TxParamsRejected(Exception):  # noqa: N818
    """400 - gas/fee params violate sanity caps (FWD_MAX_GAS / FWD_MAX_FEE_PER_GAS)
    or the EIP-1559 rule (max_priority_fee_per_gas <= max_fee_per_gas)."""


class IdempotencyConflict(Exception):  # noqa: N818
    """409 - an idempotency_key was reused with a DIFFERENT request body.
    The key already maps to a prior transaction whose canonical body differs;
    returning the cached signed tx would silently sign the wrong intent."""


async def _audit(
    audit_repo: AuditRepo,
    request: SignTransactionRequest,
    caller: Caller,
    *,
    decision: str,
    decision_reason: str | None,
    outcome: str | None,
) -> None:
    """Append one audit row for this sign-transaction operation (D16)."""
    await audit_repo.append(
        action="sign-transaction",
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
                "max_fee_per_gas": request.max_fee_per_gas,
                "max_priority_fee_per_gas": request.max_priority_fee_per_gas,
            }
        ),
        decision_reason=decision_reason,
        outcome=outcome,
    )


async def sign_transaction(
    request: SignTransactionRequest,
    signer: EnvelopeSigner,
    tx_repo: TransactionRepo,
    nonce_repo: NonceRepo,
    *,
    caller: Caller,
    wallet: Wallet,
    policy: Policy,
    registry: AbiRegistry,
    rate_repo: RateRepo,
    audit_repo: AuditRepo,
    attempt_repo: TransactionAttemptRepo | None = None,
) -> SignTransactionResult:
    # Defense-in-depth: caller must be a non-empty string <= 64 chars.
    if not request.caller or len(request.caller) > 64:
        raise ValueError("caller must be a non-empty string with len <= 64")

    # D14 idempotency replay — check BEFORE step 1 and BEFORE the policy gate.
    # If caller+key matches a prior transaction, return the cached result without
    # re-evaluating policy, reserving a nonce, or touching rate buckets.
    if request.idempotency_key is not None:
        existing = await tx_repo.get_by_idempotency_key(request.caller, request.idempotency_key)
        if existing is not None:
            # Body-check: the key must map to the SAME request body. A reused
            # key with a differing body is a client bug — returning the cached
            # signed tx would hand back the wrong intent. Reject with 409.
            incoming_body = _canonical_json(
                {
                    "wallet": request.wallet,
                    "chain": request.chain,
                    "to": request.to,
                    "value_wei": request.value_wei,
                    "data": request.data,
                    "gas": request.gas,
                    "max_fee_per_gas": request.max_fee_per_gas,
                    "max_priority_fee_per_gas": request.max_priority_fee_per_gas,
                }
            )
            if incoming_body != existing.request_json:
                await _audit(
                    audit_repo,
                    request,
                    caller,
                    decision="denied",
                    decision_reason="idempotency_key_body_mismatch",
                    outcome=_canonical_json({"original_tx_id": existing.tx_id}),
                )
                await audit_repo.commit()
                raise IdempotencyConflict(request.idempotency_key)
            hashes = await tx_repo.list_hashes_by_tx(existing.tx_id)
            cached_hash = hashes[0].hash_hex if hashes else ""
            orig_seq = await audit_repo.find_sign_transaction_seq(existing.tx_id)
            await audit_repo.append(
                action="sign-transaction-duplicate",
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
                        "max_fee_per_gas": request.max_fee_per_gas,
                        "max_priority_fee_per_gas": request.max_priority_fee_per_gas,
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
            return SignTransactionResult(
                tx_id=existing.tx_id,
                hash=cached_hash,
                signed_raw_tx=existing.signed_raw or "",
                nonce=existing.nonce,
            )

    # 1. Resolve wallet -> address.
    try:
        from_address = await signer.address(request.wallet)
    except WalletNotFoundError as exc:
        raise WalletNotFound(request.wallet) from exc

    # 2. Sanity-cap validation (NEW — BEFORE the policy gate so no rate
    # bucket is touched on a cap reject).
    s = get_settings()
    if request.max_priority_fee_per_gas > request.max_fee_per_gas:
        reason = "max_priority_fee_per_gas exceeds max_fee_per_gas"
    elif request.gas > s.fwd_max_gas:
        reason = f"gas {request.gas} exceeds FWD_MAX_GAS {s.fwd_max_gas}"
    elif request.max_fee_per_gas > s.fwd_max_fee_per_gas:
        reason = f"max_fee_per_gas {request.max_fee_per_gas} exceeds FWD_MAX_FEE_PER_GAS {s.fwd_max_fee_per_gas}"
    else:
        reason = None
    if reason is not None:
        await _audit(audit_repo, request, caller, decision="denied",
                     decision_reason=reason, outcome=None)
        await audit_repo.commit()          # forensic row survives rollback (Core #5/#19)
        raise TxParamsRejected(reason)

    # 3. Policy gate — BEFORE nonce reservation (D14 / v0.5.0a6).
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
        logger.warning(
            "sign.denied",
            caller=request.caller,
            wallet=request.wallet,
            step=exc.step,
            reason=exc.reason,
        )
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

    # 4. Reserve nonce — DB is the source of truth (zero-egress: no chain seed).
    try:
        nonce = await nonce_repo.reserve_next(request.wallet, request.chain)
    except NonceNotInitializedError as exc:
        await release_rate_after_failure(
            allow=allow,
            caller=caller,
            wallet=wallet,
            request=request,
            policy=policy,
            rate_repo=rate_repo,
            now=now,
        )
        await _audit(audit_repo, request, caller, decision="error",
                     decision_reason="nonce_not_initialized", outcome=None)
        await audit_repo.commit()          # Core #5/#19
        raise NonceNotInitialized(
            f"(wallet={request.wallet}, chain={request.chain}) has no nonce; "
            f"call POST /v1/admin/nonce-init") from exc

    # 5-6. Build tx_dict + sign. On failure: release nonce + rate, audit error, commit + raise.
    try:
        tx_dict = {
            "type": 2,
            "chainId": request.chain,
            "nonce": nonce,
            # eth_account requires an EIP-55 checksummed address and raises
            # TypeError on a non-checksummed `to` (clients commonly send
            # lowercase — the AP frontend standard is even lowercase). Normalize
            # here so any valid-hex casing signs. `to` already passed the
            # 0x-20-byte-hex validator, so to_checksum_address cannot fail.
            "to": to_checksum_address(request.to),
            "value": int(request.value_wei),
            "data": request.data,
            "gas": request.gas,
            "maxFeePerGas": request.max_fee_per_gas,
            "maxPriorityFeePerGas": request.max_priority_fee_per_gas,
        }
        try:
            signed = await signer.sign_transaction(request.wallet, tx_dict)
        except SealError as exc:
            raise VaultUnavailableError(str(exc)) from exc

    except (VaultUnavailableError, ValueError, TypeError):
        # Pre-sign failure: release the reservation. TypeError is included
        # because eth_account raises it (not ValueError) on an invalid tx field
        # — the v1.1.0a12 live drill found a non-checksummed `to` raised
        # TypeError, which previously escaped this arm, leaked a 500, AND left
        # the reserved nonce wedged (a permanent gap). The deeper rule: ANY
        # error between nonce reservation and a persisted signed tx MUST release
        # the nonce, never wedge it (Core invariant #11 spirit; partners #14/#19).
        released = await nonce_repo.release_if_unused(request.wallet, request.chain, nonce)
        logger.warning(
            "sign_transaction.pre_sign_failure",
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
            decision_reason="pre_sign_failure",
            outcome=None,
        )
        # Persist the forensic row + the just-applied nonce/rate releases
        # before the exception rolls back session_scope (D16 / Core #5).
        await audit_repo.commit()
        raise

    # 7. Compute hash + persist transaction row (no broadcast — client broadcasts).
    tx_hash = "0x" + signed.hash.hex()
    signed_raw_hex = "0x" + signed.raw_transaction.hex()
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
            "max_fee_per_gas": request.max_fee_per_gas,
            "max_priority_fee_per_gas": request.max_priority_fee_per_gas,
        }
    )

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
        status="pending",           # post-sign / pre-broadcast (NOT "submitted")
        submitted_at=None,          # the client has not broadcast yet
        idempotency_key=request.idempotency_key,
        reserved_at=now,            # set at sign time for orphan-lease detection (a13)
    )
    await tx_repo.add_hash(tx_id, tx_hash, sequence_num=1)
    if attempt_repo is not None:
        await attempt_repo.add_attempt(
            tx_id=tx_id,
            sequence_num=1,
            gas=request.gas,
            max_fee_per_gas=request.max_fee_per_gas,
            max_priority_fee_per_gas=request.max_priority_fee_per_gas,
            signed_raw=signed_raw_hex,
            hash=tx_hash,
            created_at=now,
        )
    await rate_repo.add_committed_value(wallet=wallet.name, value_wei=int(request.value_wei), now=now)
    await _audit(
        audit_repo,
        request,
        caller,
        decision="approved",
        decision_reason=None,
        outcome=_canonical_json({"tx_id": tx_id, "hash": tx_hash, "nonce": nonce}),
    )

    logger.info(
        "sign_transaction.ok",
        wallet=request.wallet,
        chain=request.chain,
        from_address=from_address,
        to=request.to,
        nonce=nonce,
        gas=request.gas,
        max_fee_per_gas=request.max_fee_per_gas,
        tx_hash=tx_hash,
        tx_id=tx_id,
        caller=request.caller,
    )

    return SignTransactionResult(
        tx_id=tx_id,
        hash=tx_hash,
        signed_raw_tx=signed_raw_hex,
        nonce=nonce,
    )
