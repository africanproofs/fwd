"""Sign-FSP-message use case (Phase 9a-ii).

EIP-191 personal-sign of a fwd-reconstructed FSP messageHash. NOT a tx: no
nonce, no broadcast, no receipt, no idempotency. RFC6979-deterministic, so a
retry yields a byte-identical signature — idempotency is unnecessary (a
future non-deterministic signer, Phase 10, would reopen this).

Core invariant #19 surface delta vs sign_transaction: there are NO nonce arms
(no nonce allocation). The arms here are: policy-deny; build-malformed
(defensive); sign/decrypt-fail. Each commits its forensic row on the shared
RequestScope session before re-raising.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from fwd.app.fsp_policy import fsp_gate, release_fsp_rate_after_failure
from fwd.app.policy_gate import PolicyDenied as PolicyDenied  # re-export for api
from fwd.domain.fsp_message import REWARD_DISTRIBUTION, UPTIME, VOTER_REGISTRATION, build_fsp_message
from fwd.infra.audit_repo import _canonical_json
from fwd.infra.sealed_master import SealError
from fwd.infra.wallet_repo import WalletNotFoundError

if TYPE_CHECKING:
    from fwd.domain.policy import Policy
    from fwd.infra.audit_repo import AuditRepo
    from fwd.infra.caller_repo import Caller
    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.rate_repo import RateRepo

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class SignFspMessageRequest:
    wallet: str
    caller: str
    message_type: str
    reward_epoch_id: int
    chain_id: int | None = None
    no_of_weight_based_claims: int | None = None
    rewards_hash: str | None = None
    address: str | None = None
    signing_policy: str | None = None
    payload: str | None = None
    protocol_id: int | None = None
    registration_variant: str | None = None


@dataclass(frozen=True)
class SignFspMessageResult:
    message_hash: str  # 0x + 64 hex
    v: int
    r: str  # 0x hex
    s: str  # 0x hex
    signature: str  # 0x + 130 hex


class WalletNotFound(Exception):  # noqa: N818
    """404 — wallet name not in the wallets table."""


class FspMessageMalformed(Exception):  # noqa: N818
    """422 — build_fsp_message returned None (defensive; the API layer
    validates shape first, so this is an unexpected internal refusal)."""


class VaultUnavailableError(Exception):
    """503 — sealed-master decrypt failed during signing."""


async def _audit(
    audit_repo: AuditRepo,
    request: SignFspMessageRequest,
    caller: Caller,
    *,
    decision: str,
    decision_reason: str | None,
    outcome: str | None,
) -> None:
    await audit_repo.append(
        action="fsp-sign-message",
        decision=decision,
        caller=caller.name,
        request_json=_canonical_json(
            {
                "wallet": request.wallet,
                "message_type": request.message_type,
                "reward_epoch_id": request.reward_epoch_id,
                "chain_id": request.chain_id,
                "no_of_weight_based_claims": request.no_of_weight_based_claims,
                "rewards_hash": request.rewards_hash,
                "address": request.address,
                "signing_policy": request.signing_policy,
                "payload": request.payload,
                "protocol_id": request.protocol_id,
                "registration_variant": request.registration_variant,
            }
        ),
        decision_reason=decision_reason,
        outcome=outcome,
    )


async def sign_fsp_message(
    request: SignFspMessageRequest,
    signer: EnvelopeSigner,
    *,
    caller: Caller,
    policy: Policy,
    rate_repo: RateRepo,
    audit_repo: AuditRepo,
) -> SignFspMessageResult:
    if not request.caller or len(request.caller) > 64:
        raise ValueError("caller must be a non-empty string with len <= 64")

    # 1. Resolve wallet -> address (existence check; no chain interaction).
    try:
        await signer.address(request.wallet)
    except WalletNotFoundError as exc:
        raise WalletNotFound(request.wallet) from exc

    now = datetime.now(UTC)

    # 2. FSP policy gate (incl. fsp rate increment) — BEFORE signing.
    try:
        allow = await fsp_gate(
            caller=caller, request=request, policy=policy, rate_repo=rate_repo, now=now
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
        await audit_repo.commit()  # Core #19 ARM 1 (deny keeps the rate increment)
        raise

    # 3. Reconstruct the FSP messageHash (typed -> bytes; fwd builds it).
    # chain_id is used at the policy gate for replay-scoping across all types,
    # but is only folded into the message hash for REWARD_DISTRIBUTION and
    # VOTER_REGISTRATION chain_scoped. UPTIME, SIGNING_POLICY, PROTOCOL_PAYLOAD,
    # and VOTER_REGISTRATION legacy all keep chain_id out of the hash.
    build_chain_id: int | None
    if request.message_type in (UPTIME,):
        build_chain_id = None
    elif request.message_type == VOTER_REGISTRATION and request.registration_variant == "legacy":
        build_chain_id = None
    elif request.message_type in ("SIGNING_POLICY", "PROTOCOL_PAYLOAD"):
        build_chain_id = None
    else:
        # REWARD_DISTRIBUTION and VOTER_REGISTRATION chain_scoped include chain_id in hash
        build_chain_id = request.chain_id
    built = build_fsp_message(
        request.message_type,
        request.reward_epoch_id,
        chain_id=build_chain_id,
        no_of_weight_based_claims=request.no_of_weight_based_claims,
        rewards_hash=request.rewards_hash,
        address=request.address,
        signing_policy=request.signing_policy,
        payload=request.payload,
        protocol_id=request.protocol_id,
        registration_variant=request.registration_variant,
    )
    if built is None:
        await release_fsp_rate_after_failure(allow=allow, rate_repo=rate_repo, now=now)
        await _audit(
            audit_repo,
            request,
            caller,
            decision="error",
            decision_reason="fsp_message_malformed",
            outcome=None,
        )
        await audit_repo.commit()  # Core #19 ARM 2 (rate released -> net zero)
        raise FspMessageMalformed(request.message_type)

    # 4. EIP-191 personal-sign the reconstructed messageHash.
    try:
        signed = await signer.sign_fsp_eip191(request.wallet, built.message_hash)
    except SealError as exc:
        await release_fsp_rate_after_failure(allow=allow, rate_repo=rate_repo, now=now)
        await _audit(
            audit_repo,
            request,
            caller,
            decision="error",
            decision_reason="sign_failure",
            outcome=None,
        )
        await audit_repo.commit()  # Core #19 ARM 3 (rate released -> net zero)
        raise VaultUnavailableError(str(exc)) from exc

    message_hash_hex = "0x" + signed.message_hash.hex()
    r_hex = "0x" + format(signed.r, "064x")
    s_hex = "0x" + format(signed.s, "064x")
    sig_hex = "0x" + signed.signature.hex()

    # 5. Approved audit row. No explicit commit — the clean path commits once
    # via session_scope on scope exit (mirrors sign_transaction approved path).
    # The signature is a CAPABILITY-BEARING artifact (anyone holding it can
    # submit it), recorded because forensically required (no on-chain tx hash
    # anchors an FSP signature); it lives at the same trust boundary as the
    # hash-chained log + its Litestream replica. NEVER log/record the privkey.
    await _audit(
        audit_repo,
        request,
        caller,
        decision="approved",
        decision_reason=None,
        outcome=_canonical_json(
            {
                "message_hash": message_hash_hex,
                "v": signed.v,
                "r": r_hex,
                "s": s_hex,
                "signature": sig_hex,
            }
        ),
    )
    logger.info(
        "sign_fsp_message.ok",
        wallet=request.wallet,
        caller=request.caller,
        message_type=request.message_type,
        reward_epoch_id=request.reward_epoch_id,
        message_hash=message_hash_hex,
    )
    return SignFspMessageResult(
        message_hash=message_hash_hex, v=signed.v, r=r_hex, s=s_hex, signature=sig_hex
    )
