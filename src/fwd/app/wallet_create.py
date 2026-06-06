"""Wallet creation use case.

Coordinates between the EnvelopeSigner (which holds the create_wallet
flow) and the structlog audit. v0.5.0a7 adds the hash-chained audit-log
row (D16): one row per request, on the shared AdminScope session so it
commits atomically with the wallet INSERT.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from fwd.infra.audit_repo import _canonical_json
from fwd.infra.sealed_master import SealError
from fwd.infra.wallet_repo import WalletExistsError

if TYPE_CHECKING:
    from fwd.infra.audit_repo import AuditRepo
    from fwd.infra.envelope_signer import EnvelopeSigner

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class WalletCreateRequest:
    name: str
    policy_path: str


@dataclass(frozen=True)
class WalletCreateResult:
    name: str
    address: str


class WalletNameTaken(Exception):  # noqa: N818
    """409-equivalent."""


class VaultUnavailableError(Exception):
    """503-equivalent. Wraps infra SealError for the api layer."""


async def create_wallet(
    request: WalletCreateRequest,
    signer: EnvelopeSigner,
    *,
    audit_repo: AuditRepo,
) -> WalletCreateResult:
    """Run the wallet-create use case.

    Translates infra exceptions into app-layer exceptions. The api/ layer
    catches WalletNameTaken (→ 409) and VaultUnavailableError (→ 503).

    D16: one audit row is appended per call (success or known-failure) on
    the shared session (AdminScope) so it commits atomically with the wallet
    INSERT under BEGIN IMMEDIATE. caller=None (admin action, not a caller key).
    request_json carries name + policy_path only — NEVER privkey or ciphertext.
    """
    _request_json = _canonical_json({"name": request.name, "policy_path": request.policy_path})

    try:
        wallet = await signer.create_wallet(name=request.name, policy_path=request.policy_path)
    except WalletExistsError as exc:
        logger.info("wallet.create.exists", name=request.name)
        await audit_repo.append(
            action="wallet-create",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc).__name__}: {exc}",
        )
        await audit_repo.commit()
        raise WalletNameTaken(request.name) from exc
    except SealError as exc:
        logger.error("wallet.create.vault_error", error=str(exc))
        await audit_repo.append(
            action="wallet-create",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc).__name__}: {exc}",
        )
        await audit_repo.commit()
        raise VaultUnavailableError(str(exc)) from exc

    await audit_repo.append(
        action="wallet-create",
        decision="approved",
        caller=None,
        request_json=_request_json,
        outcome=_canonical_json({"address": wallet.address}),
    )
    logger.info(
        "wallet.create.ok",
        name=wallet.name,
        address=wallet.address,
        policy_path=wallet.policy_path,
    )
    return WalletCreateResult(name=wallet.name, address=wallet.address)
