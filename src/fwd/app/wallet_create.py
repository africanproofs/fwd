"""Wallet creation use case.

Coordinates between the EnvelopeSigner (which holds the create_wallet
flow) and the structlog audit. Phase 7 will add the hash-chained
audit-log row here; for Phase 3b, just structlog.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from fwd.infra.vault_client import VaultError
from fwd.infra.wallet_repo import WalletExistsError

if TYPE_CHECKING:
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
    """503-equivalent. Wraps infra VaultError for the api layer."""


async def create_wallet(
    request: WalletCreateRequest, signer: EnvelopeSigner
) -> WalletCreateResult:
    """Run the wallet-create use case.

    Translates infra exceptions into app-layer exceptions. The api/ layer
    catches WalletNameTaken (→ 409) and VaultUnavailableError (→ 503).
    """
    try:
        wallet = await signer.create_wallet(
            name=request.name, policy_path=request.policy_path
        )
    except WalletExistsError as exc:
        logger.info("wallet.create.exists", name=request.name)
        raise WalletNameTaken(request.name) from exc
    except VaultError as exc:
        logger.error("wallet.create.vault_error", error=str(exc))
        raise VaultUnavailableError(str(exc)) from exc
    logger.info(
        "wallet.create.ok",
        name=wallet.name,
        address=wallet.address,
        policy_path=wallet.policy_path,
    )
    return WalletCreateResult(name=wallet.name, address=wallet.address)
