"""Startup reconciliation: compare DB next_nonce to chain transaction count.

Per implementation-plan.md:122: "reconciliation on startup (compare DB
nonce to eth_getTransactionCount(latest) and warn on drift)."

Best-effort: this never raises into the lifespan. If RPC is unreachable
for a chain, log a warning and continue — fwd must boot even if the
upstream is degraded.

The watcher (v0.4.0a6) will retry reconciliation continuously.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from fwd.infra.nonce_repo import NonceRepo
    from fwd.infra.rpc import RpcManager
    from fwd.infra.wallet_repo import WalletRepo

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class DriftReport:
    wallet: str
    chain: int
    db_next_nonce: int
    chain_count: int
    drift: int  # signed: positive = DB ahead, negative = DB behind


async def reconcile_all(
    nonce_repo: NonceRepo,
    wallet_repo: WalletRepo,
    rpc_mgr: RpcManager,
) -> list[DriftReport]:
    """Walk all nonces rows; for each, fetch eth_getTransactionCount(latest)
    and log drift. Returns the drift reports (empty if no drift across all).

    Per Core invariant #18: this is best-effort reconciliation — drift is
    logged, not raised. Operator inspects logs for drift on startup; the
    Phase 5a6 receipt watcher re-reconciles continuously.
    """
    reports: list[DriftReport] = []
    nonces = await nonce_repo.list_all()
    for n in nonces:
        wallet = await wallet_repo.get_by_name(n.wallet, missing_ok=True)
        if wallet is None:
            logger.warning(
                "nonce_reconcile.orphan_nonce",
                wallet=n.wallet,
                chain=n.chain,
                reason="nonces row references wallet that no longer exists",
            )
            continue
        try:
            rpc = rpc_mgr.for_chain(n.chain)
            chain_count = await rpc.transaction_count(wallet.address, block="latest")
        except Exception as exc:
            logger.warning(
                "nonce_reconcile.rpc_failed",
                wallet=n.wallet,
                chain=n.chain,
                error=str(exc),
            )
            continue
        drift = n.next_nonce - chain_count
        if drift != 0:
            reports.append(
                DriftReport(
                    wallet=n.wallet,
                    chain=n.chain,
                    db_next_nonce=n.next_nonce,
                    chain_count=chain_count,
                    drift=drift,
                )
            )
            logger.warning(
                "nonce_reconcile.drift",
                wallet=n.wallet,
                chain=n.chain,
                db_next_nonce=n.next_nonce,
                chain_count=chain_count,
                drift=drift,
                interpretation=(
                    "db_ahead_of_chain (gaps from released reservations)"
                    if drift > 0
                    else "db_behind_chain (external use of key — investigate)"
                ),
            )
    return reports
