"""List wallets -- admin-only use case.

Mirrors app/caller_list.py. Returns every wallet ordered by created_at.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fwd.infra.wallet_repo import Wallet, WalletRepo


async def list_wallets(repo: WalletRepo) -> list[Wallet]:
    """Return all wallets, ordered by created_at (oldest first).

    No filtering -- admin endpoint. Caller-facing endpoints (Phase 7) will
    filter by policy.yaml's wallet_allowlist. The Wallet dataclass exposes
    privkey_ciphertext and vault_master_key; the api/ layer is responsible
    for stripping both from the response (NEVER return them to the client).
    """
    return await repo.list_all()
