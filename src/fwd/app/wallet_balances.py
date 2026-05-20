"""List native-token balances for fwd-custodied wallets per chain.

Use case behind `GET /v1/admin/wallets/balances` (api/wallets.py) and
`clifwd wallets balances` (cli/wallets.py). Read-only: queries
`eth_getBalance` per (wallet, chain) for each fwd-custodied wallet on each
chain the wallet is policy-authorized to transact on, derived from
`policy.permissions[*].contracts` via the small `_CONTRACT_CHAIN` table.

The default scope is *transacting wallets only* (those reachable from any
`permissions` allowlist); `include_all=True` returns every DB wallet
across `ALLOWED_CHAINS` (operator scan). RPC errors are per-(wallet, chain)
and populated on the entry; never abort the whole request. v1.1.0a7.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from fwd.infra.rpc import ALLOWED_CHAINS

if TYPE_CHECKING:
    from fwd.domain.policy import Policy
    from fwd.infra.rpc import RpcManager
    from fwd.infra.wallet_repo import WalletRepo


# Contract address (lowercased) → chain_id (Flare-family only). Used to
# derive the per-wallet implied-chain set from policy.permissions[*].contracts.
# Mirrors clif/clif/config.py's NetworkConfig (RewardManager +
# FlareSystemsManager per network). Extend when new known-and-policy-referenced
# contracts land (e.g. Phase 9b's flare-system-client / fdc-client). v1.1.0a7.
_CONTRACT_CHAIN: dict[str, int] = {
    # Flare (14)
    "0xc8f55c5aa2c752ee285bd872855c749f4ee6239b": 14,  # RewardManager
    "0x89e50dc0380e597ece79c8494baafd84537ad0d4": 14,  # FlareSystemsManager
    # Songbird (19)
    "0xe26ad68b17224951b5740f33926cc438764eb9a7": 19,  # RewardManager
    "0x421c69e22f48e14fc2d2ee3812c59bfb81c38516": 19,  # FlareSystemsManager
    # Coston2 (114)
    "0xb4f43e342c5c77e6fe060c0481fe313ff2503454": 114,  # RewardManager
    "0xbc1f76ceb521eb5484b8943b5462d08ea96617a1": 114,  # FlareSystemsManager
}


@dataclass(frozen=True)
class BalanceEntry:
    """One (wallet, chain) balance reading."""

    wallet: str
    address: str
    chain: int
    balance_wei: str  # decimal string (avoid JSON int overflow)
    balance_native: str  # 18-decimal human form (Flare-family native tokens use 18)
    error: str | None = None


@dataclass(frozen=True)
class BalancesResult:
    """List of balance entries + per-wallet warnings (e.g. contracts not in
    `_CONTRACT_CHAIN`; never silently drop)."""

    balances: list[BalanceEntry]
    warnings: list[str]


def _derive_implied_chains(policy: Policy) -> tuple[dict[str, set[int]], list[str]]:
    """For each wallet name reachable from any `permissions` allowlist, the
    set of chain_ids implied by its block(s)' contract addresses (via
    `_CONTRACT_CHAIN`). Surfaces a warning per (wallet, contract) where
    the contract isn't mapped — operator notices stale tables.
    """
    implied: dict[str, set[int]] = {}
    warnings: list[str] = []
    for path, block in policy.permissions.items():
        chains_in_block: set[int] = set()
        unmapped_contracts: list[str] = []
        for contract_addr in block.contracts:
            chain = _CONTRACT_CHAIN.get(contract_addr.lower())
            if chain is None:
                unmapped_contracts.append(contract_addr)
            else:
                chains_in_block.add(chain)
        for wname in block.wallet_allowlist:
            implied.setdefault(wname, set()).update(chains_in_block)
            for c in unmapped_contracts:
                warnings.append(
                    f"perm '{path}' allowlists '{wname}' on contract {c} "
                    f"which is not in the balances contract→chain table; skipped"
                )
    return implied, warnings


def _format_native(wei: int) -> str:
    """18-decimal human form. Trim trailing zeros for readability."""
    if wei == 0:
        return "0"
    s = f"{wei:019d}"  # pad so we always have at least 19 digits → safe slice
    whole = s[:-18] or "0"
    frac = s[-18:].rstrip("0")
    return f"{whole}.{frac}" if frac else whole


async def list_balances(
    policy: Policy,
    wallet_repo: WalletRepo,
    rpc_mgr: RpcManager,
    *,
    include_all: bool = False,
    chain_filter: int | None = None,
) -> BalancesResult:
    """Per-(wallet, chain) gas balance.

    Default (`include_all=False`): only wallets reachable from any
    `permissions` allowlist, on the chains implied by their block(s)'
    contracts.
    `include_all=True`: every DB wallet × `ALLOWED_CHAINS` (broad operator scan).
    `chain_filter`: intersect each (wallet, chain) work-set with `{chain_filter}`.

    RPC errors are per-(wallet, chain), recorded on the entry's `error`
    field; the request never aborts on a single bad chain.
    """
    db_wallets = await wallet_repo.list_all()
    addr_by_name = {w.name: w.address for w in db_wallets}
    implied, warnings = _derive_implied_chains(policy)

    pairs: list[tuple[str, int]] = []
    if include_all:
        for w in db_wallets:
            for c in sorted(ALLOWED_CHAINS):
                if chain_filter is None or c == chain_filter:
                    pairs.append((w.name, c))
    else:
        for wname in sorted(implied):
            for c in sorted(implied[wname]):
                if chain_filter is None or c == chain_filter:
                    pairs.append((wname, c))

    entries: list[BalanceEntry] = []
    for wname, chain in pairs:
        addr = addr_by_name.get(wname)
        if addr is None:
            warnings.append(
                f"wallet '{wname}' is in policy.permissions but absent from "
                f"the DB; skipped"
            )
            continue
        try:
            wei = await rpc_mgr.for_chain(chain).get_balance(addr)
            entries.append(
                BalanceEntry(
                    wallet=wname,
                    address=addr,
                    chain=chain,
                    balance_wei=str(wei),
                    balance_native=_format_native(wei),
                )
            )
        except Exception as exc:  # noqa: BLE001 — per-call: report, don't abort
            entries.append(
                BalanceEntry(
                    wallet=wname,
                    address=addr,
                    chain=chain,
                    balance_wei="0",
                    balance_native="0",
                    error=str(exc),
                )
            )

    return BalancesResult(balances=entries, warnings=warnings)
