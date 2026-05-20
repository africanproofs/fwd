"""Async JSON-RPC client for EVM chains.

Per architecture.md § Signing flow steps 7, 9-13, 16, fwd talks to chain
RPCs over JSON-RPC/HTTP. v1 supports Flare (chain_id=14), Songbird (19),
Coston2 (114). v0.5.0a6 lifted the v0.3.0 Coston2-only authZ gate: the
policy engine is now the sole authorization. ALLOWED_CHAINS remains as
the RPC-routing rail — the set of chains fwd has a configured RPC URL
for (you cannot sign on a chain fwd cannot reach); per-caller authZ is
policy.yaml's job, not this set's.

Public surface:
- ALLOWED_CHAINS — frozenset[int] of chains fwd has an RPC URL for.
- RpcError — JSON-RPC returned an error or unexpected shape.
- RpcUnavailable — node unreachable or non-200 HTTP.
- RpcClient — per-chain RPC handle. Constructed via RpcManager.for_chain().
- RpcManager — owns the httpx pool, lazily caches RpcClient per chain_id.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from fwd.settings import get_settings

logger = structlog.get_logger(__name__)

# Chain ID -> human label for logs and error messages.
CHAIN_LABELS: dict[int, str] = {
    14: "flare",
    19: "songbird",
    114: "coston2",
}

# Chains fwd has a configured RPC URL for (RPC-routing rail, NOT authZ —
# v0.5.0a6 lifted the Coston2-only authZ gate; policy.yaml authorizes).
# Must stay in lockstep with _resolve_url's supported chain_ids.
ALLOWED_CHAINS: frozenset[int] = frozenset({14, 19, 114})  # Flare, Songbird, Coston2


class RpcError(Exception):
    """RPC call returned a JSON-RPC error or an unexpected response shape."""


class RpcUnavailable(Exception):  # noqa: N818
    """RPC node is unreachable or returned non-200 HTTP."""


def _resolve_url(chain_id: int) -> str:
    s = get_settings()
    if chain_id == 14:
        return s.rpc_url_flare
    if chain_id == 19:
        return s.rpc_url_songbird
    if chain_id == 114:
        return s.rpc_url_coston2
    raise RpcError(f"unknown chain_id: {chain_id}")


class RpcClient:
    """Per-chain JSON-RPC client.

    Constructed via RpcManager.for_chain(); shares an httpx.AsyncClient
    across chains for connection pooling. The caller verifies chain_id
    via verify_chain_id() on first use to catch URL/chain mismatch.
    """

    def __init__(self, chain_id: int, url: str, http: httpx.AsyncClient) -> None:
        if chain_id not in ALLOWED_CHAINS:
            raise RpcError(
                f"chain_id={chain_id} has no RPC URL configured in fwd "
                f"(supported: {sorted(ALLOWED_CHAINS)}). This is an RPC-routing "
                f"limit, not authZ — policy.yaml authorizes per caller."
            )
        self._chain_id = chain_id
        self._url = url
        self._http = http
        self._verified_chain_id: int | None = None
        self._next_id = 1

    @property
    def chain_id(self) -> int:
        return self._chain_id

    async def call(self, method: str, params: list[Any] | None = None) -> Any:
        """Make a JSON-RPC call. Returns the 'result' field; raises on error."""
        body = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": self._next_id,
        }
        self._next_id += 1
        try:
            r = await self._http.post(self._url, json=body)
        except httpx.HTTPError as exc:
            raise RpcUnavailable(f"rpc {self._chain_id} {method}: {exc}") from exc
        if r.status_code != 200:
            raise RpcUnavailable(
                f"rpc {self._chain_id} {method}: HTTP {r.status_code} {r.text[:200]}"
            )
        try:
            data = r.json()
        except ValueError as exc:
            raise RpcError(f"rpc {self._chain_id} {method}: invalid JSON") from exc
        if "error" in data:
            err = data["error"]
            raise RpcError(
                f"rpc {self._chain_id} {method}: " f"{err.get('code')} {err.get('message', '')}"
            )
        if "result" not in data:
            raise RpcError(f"rpc {self._chain_id} {method}: no 'result' field")
        return data["result"]

    async def verify_chain_id(self) -> int:
        """Call eth_chainId once, verify it matches the configured chain_id, cache."""
        if self._verified_chain_id is not None:
            return self._verified_chain_id
        result = await self.call("eth_chainId")
        on_chain = int(result, 16) if isinstance(result, str) else int(result)
        if on_chain != self._chain_id:
            raise RpcError(
                f"rpc returned chain_id {on_chain} but client configured for "
                f"{self._chain_id}; check RPC_URL_* in .env"
            )
        self._verified_chain_id = on_chain
        return on_chain

    async def transaction_count(self, address: str, block: str = "pending") -> int:
        result = await self.call("eth_getTransactionCount", [address, block])
        return int(result, 16)

    async def fee_history(self, blocks: int = 5) -> dict[str, Any]:
        result = await self.call("eth_feeHistory", [hex(blocks), "pending", []])
        return dict(result)

    async def estimate_gas(self, tx: dict[str, Any]) -> int:
        result = await self.call("eth_estimateGas", [tx])
        return int(result, 16)

    async def send_raw_transaction(self, raw_bytes: bytes) -> str:
        """Broadcast. Returns the tx hash hex (0x-prefixed)."""
        raw_hex = "0x" + raw_bytes.hex()
        result = await self.call("eth_sendRawTransaction", [raw_hex])
        if not isinstance(result, str) or not result.startswith("0x"):
            raise RpcError(f"unexpected eth_sendRawTransaction response: {result!r}")
        return result

    async def transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        """Returns the receipt dict or None if not yet mined."""
        result = await self.call("eth_getTransactionReceipt", [tx_hash])
        return dict(result) if result is not None else None

    async def get_balance(self, address: str) -> int:
        """`eth_getBalance(address, 'latest')` → int (wei)."""
        result = await self.call("eth_getBalance", [address, "latest"])
        return int(result, 16)


class RpcManager:
    """Per-request RPC client manager.

    Owns a single httpx.AsyncClient (connection pool) and lazily caches
    RpcClient instances per chain_id. Closed via aclose() at request end.
    """

    def __init__(self) -> None:
        self._http = httpx.AsyncClient(timeout=10.0)
        self._cache: dict[int, RpcClient] = {}

    def for_chain(self, chain_id: int) -> RpcClient:
        if chain_id not in self._cache:
            url = _resolve_url(chain_id)
            self._cache[chain_id] = RpcClient(chain_id, url, self._http)
        return self._cache[chain_id]

    async def aclose(self) -> None:
        await self._http.aclose()
