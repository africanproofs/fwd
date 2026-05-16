"""RpcClient unit tests with httpx.MockTransport."""

from __future__ import annotations

import httpx
import pytest

from fwd import settings as settings_mod
from fwd.infra.rpc import (
    ALLOWED_CHAINS,
    RpcClient,
    RpcError,
    RpcManager,
    RpcUnavailable,
)


def _set_rpc_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RPC_URL_COSTON2", "http://coston2:9650/ext/C/rpc")
    settings_mod.get_settings.cache_clear()


def test_allowed_chains_is_rpc_routing_set() -> None:
    # v0.5.0a6 lifted the v0.3.0 Coston2-only authZ gate. ALLOWED_CHAINS is
    # now the RPC-routing rail (chains fwd has a configured RPC URL for);
    # per-caller authorization is policy.yaml's job, not this set's.
    assert ALLOWED_CHAINS == frozenset({14, 19, 114})  # noqa: SIM300


def test_unconfigured_chain_construction_raises() -> None:
    http = httpx.AsyncClient()
    with pytest.raises(RpcError, match="no RPC URL configured"):
        RpcClient(1, "http://eth", http)  # chain 1 has no configured RPC URL in fwd


@pytest.mark.asyncio
async def test_verify_chain_id_happy(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_rpc_urls(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x72"})  # 114

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = RpcClient(114, "http://coston2", http)
    assert await client.verify_chain_id() == 114
    # cached on second call
    assert await client.verify_chain_id() == 114
    await http.aclose()


@pytest.mark.asyncio
async def test_chain_id_mismatch_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_rpc_urls(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0xe"})  # 14, not 114

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = RpcClient(114, "http://wrong-chain", http)
    with pytest.raises(RpcError, match="returned chain_id 14"):
        await client.verify_chain_id()
    await http.aclose()


@pytest.mark.asyncio
async def test_jsonrpc_error_response(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_rpc_urls(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32000, "message": "execution reverted"},
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = RpcClient(114, "http://coston2", http)
    with pytest.raises(RpcError, match="execution reverted"):
        await client.call("eth_call")
    await http.aclose()


@pytest.mark.asyncio
async def test_rpc_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_rpc_urls(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = RpcClient(114, "http://nope", http)
    with pytest.raises(RpcUnavailable):
        await client.call("eth_blockNumber")
    await http.aclose()


@pytest.mark.asyncio
async def test_send_raw_transaction(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_rpc_urls(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read()
        # Sanity: request body should contain the hex of our raw bytes.
        assert b"0x020102" in body
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0x" + "ab" * 32,
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = RpcClient(114, "http://coston2", http)
    h = await client.send_raw_transaction(b"\x02\x01\x02")
    assert h.startswith("0x")
    assert len(h) == 66  # 0x + 64 hex chars
    await http.aclose()


@pytest.mark.asyncio
async def test_transaction_count(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_rpc_urls(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x5"})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = RpcClient(114, "http://coston2", http)
    n = await client.transaction_count("0x" + "00" * 20)
    assert n == 5
    await http.aclose()


def test_rpc_manager_caches_per_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_rpc_urls(monkeypatch)
    mgr = RpcManager()
    a = mgr.for_chain(114)
    b = mgr.for_chain(114)
    assert a is b


@pytest.mark.asyncio
async def test_rpc_manager_aclose(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_rpc_urls(monkeypatch)
    mgr = RpcManager()
    _ = mgr.for_chain(114)
    await mgr.aclose()  # must not raise
