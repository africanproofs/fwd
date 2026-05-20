"""Tests for the v1.1.0a7 `wallets balances` feature.

Covers the use case (`fwd.app.wallet_balances.list_balances` + its
`_derive_implied_chains` helper) and the HTTP endpoint
(`GET /v1/admin/wallets/balances`). Real-RPC integration smoke is at the
bottom, env-gated behind `FWD_LIVE_RPC=1` (skipped by default; Core #14).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fwd import settings as settings_mod
from fwd.api.wallets import router
from fwd.app.dependencies import get_rpc_manager, get_wallet_repo
from fwd.app.wallet_balances import (
    _derive_implied_chains,
    _format_native,
    list_balances,
)
from fwd.domain.policy import (
    ContractRule,
    MethodRule,
    PermissionBlock,
    Policy,
)
from fwd.infra.wallet_repo import Wallet

# Canonical addresses (mirrors the use case's `_CONTRACT_CHAIN`).
_FLR_RM = "0xC8f55c5aA2C752eE285Bd872855C749f4ee6239B"  # Flare RewardManager
_FLR_FSM = "0x89e50DC0380e597ecE79c8494bAAFD84537AD0D4"  # Flare FlareSystemsManager
_SGB_RM = "0xE26AD68b17224951b5740F33926Cc438764eB9a7"  # Songbird RewardManager
_C2_RM = "0xB4f43E342c5c77e6fe060c0481Fe313Ff2503454"  # Coston2 RewardManager
_UNKNOWN = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"  # not in _CONTRACT_CHAIN


def _wallet(name: str, address: str) -> Wallet:
    return Wallet(
        name=name,
        address=address,
        privkey_ciphertext="seal:v1:NEVER_LEAK",
        vault_master_key="local:v1",
        policy_path=f"wc/{name}",
        created_at=datetime.now(UTC),
    )


def _claim_block(contract: str, wallet_name: str) -> PermissionBlock:
    return PermissionBlock(
        contracts={
            contract: ContractRule(
                abi="reward_manager",
                methods={
                    "claim(address,address,uint24,bool,(bytes32[],(uint24,bytes20,uint120,uint8))[])":
                        MethodRule(max_value_wei="0"),
                },
            ),
        },
        wallet_allowlist=[wallet_name],
        rate=None,
    )


def _policy(perms: dict[str, PermissionBlock]) -> Policy:
    return Policy(version=1, permissions=perms)


# ----- _derive_implied_chains -------------------------------------------------


def test_implied_chains_single_flare_wallet() -> None:
    """Wallet in a Flare-RM-and-FSM block -> implied = {14}, no warnings."""
    blk_rm = _claim_block(_FLR_RM, "W")
    blk_fsm = PermissionBlock(
        contracts={
            _FLR_FSM: ContractRule(
                abi="flare_systems_manager",
                methods={
                    "signUptimeVote(uint24,bytes32,(uint8,bytes32,bytes32))":
                        MethodRule(max_value_wei="0"),
                },
            ),
        },
        wallet_allowlist=["W"],
        rate=None,
    )
    p = _policy({"perm/clif-claim-flr": blk_rm, "perm/clif-fsp-submit-flr": blk_fsm})
    implied, warnings = _derive_implied_chains(p)
    assert implied == {"W": {14}}
    assert warnings == []


def test_implied_chains_multi_network_wallet() -> None:
    """Same wallet allowlisted in Flare-block AND Songbird-block -> {14, 19}."""
    blk_flr = _claim_block(_FLR_RM, "W")
    blk_sgb = _claim_block(_SGB_RM, "W")
    p = _policy({"perm/clif-claim-flr": blk_flr, "perm/clif-claim-sgb": blk_sgb})
    implied, warnings = _derive_implied_chains(p)
    assert implied == {"W": {14, 19}}
    assert warnings == []


def test_implied_chains_unmapped_contract_surfaces_warning() -> None:
    """A permissions block whose contract is NOT in `_CONTRACT_CHAIN`:
    the wallet's implied set is empty, AND a per-(wallet, contract) warning
    is collected (never silently dropped)."""
    blk = _claim_block(_UNKNOWN, "W")
    p = _policy({"perm/clif-claim-mystery": blk})
    implied, warnings = _derive_implied_chains(p)
    assert implied == {"W": set()}  # named but empty chain set
    assert len(warnings) == 1
    assert "W" in warnings[0] and _UNKNOWN in warnings[0]
    assert "contract" in warnings[0].lower() or "chain" in warnings[0].lower()


def test_implied_chains_skips_unmapped_keeps_mapped() -> None:
    """Mixed block with one mapped + one unmapped contract -> wallet gets the
    mapped chain, warning surfaces for the unmapped one."""
    blk = PermissionBlock(
        contracts={
            _FLR_RM: ContractRule(abi="reward_manager", methods={
                "claim(address,address,uint24,bool,(bytes32[],(uint24,bytes20,uint120,uint8))[])":
                    MethodRule(max_value_wei="0"),
            }),
            _UNKNOWN: ContractRule(abi="reward_manager", methods={
                "claim(address,address,uint24,bool,(bytes32[],(uint24,bytes20,uint120,uint8))[])":
                    MethodRule(max_value_wei="0"),
            }),
        },
        wallet_allowlist=["W"],
        rate=None,
    )
    implied, warnings = _derive_implied_chains(_policy({"perm/mixed": blk}))
    assert implied == {"W": {14}}
    assert len(warnings) == 1
    assert _UNKNOWN in warnings[0]


# ----- _format_native ---------------------------------------------------------


def test_format_native_round_numbers() -> None:
    assert _format_native(0) == "0"
    assert _format_native(10**18) == "1"
    assert _format_native(10**18 + 5 * 10**17) == "1.5"
    assert _format_native(123_456_789) == "0.000000000123456789"


# ----- list_balances ----------------------------------------------------------


class _FakeRpcClient:
    """Returns a deterministic balance per (chain, address) for tests."""

    def __init__(self, chain: int, balances: dict[tuple[int, str], int]) -> None:
        self._chain = chain
        self._balances = balances

    async def get_balance(self, addr: str) -> int:
        return self._balances.get((self._chain, addr), 0)


class _FakeRpcMgr:
    def __init__(self, balances: dict[tuple[int, str], int],
                 raise_for: set[tuple[int, str]] | None = None) -> None:
        self._balances = balances
        self._raise_for = raise_for or set()
        self._chain: int | None = None

    def for_chain(self, chain_id: int) -> _FakeRpcMgr:
        self._chain = chain_id
        return self

    async def get_balance(self, addr: str) -> int:
        chain = self._chain
        assert chain is not None
        if (chain, addr) in self._raise_for:
            raise RuntimeError(f"simulated rpc failure on chain {chain}")
        return self._balances.get((chain, addr), 0)


@pytest.mark.asyncio
async def test_list_balances_default_scope_transacting_only() -> None:
    """Default (include_all=False): only wallets reachable from a
    permissions allowlist, on their implied chains."""
    w_flr = _wallet("w-flr", "0x" + "aa" * 20)
    w_orphan = _wallet("w-orphan", "0x" + "bb" * 20)  # in DB but not in any allowlist

    repo = MagicMock()
    repo.list_all = AsyncMock(return_value=[w_flr, w_orphan])
    rpc = _FakeRpcMgr({(14, w_flr.address): 5 * 10**18})

    p = _policy({"perm/clif-claim-flr": _claim_block(_FLR_RM, "w-flr")})

    result = await list_balances(p, repo, rpc)  # type: ignore[arg-type]
    assert [e.wallet for e in result.balances] == ["w-flr"]
    assert result.balances[0].chain == 14
    assert result.balances[0].balance_native == "5"
    assert result.balances[0].error is None
    assert result.warnings == []


@pytest.mark.asyncio
async def test_list_balances_include_all_every_wallet_x_allowed_chains() -> None:
    """include_all=True: every DB wallet × ALLOWED_CHAINS (broad scan)."""
    w1 = _wallet("w1", "0x" + "11" * 20)
    w2 = _wallet("w2", "0x" + "22" * 20)
    repo = MagicMock()
    repo.list_all = AsyncMock(return_value=[w1, w2])
    rpc = _FakeRpcMgr({})  # all zero
    p = _policy({})  # no permissions

    result = await list_balances(p, repo, rpc, include_all=True)  # type: ignore[arg-type]
    chains_seen = {(e.wallet, e.chain) for e in result.balances}
    # 2 wallets × 3 ALLOWED_CHAINS = 6 entries
    assert chains_seen == {
        ("w1", 14), ("w1", 19), ("w1", 114),
        ("w2", 14), ("w2", 19), ("w2", 114),
    }


@pytest.mark.asyncio
async def test_list_balances_chain_filter_intersects() -> None:
    """chain_filter=19 reduces every (wallet, chain) work pair to chain=19."""
    w = _wallet("W", "0x" + "cc" * 20)
    repo = MagicMock()
    repo.list_all = AsyncMock(return_value=[w])
    rpc = _FakeRpcMgr({(19, w.address): 42 * 10**18})
    # Wallet is in Flare + Songbird blocks; filter to 19 -> only Songbird.
    p = _policy({
        "perm/clif-claim-flr": _claim_block(_FLR_RM, "W"),
        "perm/clif-claim-sgb": _claim_block(_SGB_RM, "W"),
    })
    result = await list_balances(p, repo, rpc, chain_filter=19)  # type: ignore[arg-type]
    assert [(e.wallet, e.chain, e.balance_native) for e in result.balances] == [("W", 19, "42")]


@pytest.mark.asyncio
async def test_list_balances_rpc_error_per_call_not_aborting() -> None:
    """An RPC error on one (wallet, chain) sets `error` on that entry only;
    other entries succeed."""
    w = _wallet("W", "0x" + "dd" * 20)
    repo = MagicMock()
    repo.list_all = AsyncMock(return_value=[w])
    rpc = _FakeRpcMgr(
        balances={(14, w.address): 7 * 10**18, (19, w.address): 0},
        raise_for={(19, w.address)},
    )
    p = _policy({
        "perm/clif-claim-flr": _claim_block(_FLR_RM, "W"),
        "perm/clif-claim-sgb": _claim_block(_SGB_RM, "W"),
    })
    result = await list_balances(p, repo, rpc)  # type: ignore[arg-type]
    by_chain = {e.chain: e for e in result.balances}
    assert by_chain[14].error is None and by_chain[14].balance_native == "7"
    assert by_chain[19].error is not None and "simulated rpc failure" in by_chain[19].error
    assert by_chain[19].balance_wei == "0"


# ----- endpoint ---------------------------------------------------------------


def _make_endpoint_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    wallets: list[Wallet] | None = None,
    balances_map: dict[tuple[int, str], int] | None = None,
    policy: Policy | None = None,
) -> TestClient:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()

    mock_repo = MagicMock()
    mock_repo.list_all = AsyncMock(return_value=wallets or [])

    class _FakeRepoCM:
        async def __aenter__(self) -> MagicMock:
            return mock_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    fake_rpc_mgr = _FakeRpcMgr(balances_map or {})

    class _FakeRpcCM:
        async def __aenter__(self) -> _FakeRpcMgr:
            return fake_rpc_mgr

        async def __aexit__(self, *args: object) -> None:
            pass

    app = FastAPI()
    app.include_router(router)
    if policy is not None:
        app.state.policy = policy
    app.dependency_overrides[get_wallet_repo] = lambda: _FakeRepoCM()
    app.dependency_overrides[get_rpc_manager] = lambda: _FakeRpcCM()
    return TestClient(app, raise_server_exceptions=False)


_ADMIN_HDR = {"Authorization": "Bearer admin-secret"}


def test_endpoint_requires_admin_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_endpoint_client(monkeypatch, policy=_policy({}))
    r = client.get("/v1/admin/wallets/balances")  # no auth header
    assert r.status_code == 401


def test_endpoint_policy_not_loaded_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    """If app.state.policy is None, the endpoint returns 503 (not 200 with
    empty data — explicit signal that the daemon isn't in a queryable state)."""
    client = _make_endpoint_client(monkeypatch, policy=None)
    r = client.get("/v1/admin/wallets/balances", headers=_ADMIN_HDR)
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "policy_not_loaded"


def test_endpoint_happy_path_returns_balances(monkeypatch: pytest.MonkeyPatch) -> None:
    w = _wallet("w-flr", "0x" + "aa" * 20)
    client = _make_endpoint_client(
        monkeypatch,
        wallets=[w],
        balances_map={(14, w.address): 3 * 10**18},
        policy=_policy({"perm/clif-claim-flr": _claim_block(_FLR_RM, "w-flr")}),
    )
    r = client.get("/v1/admin/wallets/balances", headers=_ADMIN_HDR)
    assert r.status_code == 200
    body = r.json()
    assert len(body["balances"]) == 1
    e = body["balances"][0]
    assert e["wallet"] == "w-flr"
    assert e["chain"] == 14
    assert e["balance_native"] == "3"
    assert e["error"] is None
    assert body["warnings"] == []


def test_endpoint_chain_filter_query_param(monkeypatch: pytest.MonkeyPatch) -> None:
    w = _wallet("w-multi", "0x" + "bb" * 20)
    client = _make_endpoint_client(
        monkeypatch,
        wallets=[w],
        balances_map={(14, w.address): 10**18, (19, w.address): 2 * 10**18},
        policy=_policy({
            "perm/clif-claim-flr": _claim_block(_FLR_RM, "w-multi"),
            "perm/clif-claim-sgb": _claim_block(_SGB_RM, "w-multi"),
        }),
    )
    r = client.get(
        "/v1/admin/wallets/balances?chain=19",
        headers=_ADMIN_HDR,
    )
    assert r.status_code == 200
    bals = r.json()["balances"]
    assert len(bals) == 1
    assert bals[0]["chain"] == 19 and bals[0]["balance_native"] == "2"


# ----- real-RPC integration smoke (Core #14; env-gated) -----------------------


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.environ.get("FWD_LIVE_RPC") != "1",
    reason="FWD_LIVE_RPC=1 required for real-RPC smoke (Core #14)",
)
async def test_list_balances_live_coston2() -> None:
    """Smoke: against live Coston2 RPC, look up the genesis address (or any
    well-known address) and assert we get a non-error response (whatever the
    actual balance is). Validates the get_balance plumbing end-to-end."""
    from fwd.infra.rpc import RpcManager

    w = _wallet("smoke", "0x0000000000000000000000000000000000000000")
    repo = MagicMock()
    repo.list_all = AsyncMock(return_value=[w])
    rpc_mgr = RpcManager()
    try:
        p = _policy({"perm/clif-claim-c2": _claim_block(_C2_RM, "smoke")})
        result = await list_balances(p, repo, rpc_mgr)
        assert len(result.balances) == 1
        # The zero-address may or may not have a balance; either way error=None.
        assert result.balances[0].error is None
        assert result.balances[0].chain == 114
    finally:
        await rpc_mgr.aclose()
