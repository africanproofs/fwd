"""Tests for app/policy_gate.py — gate() and release_rate_after_failure().

Uses the real policy_engine + AbiRegistry.load(config/abis) + tmp-sqlite
RateRepo. Helper shapes mirrored from test_policy_engine.py.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import eth_abi
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.app.policy_gate import PolicyDenied, gate, release_rate_after_failure
from fwd.app.sign_transaction import SignTransactionRequest
from fwd.domain.policy import MethodRule, Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.caller_repo import Caller
from fwd.infra.rate_repo import RateRepo, rate_metadata
from fwd.infra.wallet_repo import Wallet

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

ERC20_CONTRACT = "0x1234567890abcdef1234567890abcdef12345678"
RECIPIENT_ADDR = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
TRANSFER_SELECTOR = "0xa9059cbb"
POLICY_PATH = "perm/main"
WALLET_NAME = "my-wallet"
CALLER_NAME = "my-caller"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


@pytest.fixture()
async def session(tmp_path):  # type: ignore[no-untyped-def]
    db = tmp_path / "test_gate.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(rate_metadata.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_caller(
    policy_path: str = POLICY_PATH,
    name: str = CALLER_NAME,
) -> Caller:
    return Caller(
        name=name,
        api_key_hash="h",
        api_key_prefix="p",
        policy_path=policy_path,
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _make_wallet(name: str = WALLET_NAME, policy_path: str = "wc/main") -> Wallet:
    return Wallet(
        name=name,
        address="0x" + "bb" * 20,
        privkey_ciphertext="vault:v1:x",
        vault_master_key="fwd-master",
        policy_path=policy_path,
        created_at=datetime.now(UTC),
    )


def _make_policy(
    *,
    per_hour: int | None = 100,
    max_value_wei: str = "1000000000000000000",
) -> Policy:
    methods: dict[str, object] = {
        "transfer(address,uint256)": MethodRule(max_value_wei=max_value_wei),
    }
    rate_dict: dict[str, int] = {}
    if per_hour is not None:
        rate_dict["per_hour"] = per_hour
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {
                CALLER_NAME: {"policy_path": POLICY_PATH},
            },
            "wallets": {
                WALLET_NAME: {"policy_path": "wc/main"},
            },
            "permissions": {
                POLICY_PATH: {
                    "contracts": {
                        ERC20_CONTRACT: {
                            "abi": "erc20",
                            "chains": [114],
                            "methods": {
                                sig: {
                                    "max_value_wei": mr.max_value_wei,  # type: ignore[union-attr]
                                    "arg_predicates": mr.arg_predicates,  # type: ignore[union-attr]
                                }
                                for sig, mr in methods.items()  # type: ignore[union-attr]
                            },
                        }
                    },
                    "wallet_allowlist": [WALLET_NAME],
                    **({"rate": rate_dict} if rate_dict else {}),
                }
            },
            "wallet_constraints": {
                "wc/main": {},
            },
        }
    )


def _transfer_calldata(amount: int = 100) -> str:
    encoded = eth_abi.encode(["address", "uint256"], [RECIPIENT_ADDR, amount])
    raw = bytes.fromhex(TRANSFER_SELECTOR[2:]) + encoded
    return "0x" + raw.hex()


def _make_request(value_wei: str = "0") -> SignTransactionRequest:
    return SignTransactionRequest(
        wallet=WALLET_NAME,
        caller=CALLER_NAME,
        chain=114,
        to=ERC20_CONTRACT,
        value_wei=value_wei,
        data=_transfer_calldata(),
        gas=21_000,
        max_fee_per_gas=3_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_returns_allow_on_permitting_policy(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """gate(...) returns AllowDecision on a policy that permits the request."""
    from fwd.app.policy_engine import AllowDecision

    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)
    now = datetime.now(UTC)

    result = await gate(
        caller=caller,
        wallet=wallet,
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=now,
    )
    assert isinstance(result, AllowDecision)
    assert result.matched_policy_path == POLICY_PATH


@pytest.mark.asyncio
async def test_gate_raises_policy_denied_on_denying_policy(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """gate(...) raises PolicyDenied (with .step) when the engine denies."""
    # Use a caller that is NOT in policy.callers → step 1 deny.
    policy = _make_policy()
    caller = _make_caller(name="unknown-caller")
    wallet = _make_wallet()
    rate_repo = RateRepo(session)
    now = datetime.now(UTC)

    with pytest.raises(PolicyDenied) as exc_info:
        await gate(
            caller=caller,
            wallet=wallet,
            request=_make_request(),
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            now=now,
        )
    err = exc_info.value
    assert err.step == 1
    assert isinstance(err.reason, str)
    assert len(err.reason) > 0


@pytest.mark.asyncio
async def test_release_rate_after_failure_allows_second_call(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """release_rate_after_failure decrements caller bucket so a 2nd gate call passes.

    Proof via per_hour=1 policy:
      gate → allow (bucket now at 1)
      release_rate_after_failure (bucket back to 0)
      gate again → allow (not denied at step 8)
    """
    from fwd.app.policy_engine import AllowDecision

    policy = _make_policy(per_hour=1)
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)
    now = datetime.now(UTC)
    request = _make_request()

    # First gate → allow (consumes the 1-per-hour slot).
    allow1 = await gate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=now,
    )
    assert isinstance(allow1, AllowDecision)

    # Release (simulates pre-broadcast failure).
    await release_rate_after_failure(
        allow=allow1,
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        rate_repo=rate_repo,
        now=now,
    )

    # Second gate must pass (slot was returned).
    allow2 = await gate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=now,
    )
    assert isinstance(allow2, AllowDecision)


@pytest.mark.asyncio
async def test_release_rate_after_failure_never_raises_when_policy_empty(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """release_rate_after_failure is best-effort: never raises even if policy.permissions is empty."""
    from fwd.app.policy_engine import AllowDecision

    good_policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)
    now = datetime.now(UTC)
    request = _make_request()

    # Get a real AllowDecision to pass to release.
    allow = await gate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=good_policy,
        registry=registry,
        rate_repo=rate_repo,
        now=now,
    )
    assert isinstance(allow, AllowDecision)

    # Now pass a policy whose permissions dict is emptied.
    empty_policy = Policy.model_validate(
        {
            "version": 1,
            "callers": {CALLER_NAME: {"policy_path": POLICY_PATH}},
            "wallets": {WALLET_NAME: {"policy_path": "wc/main"}},
            "permissions": {},  # emptied — matched_policy_path will not be found
            "wallet_constraints": {"wc/main": {}},
        }
    )

    # Must not raise.
    await release_rate_after_failure(
        allow=allow,
        caller=caller,
        wallet=wallet,
        request=request,
        policy=empty_policy,
        rate_repo=rate_repo,
        now=now,
    )
