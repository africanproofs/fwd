"""Tests for the native_transfers policy-engine branch (app/policy_engine.py).

A value-only (empty-calldata) signing request is gated by a
`native_transfers` block instead of the ABI decode path. Mirrors the style
and fixtures of test_policy_engine.py.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.app.policy_engine import AllowDecision, DenyDecision, evaluate
from fwd.app.sign_transaction import SignTransactionRequest
from fwd.domain.policy import Policy
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.caller_repo import Caller
from fwd.infra.rate_repo import RateRepo, rate_metadata
from fwd.infra.wallet_repo import Wallet

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

CHAIN = 14
RECIPIENT_1 = "0x" + "11" * 20
RECIPIENT_2 = "0x" + "22" * 20
OFF_ALLOWLIST_RECIPIENT = "0x" + "99" * 20
MAX_VALUE_WEI = "400000000000000000000"

POLICY_PATH = "perm/funding-flare"
WALLET_NAME = "funding-flare"
CALLER_NAME = "funding-flare"

NOW = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


@pytest.fixture()
async def session(tmp_path):  # type: ignore[no-untyped-def]
    db = tmp_path / "test_engine.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(rate_metadata.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


def _make_caller(policy_path: str = POLICY_PATH, name: str = CALLER_NAME) -> Caller:
    return Caller(
        name=name,
        api_key_hash="h",
        api_key_prefix="p",
        policy_path=policy_path,
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _make_wallet(name: str = WALLET_NAME) -> Wallet:
    return Wallet(
        name=name,
        address="0x" + "bb" * 20,
        privkey_ciphertext="seal:v1:x",
        vault_master_key="fwd-master",
        policy_path="wc/main",
        created_at=datetime.now(UTC),
    )


def _make_policy(
    *,
    rate: dict[str, int] | None = None,
    extra_caller: dict[str, object] | None = None,
    wallet_constraint: dict[str, object] | None = None,
    bind_wallet: bool = True,
) -> Policy:
    if rate is None:
        rate = {"per_hour": 6, "per_day": 20}
    callers = {
        CALLER_NAME: {"policy_path": POLICY_PATH},
    }
    if extra_caller is not None:
        callers.update(extra_caller)
    doc: dict[str, object] = {
        "version": 1,
        "callers": callers,
        "native_transfers": {
            POLICY_PATH: {
                "chains": [CHAIN],
                "recipient_allowlist": [RECIPIENT_1, RECIPIENT_2],
                "max_value_wei": MAX_VALUE_WEI,
                "wallet_allowlist": [WALLET_NAME],
                "rate": rate,
            }
        },
    }
    # Step 9 (per-wallet aggregate) needs the wallet bound to a constraint. Omit
    # the binding (bind_wallet=False) to exercise the fail-closed no-constraint
    # deny; empty constraint = no aggregate cap (allow).
    if bind_wallet:
        doc["wallets"] = {WALLET_NAME: {"policy_path": "wc/main"}}
        doc["wallet_constraints"] = {"wc/main": wallet_constraint or {}}
    return Policy.model_validate(doc)


def _make_request(
    *,
    to: str = RECIPIENT_1,
    value_wei: str = "1000000000000000000",
    data: str = "0x",
    chain: int = CHAIN,
    wallet: str = WALLET_NAME,
    caller: str = CALLER_NAME,
) -> SignTransactionRequest:
    return SignTransactionRequest(
        wallet=wallet,
        caller=caller,
        chain=chain,
        to=to,
        value_wei=value_wei,
        data=data,
        gas=21_000,
        max_fee_per_gas=3_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
    )


# ---------------------------------------------------------------------------
# Case 1: allow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allow_whitelisted_recipient_under_cap(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy()
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, AllowDecision)
    assert result.decoded.args["to"] == RECIPIENT_1
    assert result.decoded.args["value"] == 1000000000000000000


# ---------------------------------------------------------------------------
# Case 2: recipient not in allowlist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_recipient_not_in_allowlist(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy()
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(to=OFF_ALLOWLIST_RECIPIENT),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 2


# ---------------------------------------------------------------------------
# Case 3: value == cap + 1
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_value_exceeds_cap(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    over_cap = str(int(MAX_VALUE_WEI) + 1)
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(value_wei=over_cap),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 5
    assert "max_value_wei exceeded" in result.reason


# ---------------------------------------------------------------------------
# Case 4: value == 0
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_value_zero(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(value_wei="0"),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 5
    assert "value must be > 0" in result.reason


# ---------------------------------------------------------------------------
# Case 5: wrong chain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_wrong_chain(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(chain=19),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 2


# ---------------------------------------------------------------------------
# Case 6: wallet not in the block's allowlist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_wallet_not_in_allowlist(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(name="other-wallet"),
        request=_make_request(wallet="other-wallet"),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 7


# ---------------------------------------------------------------------------
# Case 7: non-empty calldata from a native_transfers caller
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_nonempty_calldata_from_native_transfer_caller(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy()
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(data="0xa9059cbb" + "00" * 64),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 2
    assert "value-only" in result.reason


# ---------------------------------------------------------------------------
# Case 8: default-deny — caller with NO native_transfers rule, empty calldata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_deny_no_native_transfer_rule_still_denies_step3(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy(extra_caller={"no-rule-caller": {"policy_path": "nowhere"}})
    result = await evaluate(
        caller=_make_caller(policy_path="nowhere", name="no-rule-caller"),
        wallet=_make_wallet(),
        request=_make_request(caller="no-rule-caller"),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 3
    assert "calldata too short" in result.reason


# ---------------------------------------------------------------------------
# Case 9: rate — exhaust per_hour(6), 7th call denies step=8
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_exhausted_denies_step8(tmp_path) -> None:  # type: ignore[no-untyped-def]
    db = tmp_path / "nt_rate.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(rate_metadata.create_all)
    reg = AbiRegistry.load(ABIS_DIR)
    policy = _make_policy(rate={"per_hour": 6})

    async def _eval() -> AllowDecision | DenyDecision:
        async with AsyncSession(engine) as s:
            result = await evaluate(
                caller=_make_caller(),
                wallet=_make_wallet(),
                request=_make_request(),
                policy=policy,
                registry=reg,
                rate_repo=RateRepo(s),
                now=NOW,
            )
            await s.commit()
            return result

    for _ in range(6):
        result = await _eval()
        assert isinstance(result, AllowDecision), result

    result = await _eval()
    assert isinstance(result, DenyDecision)
    assert result.step == 8

    await engine.dispose()


# ---------------------------------------------------------------------------
# Case 9: Step-9 per-wallet aggregate cap (the value-moving guardrail)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_over_wallet_aggregate_cap_step9(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """A transfer whose value exceeds the wallet's daily aggregate cap → step 9.

    This is the guardrail that bounds daily spend from the funding wallet
    (wc/ap-funder max_aggregate_value_wei_per_day) — native transfers are the
    only value-moving path, so the aggregate cap MUST bind here.
    """
    # cap 0.5 FLR; request sends 1 FLR (the _make_request default) -> exceeds.
    policy = _make_policy(wallet_constraint={"max_aggregate_value_wei_per_day": "500000000000000000"})
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 9


@pytest.mark.asyncio
async def test_deny_no_wallet_constraint_binding_step9(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Fail-closed: a native-transfer wallet with no policy.wallets binding (so no
    aggregate cap can apply) is denied at step 9, never signed unconstrained."""
    policy = _make_policy(bind_wallet=False)
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 9
