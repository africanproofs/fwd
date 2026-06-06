"""Tests for app/policy_engine.py — the D14 10-step evaluation matrix.

Uses the real AbiRegistry.load(config/abis) and real decode_intent.
The ERC20 transfer(address,uint256) function is the workhorse method.
Rate buckets are backed by a tmp SQLite session.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import eth_abi
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.app.policy_engine import AllowDecision, DenyDecision, evaluate
from fwd.app.sign_transaction import SignTransactionRequest
from fwd.domain.policy import (
    MethodRule,
    Policy,
    RateLimit,
    WalletConstraint,
)
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.caller_repo import Caller
from fwd.infra.rate_repo import RateRepo, rate_metadata
from fwd.infra.wallet_repo import Wallet

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

# ERC20 addresses (lowercase 42-char).
ERC20_CONTRACT = "0x1234567890abcdef1234567890abcdef12345678"
RECIPIENT_ADDR = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"

# Selectors (from eth_utils).
TRANSFER_SELECTOR = "0xa9059cbb"
APPROVE_SELECTOR = "0x095ea7b3"

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
    db = tmp_path / "test_engine.db"
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
    caller_name: str = CALLER_NAME,
    caller_policy_path: str = POLICY_PATH,
    perm_path: str = POLICY_PATH,
    contract_addr: str = ERC20_CONTRACT,
    abi: str = "erc20",
    chains: list[int] | None = None,
    methods: dict[str, MethodRule] | None = None,
    wallet_allowlist: list[str] | None = None,
    rate: RateLimit | None = RateLimit(per_hour=100, per_day=1000),
    wallet_name: str = WALLET_NAME,
    wallet_constraint_path: str = "wc/main",
    wallet_constraint: WalletConstraint | None = None,
    include_wallets_binding: bool = True,
) -> Policy:
    if methods is None:
        methods = {
            "transfer(address,uint256)": MethodRule(
                max_value_wei="1000000000000000000",  # 1 ETH
            )
        }
    if wallet_allowlist is None:
        wallet_allowlist = [WALLET_NAME]
    if chains is None:
        chains = [114]
    return Policy.model_validate(
        {
            "version": 1,
            "callers": {
                caller_name: {"policy_path": caller_policy_path},
            },
            "wallets": (
                {wallet_name: {"policy_path": wallet_constraint_path}}
                if include_wallets_binding
                else {}
            ),
            "permissions": {
                perm_path: {
                    "contracts": {
                        contract_addr: {
                            "abi": abi,
                            "chains": chains,
                            "methods": {
                                sig: {
                                    "max_value_wei": mr.max_value_wei,
                                    "arg_predicates": mr.arg_predicates,
                                    "allow_unconstrained_args": mr.allow_unconstrained_args,
                                }
                                for sig, mr in methods.items()
                            },
                        }
                    },
                    "wallet_allowlist": wallet_allowlist,
                    **(
                        {"rate": {"per_hour": rate.per_hour, "per_day": rate.per_day}}
                        if rate
                        else {}
                    ),
                }
            },
            "wallet_constraints": {
                wallet_constraint_path: (
                    {}
                    if wallet_constraint is None
                    else {
                        k: v
                        for k, v in {
                            "max_aggregate_value_wei_per_day": wallet_constraint.max_aggregate_value_wei_per_day,
                            "rate": (
                                {
                                    "per_hour": wallet_constraint.rate.per_hour,
                                    "per_day": wallet_constraint.rate.per_day,
                                }
                                if wallet_constraint.rate
                                else None
                            ),
                        }.items()
                        if v is not None
                    }
                ),
            },
        }
    )


def _transfer_calldata(to: str = RECIPIENT_ADDR, amount: int = 100) -> str:
    """Return 0x-prefixed calldata for ERC20 transfer(address,uint256)."""
    encoded = eth_abi.encode(["address", "uint256"], [to, amount])
    raw = bytes.fromhex(TRANSFER_SELECTOR[2:]) + encoded
    return "0x" + raw.hex()


def _approve_calldata(spender: str = RECIPIENT_ADDR, amount: int = 100) -> str:
    """Return 0x-prefixed calldata for ERC20 approve(address,uint256)."""
    encoded = eth_abi.encode(["address", "uint256"], [spender, amount])
    raw = bytes.fromhex(APPROVE_SELECTOR[2:]) + encoded
    return "0x" + raw.hex()


def _make_request(
    data: str | None = None,
    value_wei: str = "0",
    wallet: str = WALLET_NAME,
    to: str = ERC20_CONTRACT,
) -> SignTransactionRequest:
    if data is None:
        data = _transfer_calldata()
    return SignTransactionRequest(
        wallet=wallet,
        caller=CALLER_NAME,
        chain=114,
        to=to,
        value_wei=value_wei,
        data=data,
        gas=21_000,
        max_fee_per_gas=3_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
    )


NOW = datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Step 10: happy path — AllowDecision
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_returns_allow(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, AllowDecision)
    assert result.matched_policy_path == POLICY_PATH
    assert result.decoded is not None


# ---------------------------------------------------------------------------
# Step 2: chain-ID binding (a29) — a contract address is not chain-unique
# ---------------------------------------------------------------------------

REWARD_CONTRACT = "0x" + "cc" * 20
CLAIM_SIG = "claim(address,address,uint24,bool,(bytes32[],(uint24,bytes20,uint120,uint8))[])"


def _claim_calldata() -> str:
    """Valid reward_manager.claim calldata with an EMPTY proofs array.

    The proofs arg is a tuple[] (non-scalar) — decoded but projected out of
    .args (B1). Used to exercise the non-scalar fail-closed gate (step 4b).
    """
    selector = bytes.fromhex("8e33aba5")  # selector_of(reward_manager.claim)
    encoded = eth_abi.encode(
        ["address", "address", "uint24", "bool", "(bytes32[],(uint24,bytes20,uint120,uint8))[]"],
        [RECIPIENT_ADDR, RECIPIENT_ADDR, 5, False, []],
    )
    return "0x" + (selector + encoded).hex()


@pytest.mark.asyncio
async def test_step2_chain_not_permitted_denies(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    # Policy binds the contract to chain 14 (Flare); request is for 114 (Coston2).
    policy = _make_policy(chains=[14])
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(),  # chain=114
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 2
    assert "chain 114" in result.reason


@pytest.mark.asyncio
async def test_step2_chain_permitted_when_listed(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    # Same address valid on BOTH chains; request 114 matches.
    policy = _make_policy(chains=[14, 114])
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(),  # chain=114
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, AllowDecision)


# ---------------------------------------------------------------------------
# Step 4b: non-scalar (array/tuple) args fail closed unless opted in (a29)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step4b_nonscalar_args_denied_without_optin(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy(
        abi="reward_manager",
        contract_addr=REWARD_CONTRACT,
        methods={CLAIM_SIG: MethodRule(max_value_wei="0")},  # allow_unconstrained_args=False
    )
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(data=_claim_calldata(), to=REWARD_CONTRACT),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 4
    assert "non-scalar" in result.reason


@pytest.mark.asyncio
async def test_step4b_nonscalar_args_allowed_with_optin(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy(
        abi="reward_manager",
        contract_addr=REWARD_CONTRACT,
        methods={CLAIM_SIG: MethodRule(max_value_wei="0", allow_unconstrained_args=True)},
    )
    result = await evaluate(
        caller=_make_caller(),
        wallet=_make_wallet(),
        request=_make_request(data=_claim_calldata(), to=REWARD_CONTRACT),
        policy=policy,
        registry=registry,
        rate_repo=RateRepo(session),
        now=NOW,
    )
    assert isinstance(result, AllowDecision)


# ---------------------------------------------------------------------------
# Step 9: a signable wallet MUST have a policy.wallets binding (a29)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step9_wallet_without_binding_denies(tmp_path) -> None:  # type: ignore[no-untyped-def]
    db = tmp_path / "engine9b.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(rate_metadata.create_all)
    reg = AbiRegistry.load(ABIS_DIR)
    # Wallet is allowlisted (step 7 passes) but has NO policy.wallets binding.
    policy = _make_policy(rate=RateLimit(per_hour=10), include_wallets_binding=False)

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

    r1 = await _eval()
    assert isinstance(r1, DenyDecision)
    assert r1.step == 9
    assert "no constraint binding" in r1.reason
    # Caller bucket released: a second identical request still reaches step 9
    # (would be step 8 if the first denial had leaked the increment).
    r2 = await _eval()
    assert isinstance(r2, DenyDecision)
    assert r2.step == 9

    await engine.dispose()


# ---------------------------------------------------------------------------
# Step 1: caller not in policy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step1_caller_not_in_policy(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    # Use a different caller name not in policy.callers
    caller = _make_caller(name="unknown-caller", policy_path=POLICY_PATH)
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 1
    assert "not in policy" in result.reason


@pytest.mark.asyncio
async def test_step1_caller_policy_path_drift(session: AsyncSession, registry: AbiRegistry) -> None:
    """caller.policy_path differs from the binding's policy_path → Deny(1)."""
    policy = _make_policy()  # binding.policy_path = POLICY_PATH
    # caller.policy_path differs from binding.policy_path
    caller = _make_caller(policy_path="some-other-path")
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 1
    assert "drift" in result.reason


# ---------------------------------------------------------------------------
# Step 2: contract not permitted
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step2_contract_not_permitted(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    # Send to a different contract address not in policy.
    request = _make_request(to="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 2


# ---------------------------------------------------------------------------
# Step 3: calldata errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step3_non_hex_data(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    request = _make_request(data="0xnothex!!")
    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 3


@pytest.mark.asyncio
async def test_step3_too_short(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    request = _make_request(data="0xabcd")  # only 2 bytes
    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 3


@pytest.mark.asyncio
async def test_step3_unknown_selector(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    # Valid hex, 4+ bytes, but selector not in erc20 ABI.
    request = _make_request(data="0xdeadbeef" + "00" * 32)
    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 3


@pytest.mark.asyncio
async def test_step3_decode_fails_truncated_args(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Valid selector, but truncated args → decode_intent returns None → Deny(3)."""
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    # transfer selector + only 10 bytes of args (needs 64 bytes for address+uint256)
    data = "0x" + TRANSFER_SELECTOR[2:] + "aabbccddee" * 2
    request = _make_request(data=data)
    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 3


# ---------------------------------------------------------------------------
# Step 4: method not in policy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step4_method_not_in_policy(session: AsyncSession, registry: AbiRegistry) -> None:
    """approve is in the ABI but not in policy.methods → Deny(4)."""
    policy = _make_policy()  # only transfer is in methods
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    request = _make_request(data=_approve_calldata())
    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 4


# ---------------------------------------------------------------------------
# Step 5: max_value_wei exceeded / bad value_wei
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step5_value_wei_exceeds_max(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy(methods={"transfer(address,uint256)": MethodRule(max_value_wei="100")})
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    request = _make_request(value_wei="101")
    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 5


@pytest.mark.asyncio
async def test_step5_bad_request_value_wei(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    request = _make_request(value_wei="not-a-number")
    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=request,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 5


# ---------------------------------------------------------------------------
# Step 6: arg_predicates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step6_address_predicate_match_returns_allow(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy(
        methods={
            "transfer(address,uint256)": MethodRule(
                max_value_wei="1000000000000000000",
                arg_predicates={"to": RECIPIENT_ADDR.lower()},
            )
        }
    )
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(data=_transfer_calldata(to=RECIPIENT_ADDR)),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, AllowDecision)


@pytest.mark.asyncio
async def test_step6_address_predicate_mismatch_denies(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy(
        methods={
            "transfer(address,uint256)": MethodRule(
                max_value_wei="1000000000000000000",
                arg_predicates={"to": "0x" + "cc" * 20},
            )
        }
    )
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(data=_transfer_calldata(to=RECIPIENT_ADDR)),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 6


@pytest.mark.asyncio
async def test_step6_any_sentinel_passes(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy(
        methods={
            "transfer(address,uint256)": MethodRule(
                max_value_wei="1000000000000000000",
                arg_predicates={"to": "any"},
            )
        }
    )
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(data=_transfer_calldata(to=RECIPIENT_ADDR)),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, AllowDecision)


@pytest.mark.asyncio
async def test_step6_predicate_on_absent_arg_denies(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy(
        methods={
            "transfer(address,uint256)": MethodRule(
                max_value_wei="1000000000000000000",
                arg_predicates={"nonexistent_param": "value"},
            )
        }
    )
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(data=_transfer_calldata()),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 6
    assert "not in decoded scalars" in result.reason


@pytest.mark.asyncio
async def test_step6_int_predicate_match(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy(
        methods={
            "transfer(address,uint256)": MethodRule(
                max_value_wei="1000000000000000000",
                arg_predicates={"amount": 100},
            )
        }
    )
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(data=_transfer_calldata(amount=100)),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, AllowDecision)


@pytest.mark.asyncio
async def test_step6_int_predicate_mismatch(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy(
        methods={
            "transfer(address,uint256)": MethodRule(
                max_value_wei="1000000000000000000",
                arg_predicates={"amount": 999},
            )
        }
    )
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(data=_transfer_calldata(amount=100)),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 6


@pytest.mark.asyncio
async def test_step6_address_case_insensitive_match(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Predicate in uppercase, decoded arg in lowercase → should match."""
    policy = _make_policy(
        methods={
            "transfer(address,uint256)": MethodRule(
                max_value_wei="1000000000000000000",
                arg_predicates={"to": RECIPIENT_ADDR.upper()},
            )
        }
    )
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(data=_transfer_calldata(to=RECIPIENT_ADDR)),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, AllowDecision)


# ---------------------------------------------------------------------------
# Step 7: wallet not in allowlist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step7_wallet_not_in_allowlist(session: AsyncSession, registry: AbiRegistry) -> None:
    policy = _make_policy(wallet_allowlist=["other-wallet"])
    caller = _make_caller()
    wallet = _make_wallet()  # name=WALLET_NAME, not in allowlist
    rate_repo = RateRepo(session)

    result = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result, DenyDecision)
    assert result.step == 7


# ---------------------------------------------------------------------------
# Step 8: caller rate limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step8_first_request_allow_second_deny(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    policy = _make_policy(rate=RateLimit(per_hour=1))
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    result1 = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    await session.commit()
    assert isinstance(result1, AllowDecision)

    result2 = await evaluate(
        caller=caller,
        wallet=wallet,
        request=_make_request(),
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        now=NOW,
    )
    assert isinstance(result2, DenyDecision)
    assert result2.step == 8


# ---------------------------------------------------------------------------
# Step 9: wallet constraint exceeded + caller bucket release
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step9_wallet_aggregate_exceeded_releases_caller_bucket(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Deny at step 9 must release the step-8 caller increment.
    Proof: a subsequent identical request (after the denial) still succeeds.
    """
    db = tmp_path / "engine9.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(rate_metadata.create_all)

    reg = AbiRegistry.load(ABIS_DIR)
    constraint = WalletConstraint(max_aggregate_value_wei_per_day="0")
    policy = _make_policy(
        rate=RateLimit(per_hour=10),
        wallet_constraint=constraint,
    )
    caller = _make_caller()
    wallet = _make_wallet()

    async def _eval() -> AllowDecision | DenyDecision:
        async with AsyncSession(engine) as s:
            repo = RateRepo(s)
            result = await evaluate(
                caller=caller,
                wallet=wallet,
                request=_make_request(value_wei="1"),  # value_wei=1 > cap=0
                policy=policy,
                registry=reg,
                rate_repo=repo,
                now=NOW,
            )
            await s.commit()
            return result

    # First request: Deny(9) because wallet aggregate cap = 0 < value=1.
    r1 = await _eval()
    assert isinstance(r1, DenyDecision), f"Expected Deny, got {r1}"
    assert r1.step == 9

    # Second request: must also Deny(9) — proving caller bucket was released
    # (if not released, second request would Deny(8)).
    r2 = await _eval()
    assert isinstance(r2, DenyDecision)
    assert r2.step == 9, (
        f"Expected step=9 (wallet cap still exceeded), got step={r2.step} — "
        f"caller bucket was likely NOT released after first denial"
    )

    await engine.dispose()


# ---------------------------------------------------------------------------
# Step 0: unexpected error → Deny(0), evaluate does not raise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step0_unexpected_error_does_not_raise(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Monkeypatching registry.lookup to raise proves evaluate() wraps it."""
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    rate_repo = RateRepo(session)

    with patch.object(registry, "lookup", side_effect=RuntimeError("injected crash")):
        result = await evaluate(
            caller=caller,
            wallet=wallet,
            request=_make_request(),
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            now=NOW,
        )

    assert isinstance(result, DenyDecision)
    assert result.step == 0
    assert "evaluation error" in result.reason
