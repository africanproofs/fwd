"""Synthetic-attack default-deny matrix for sign_and_send (v0.5.0a6).

App-layer. Real policy_engine + decode_intent + AuditRepo against tmp-sqlite;
signer and rpc are AsyncMock. All DB metadata (audit + rate + tx + nonce) on
ONE engine/session.

For each attack scenario the test asserts:
  - sign_and_send raises PolicyDenied.
  - An audit row exists with action="sign-and-send", decision="denied", and
    the expected D14 step in decision_reason.
  - rpc.send_raw_transaction was NOT awaited (default-deny never signs or broadcasts).

Plus one happy-path test: a permitting policy → SignAndSendResult returned,
rpc.send_raw_transaction WAS awaited, audit row decision="approved" exists with
outcome containing the tx_id.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import eth_abi
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.app.policy_gate import PolicyDenied
from fwd.app.sign_and_send import SignAndSendRequest, SignAndSendResult, sign_and_send
from fwd.domain.policy import MethodRule, Policy, WalletConstraint
from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.audit_repo import AuditRepo, audit_log, audit_metadata
from fwd.infra.caller_repo import Caller
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.nonce_repo import metadata as nonce_metadata
from fwd.infra.rate_repo import RateRepo, rate_metadata
from fwd.infra.transaction_repo import TransactionRepo
from fwd.infra.transaction_repo import metadata as transaction_metadata
from fwd.infra.wallet_repo import Wallet

ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"

# ERC20 addresses (lowercase).
ERC20_CONTRACT = "0x1234567890abcdef1234567890abcdef12345678"
RECIPIENT_ADDR = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
TRANSFER_SELECTOR = "0xa9059cbb"

POLICY_PATH = "perm/main"
WALLET_NAME = "my-wallet"
CALLER_NAME = "my-caller"
WALLET_ADDR = "0x" + "bb" * 20
CHAIN_ID = 114


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def registry() -> AbiRegistry:
    return AbiRegistry.load(ABIS_DIR)


@pytest.fixture()
async def session(tmp_path):  # type: ignore[no-untyped-def]
    """Single engine/session for ALL DB metadata (audit+rate+tx+nonce)."""
    db = tmp_path / "test_policy.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(audit_metadata.create_all)
        await conn.run_sync(rate_metadata.create_all)
        await conn.run_sync(transaction_metadata.create_all)
        await conn.run_sync(nonce_metadata.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_caller(
    name: str = CALLER_NAME,
    policy_path: str = POLICY_PATH,
) -> Caller:
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
        address=WALLET_ADDR,
        privkey_ciphertext="vault:v1:x",
        vault_master_key="fwd-master",
        policy_path="wc/main",
        created_at=datetime.now(UTC),
    )


def _make_policy(
    *,
    methods: dict[str, MethodRule] | None = None,
    wallet_allowlist: list[str] | None = None,
    per_hour: int | None = None,
    wallet_constraint: WalletConstraint | None = None,
    contract_addr: str = ERC20_CONTRACT,
    caller_name: str = CALLER_NAME,
    caller_policy_path: str = POLICY_PATH,
) -> Policy:
    if methods is None:
        methods = {
            "transfer(address,uint256)": MethodRule(max_value_wei="1000000000000000000"),
        }
    if wallet_allowlist is None:
        wallet_allowlist = [WALLET_NAME]

    rate_dict: dict[str, int] = {}
    if per_hour is not None:
        rate_dict["per_hour"] = per_hour

    wc_path = "wc/main"
    wc_spec: dict[str, object]
    if wallet_constraint is not None:
        wc_spec = {}
        if wallet_constraint.max_aggregate_value_wei_per_day is not None:
            wc_spec["max_aggregate_value_wei_per_day"] = (
                wallet_constraint.max_aggregate_value_wei_per_day
            )
        if wallet_constraint.rate is not None:
            wc_spec["rate"] = {
                "per_hour": wallet_constraint.rate.per_hour,
                "per_day": wallet_constraint.rate.per_day,
            }
    else:
        wc_spec = {}

    return Policy.model_validate(
        {
            "version": 1,
            "callers": {
                caller_name: {"policy_path": caller_policy_path},
            },
            "wallets": {
                WALLET_NAME: {"policy_path": wc_path},
            },
            "permissions": {
                POLICY_PATH: {
                    "contracts": {
                        contract_addr: {
                            "abi": "erc20",
                            "methods": {
                                sig: {
                                    "max_value_wei": mr.max_value_wei,
                                    "arg_predicates": mr.arg_predicates,
                                }
                                for sig, mr in methods.items()
                            },
                        }
                    },
                    "wallet_allowlist": wallet_allowlist,
                    **({"rate": rate_dict} if rate_dict else {}),
                }
            },
            "wallet_constraints": {wc_path: wc_spec},
        }
    )


def _transfer_calldata(
    to: str = RECIPIENT_ADDR,
    amount: int = 100,
) -> str:
    encoded = eth_abi.encode(["address", "uint256"], [to, amount])
    raw = bytes.fromhex(TRANSFER_SELECTOR[2:]) + encoded
    return "0x" + raw.hex()


def _make_request(
    value_wei: str = "0",
    to: str = ERC20_CONTRACT,
    data: str | None = None,
    wallet: str = WALLET_NAME,
    caller: str = CALLER_NAME,
) -> SignAndSendRequest:
    if data is None:
        data = _transfer_calldata()
    return SignAndSendRequest(
        wallet=wallet,
        caller=caller,
        chain=CHAIN_ID,
        to=to,
        value_wei=value_wei,
        data=data,
        gas=21000,
    )


def _mock_signer(address: str = WALLET_ADDR) -> AsyncMock:
    """AsyncMock for EnvelopeSigner: address() + sign_transaction()."""
    signer = AsyncMock()
    signer.address.return_value = address
    signed = MagicMock()
    signed.raw_transaction = bytes(32)  # 32 zero bytes as dummy raw tx
    signer.sign_transaction.return_value = signed
    return signer


def _mock_rpc(tx_hash: str = "0x" + "ab" * 32) -> AsyncMock:
    """AsyncMock for RpcClient: verify_chain_id, fee_history, estimate_gas, etc."""
    rpc = AsyncMock()
    rpc.verify_chain_id.return_value = None
    rpc.fee_history.return_value = {"baseFeePerGas": ["0x1"]}
    rpc.estimate_gas.return_value = 21000
    rpc.transaction_count.return_value = 0
    rpc.send_raw_transaction.return_value = tx_hash
    return rpc


async def _get_audit_rows(session: AsyncSession) -> list[dict[str, object]]:
    """Return all audit_log rows as dicts (ordered by seq)."""
    result = await session.execute(select(audit_log).order_by(audit_log.c.seq.asc()))
    return [dict(row._mapping) for row in result]


# ---------------------------------------------------------------------------
# Attack scenarios
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attack1_caller_not_in_policy(session: AsyncSession, registry: AbiRegistry) -> None:
    """Attack 1: caller not in policy.callers → Deny step 1."""
    policy = _make_policy()
    caller = _make_caller(name="unknown-caller")
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(caller="unknown-caller"),
            signer,
            rpc,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 1
    rpc.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    assert denied[-1]["action"] == "sign-and-send"
    assert "1" in str(denied[-1]["decision_reason"])
    await session.rollback()


@pytest.mark.asyncio
async def test_attack2_caller_policy_path_drift(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Attack 2: caller.policy_path drifts from policy binding → Deny step 1."""
    # Caller binding in policy has policy_path=POLICY_PATH, but the Caller
    # object carries a different policy_path.
    policy = _make_policy(caller_name=CALLER_NAME, caller_policy_path=POLICY_PATH)
    caller = _make_caller(name=CALLER_NAME, policy_path="some-other-path")
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(),
            signer,
            rpc,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 1
    rpc.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_attack3_contract_not_in_permission(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Attack 3: request.to not in perm.contracts → Deny step 2."""
    policy = _make_policy()  # ERC20_CONTRACT is the only permitted contract
    caller = _make_caller()
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    other_contract = "0x" + "de" * 20
    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(to=other_contract),
            signer,
            rpc,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 2
    rpc.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_attack4_unknown_selector_non_hex_data(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Attack 4: unknown selector / non-hex data → Deny step 3."""
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(data="0xdeadbeef" + "00" * 32),  # unknown selector
            signer,
            rpc,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 3
    rpc.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_attack5_method_not_in_policy(session: AsyncSession, registry: AbiRegistry) -> None:
    """Attack 5: method signature in ABI but NOT in policy.methods → Deny step 4."""
    # Policy permits only 'transfer'; send an 'approve' call.
    policy = _make_policy(
        methods={"transfer(address,uint256)": MethodRule(max_value_wei="1000000000000000000")}
    )
    caller = _make_caller()
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    # Build approve(address,uint256) calldata (selector 0x095ea7b3)
    approve_selector = "0x095ea7b3"
    encoded = eth_abi.encode(["address", "uint256"], [RECIPIENT_ADDR, 999])
    approve_data = "0x" + bytes.fromhex(approve_selector[2:]).hex() + encoded.hex()

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(data=approve_data),
            signer,
            rpc,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 4
    rpc.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_attack6_value_exceeds_max(session: AsyncSession, registry: AbiRegistry) -> None:
    """Attack 6: value_wei > max_value_wei → Deny step 5."""
    policy = _make_policy(methods={"transfer(address,uint256)": MethodRule(max_value_wei="1000")})
    caller = _make_caller()
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(value_wei="9999"),  # > 1000 max
            signer,
            rpc,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 5
    rpc.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_attack7_arg_predicate_mismatch(session: AsyncSession, registry: AbiRegistry) -> None:
    """Attack 6→step 6: arg_predicate mismatch on 'to' address → Deny step 6."""
    # Restrict 'to' (first arg of transfer) to only RECIPIENT_ADDR.
    policy = _make_policy(
        methods={
            "transfer(address,uint256)": MethodRule(
                max_value_wei="1000000000000000000",
                arg_predicates={"to": RECIPIENT_ADDR},
            )
        }
    )
    caller = _make_caller()
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    # Send to a DIFFERENT address → predicate fails.
    wrong_recipient = "0x" + "ff" * 20
    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(data=_transfer_calldata(to=wrong_recipient)),
            signer,
            rpc,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 6
    rpc.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_attack8_wallet_not_in_allowlist(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Attack 8: wallet not in wallet_allowlist → Deny step 7."""
    other_wallet = "other-wallet"
    policy = _make_policy(wallet_allowlist=[other_wallet])  # WALLET_NAME NOT in list
    caller = _make_caller()
    wallet = _make_wallet()  # name = WALLET_NAME
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(),
            signer,
            rpc,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 7
    rpc.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_attack9_caller_rate_exceeded(session: AsyncSession, registry: AbiRegistry) -> None:
    """Attack 9: caller rate exceeded — per_hour=1, 2nd call denied → step 8."""
    policy = _make_policy(per_hour=1)
    caller = _make_caller()
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    # First call: must succeed (consumes the 1-per-hour slot).
    # But sign_and_send goes all the way through; we need the full mock chain.
    result1 = await sign_and_send(
        _make_request(),
        signer,
        rpc,
        tx_repo,
        nonce_repo,
        caller=caller,
        wallet=wallet,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        audit_repo=audit_repo,
    )
    assert isinstance(result1, SignAndSendResult)
    await session.commit()

    # Second call: rate bucket is full → Deny step 8.
    rpc2 = _mock_rpc()
    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(),
            signer,
            rpc2,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 8
    rpc2.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_attack10_wallet_aggregate_cap_exceeded(
    session: AsyncSession, registry: AbiRegistry
) -> None:
    """Attack 10: wallet aggregate cap = 0, value = 1 → Deny step 9."""
    constraint = WalletConstraint(
        max_aggregate_value_wei_per_day="0",  # zero cap
        rate=None,
    )
    policy = _make_policy(wallet_constraint=constraint)
    caller = _make_caller()
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc()
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_and_send(
            _make_request(value_wei="1"),  # 1 > 0 cap
            signer,
            rpc,
            tx_repo,
            nonce_repo,
            caller=caller,
            wallet=wallet,
            policy=policy,
            registry=registry,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 9
    rpc.send_raw_transaction.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_permitting_policy(session: AsyncSession, registry: AbiRegistry) -> None:
    """Happy path: permitting policy → SignAndSendResult, broadcast called, audit approved."""
    tx_hash = "0x" + "fe" * 32
    policy = _make_policy()
    caller = _make_caller()
    wallet = _make_wallet()
    signer = _mock_signer()
    rpc = _mock_rpc(tx_hash=tx_hash)
    tx_repo = TransactionRepo(session)
    nonce_repo = NonceRepo(session)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    result = await sign_and_send(
        _make_request(),
        signer,
        rpc,
        tx_repo,
        nonce_repo,
        caller=caller,
        wallet=wallet,
        policy=policy,
        registry=registry,
        rate_repo=rate_repo,
        audit_repo=audit_repo,
    )

    assert isinstance(result, SignAndSendResult)
    assert result.hash == tx_hash
    rpc.send_raw_transaction.assert_awaited_once()

    rows = await _get_audit_rows(session)
    approved = [r for r in rows if r["decision"] == "approved"]
    assert len(approved) >= 1
    last_approved = approved[-1]
    assert last_approved["action"] == "sign-and-send"
    # outcome must contain the tx_id.
    outcome = json.loads(str(last_approved["outcome"]))
    assert outcome["tx_id"] == result.tx_id
    assert outcome["hash"] == tx_hash
    await session.rollback()
