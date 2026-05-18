"""Default-deny matrix + happy path + forensic-arm tests for sign_fsp_message.

App-layer. Real AuditRepo + RateRepo against tmp-sqlite; signer is AsyncMock.
All DB metadata (audit + rate, including fsp_rate_buckets) on ONE engine/session.

For each deny scenario the test asserts:
  - sign_fsp_message raises PolicyDenied.
  - An audit row exists with action="fsp-sign-message", decision="denied".
  - signer.sign_fsp_eip191 was NOT awaited.

Happy-path: SignFspMessageResult returned, sign_fsp_eip191 awaited once,
audit row decision="approved" with message_hash + signature in outcome.

Sign-fail arm: SealError from sign_fsp_eip191 raises VaultUnavailableError,
an "error" audit row exists, and fsp_rate_buckets counter is net-zero.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.app.policy_gate import PolicyDenied
from fwd.app.sign_fsp_message import (
    SignFspMessageRequest,
    SignFspMessageResult,
    VaultUnavailableError,
    sign_fsp_message,
)
from fwd.domain.policy import Policy
from fwd.domain.signer import SignedDigest
from fwd.infra.audit_repo import AuditRepo, audit_log, audit_metadata
from fwd.infra.caller_repo import Caller
from fwd.infra.rate_repo import RateRepo, fsp_rate_buckets, rate_metadata
from fwd.infra.sealed_master import SealError

CALLER_NAME = "fsp-caller"
WALLET_NAME = "fsp-wallet"
POLICY_PATH = "fsp/main"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def session(tmp_path):  # type: ignore[no-untyped-def]
    """Single engine/session for audit + rate metadata."""
    db = tmp_path / "test_fsp_policy.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(audit_metadata.create_all)
        await conn.run_sync(rate_metadata.create_all)
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


def _make_policy(
    *,
    message_types: list[str] | None = None,
    wallet_allowlist: list[str] | None = None,
    per_hour: int | None = None,
    fsp_path: str = POLICY_PATH,
    caller_name: str = CALLER_NAME,
    also_in_evm_permissions: bool = False,
) -> Policy:
    if message_types is None:
        message_types = ["UPTIME", "REWARD_DISTRIBUTION"]
    if wallet_allowlist is None:
        wallet_allowlist = [WALLET_NAME]

    rate_dict: dict[str, int] = {}
    if per_hour is not None:
        rate_dict["per_hour"] = per_hour

    fsp_block: dict[str, object] = {
        "message_types": message_types,
        "wallet_allowlist": wallet_allowlist,
    }
    if rate_dict:
        fsp_block["rate"] = rate_dict

    raw: dict[str, object] = {
        "version": 1,
        "callers": {
            caller_name: {"policy_path": fsp_path},
        },
        "permissions": {},
        "fsp_permissions": {
            fsp_path: fsp_block,
        },
        "wallet_constraints": {},
    }
    if also_in_evm_permissions:
        # Put fsp_path in BOTH permissions and fsp_permissions to test step 3.
        raw["permissions"] = {
            fsp_path: {
                "contracts": {},
                "wallet_allowlist": [],
            }
        }
    return Policy.model_validate(raw)


def _make_request(
    message_type: str = "UPTIME",
    wallet: str = WALLET_NAME,
    caller: str = CALLER_NAME,
    reward_epoch_id: int = 42,
) -> SignFspMessageRequest:
    return SignFspMessageRequest(
        wallet=wallet,
        caller=caller,
        message_type=message_type,
        reward_epoch_id=reward_epoch_id,
    )


def _mock_signer(*, raise_seal_error: bool = False) -> AsyncMock:
    """AsyncMock for EnvelopeSigner: address() + sign_fsp_eip191()."""
    signer = AsyncMock()
    signer.address.return_value = "0x" + "aa" * 20
    if raise_seal_error:
        signer.sign_fsp_eip191.side_effect = SealError("decrypt failed")
    else:
        # Return a realistic SignedDigest
        mh = b"\x01" * 32
        sig = b"\x02" * 65
        signer.sign_fsp_eip191.return_value = SignedDigest(
            message_hash=mh,
            r=1,
            s=2,
            v=27,
            signature=sig,
        )
    return signer


async def _get_audit_rows(session: AsyncSession) -> list[dict[str, object]]:
    result = await session.execute(select(audit_log).order_by(audit_log.c.seq.asc()))
    return [dict(row._mapping) for row in result]


# ---------------------------------------------------------------------------
# Deny scenarios
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_caller_not_in_policy(session: AsyncSession) -> None:
    """Step 1: caller name not in policy.callers."""
    policy = _make_policy()
    caller = _make_caller(name="unknown-caller")
    signer = _mock_signer()
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_fsp_message(
            _make_request(caller="unknown-caller"),
            signer,
            caller=caller,
            policy=policy,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 1
    signer.sign_fsp_eip191.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    assert denied[-1]["action"] == "fsp-sign-message"
    await session.rollback()


@pytest.mark.asyncio
async def test_caller_policy_path_drift(session: AsyncSession) -> None:
    """Step 1: caller.policy_path drifts from policy binding."""
    policy = _make_policy()
    caller = _make_caller(policy_path="stale/path")
    signer = _mock_signer()
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_fsp_message(
            _make_request(),
            signer,
            caller=caller,
            policy=policy,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 1
    signer.sign_fsp_eip191.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_no_fsp_permissions_block(session: AsyncSession) -> None:
    """Step 2: binding.policy_path has no fsp_permissions entry."""
    # Make a policy where the caller is bound but fsp_permissions uses a DIFFERENT key.
    raw = {
        "version": 1,
        "callers": {CALLER_NAME: {"policy_path": "fsp/main"}},
        "permissions": {},
        "fsp_permissions": {"fsp/other": {"message_types": ["UPTIME"], "wallet_allowlist": [WALLET_NAME]}},
        "wallet_constraints": {},
    }
    policy = Policy.model_validate(raw)
    caller = _make_caller()
    signer = _mock_signer()
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_fsp_message(
            _make_request(),
            signer,
            caller=caller,
            policy=policy,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 2
    signer.sign_fsp_eip191.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_policy_path_also_evm_permissions(session: AsyncSession) -> None:
    """Step 3: policy_path present in BOTH permissions and fsp_permissions."""
    policy = _make_policy(also_in_evm_permissions=True)
    caller = _make_caller()
    signer = _mock_signer()
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_fsp_message(
            _make_request(),
            signer,
            caller=caller,
            policy=policy,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 3
    signer.sign_fsp_eip191.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_message_type_not_permitted(session: AsyncSession) -> None:
    """Step 4: message_type not in fsp_permissions.message_types."""
    policy = _make_policy(message_types=["UPTIME"])  # REWARD_DISTRIBUTION not permitted
    caller = _make_caller()
    signer = _mock_signer()
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_fsp_message(
            _make_request(message_type="REWARD_DISTRIBUTION"),
            signer,
            caller=caller,
            policy=policy,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 4
    signer.sign_fsp_eip191.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_wallet_not_in_fsp_allowlist(session: AsyncSession) -> None:
    """Step 5: wallet not in fsp_permissions.wallet_allowlist."""
    policy = _make_policy(wallet_allowlist=["other-wallet"])
    caller = _make_caller()
    signer = _mock_signer()
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(PolicyDenied) as exc_info:
        await sign_fsp_message(
            _make_request(wallet=WALLET_NAME),
            signer,
            caller=caller,
            policy=policy,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 5
    signer.sign_fsp_eip191.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


@pytest.mark.asyncio
async def test_fsp_rate_exceeded(session: AsyncSession) -> None:
    """Step 6: first call ok, second denied when per_hour=1."""
    policy = _make_policy(per_hour=1)
    caller = _make_caller()
    signer = _mock_signer()
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    # First call succeeds.
    result1 = await sign_fsp_message(
        _make_request(),
        signer,
        caller=caller,
        policy=policy,
        rate_repo=rate_repo,
        audit_repo=audit_repo,
    )
    assert isinstance(result1, SignFspMessageResult)
    await session.commit()

    # Second call rate-limited.
    signer2 = _mock_signer()
    with pytest.raises(PolicyDenied) as exc_info:
        await sign_fsp_message(
            _make_request(),
            signer2,
            caller=caller,
            policy=policy,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )
    assert exc_info.value.step == 6
    signer2.sign_fsp_eip191.assert_not_awaited()

    rows = await _get_audit_rows(session)
    denied = [r for r in rows if r["decision"] == "denied"]
    assert len(denied) >= 1
    await session.rollback()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path(session: AsyncSession) -> None:
    """Permitting policy -> SignFspMessageResult, sign_fsp_eip191 called, audit approved."""
    policy = _make_policy()
    caller = _make_caller()
    signer = _mock_signer()
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    result = await sign_fsp_message(
        _make_request(),
        signer,
        caller=caller,
        policy=policy,
        rate_repo=rate_repo,
        audit_repo=audit_repo,
    )

    assert isinstance(result, SignFspMessageResult)
    assert result.message_hash.startswith("0x")
    assert result.signature.startswith("0x")
    signer.sign_fsp_eip191.assert_awaited_once()

    rows = await _get_audit_rows(session)
    approved = [r for r in rows if r["decision"] == "approved"]
    assert len(approved) >= 1
    last_approved = approved[-1]
    assert last_approved["action"] == "fsp-sign-message"
    outcome = json.loads(str(last_approved["outcome"]))
    assert "message_hash" in outcome
    assert "signature" in outcome
    await session.rollback()


# ---------------------------------------------------------------------------
# Sign-fail arm (Core #19 ARM 3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sign_fail_arm_error_row_and_net_zero_rate(session: AsyncSession) -> None:
    """SealError from sign_fsp_eip191 -> VaultUnavailableError, error audit row,
    and fsp_rate_buckets counter is net-zero after (rate released)."""
    policy = _make_policy(per_hour=10)
    caller = _make_caller()
    signer = _mock_signer(raise_seal_error=True)
    rate_repo = RateRepo(session)
    audit_repo = AuditRepo(session)

    with pytest.raises(VaultUnavailableError):
        await sign_fsp_message(
            _make_request(),
            signer,
            caller=caller,
            policy=policy,
            rate_repo=rate_repo,
            audit_repo=audit_repo,
        )

    # Error audit row must exist (committed before raise per Core #19 ARM 3).
    rows = await _get_audit_rows(session)
    error_rows = [r for r in rows if r["decision"] == "error"]
    assert len(error_rows) >= 1
    assert error_rows[-1]["action"] == "fsp-sign-message"

    # fsp_rate_buckets counter must be net-zero (rate was incremented then released).
    result = await session.execute(
        select(fsp_rate_buckets.c.counter).where(
            fsp_rate_buckets.c.caller == CALLER_NAME,
            fsp_rate_buckets.c.wallet == WALLET_NAME,
            fsp_rate_buckets.c.message_type == "UPTIME",
        )
    )
    counters = [row[0] for row in result]
    # All counters must be 0 (net-zero: increment then release).
    for c in counters:
        assert c == 0, f"expected net-zero fsp_rate_buckets counter but got {c}"

    await session.rollback()
