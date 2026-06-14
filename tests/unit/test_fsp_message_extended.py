"""KAT + default-deny tests for the three new FSP message types (Phase 1a).

Golden vectors byte-verified against flare-system-client@29d2c78 via the
Go oracle (fwd_oracle_test.go, now deleted). DO NOT edit without re-deriving
from the upstream Go client.

Fixed oracle inputs:
  epoch = 12345
  ADDR  = 0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294
  chain_id = 19
  POLICY_BYTES = bytes(range(1, 97))   # 0x01..0x60, 96 bytes, 3 chunks
  PAYLOAD      = bytes([0xAB] * 38)
"""

from __future__ import annotations

import pytest
from eth_utils import keccak
from pydantic import ValidationError

from fwd.api.sign_fsp_message import SignFspMessageBody
from fwd.domain.fsp_message import (
    PROTOCOL_PAYLOAD,
    REWARD_DISTRIBUTION,
    SIGNING_POLICY,
    UPTIME,
    VOTER_REGISTRATION,
    build_fsp_message,
)

# ---------------------------------------------------------------------------
# Go-oracle golden constants (from TestFwdOracle; FROZEN)
# ---------------------------------------------------------------------------

_GO_VOTER_REG_LEGACY = bytes.fromhex(
    "c443ddc08d04b16e83f680aec43050eda2053a33eb5e1fb25927748312afa0cb"
)
_GO_VOTER_REG_CHAIN_SCOPED = bytes.fromhex(
    "d62d84275e55fa1bf7de234ec89a98889b11210dbb8297f74f5553bfce0f4f46"
)
_GO_SIGNING_POLICY = bytes.fromhex(
    "7f4817c88df6596949cde098dc3b33ead835b8f224a6d254fbd1541f4c23e175"
)

# PROTOCOL_PAYLOAD: plain keccak256(payload_bytes) — no Go needed
_PAYLOAD_BYTES = bytes([0xAB] * 38)
_PROTOCOL_PAYLOAD_HASH = keccak(_PAYLOAD_BYTES)

_EPOCH = 12345
_ADDR = "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"
_CHAIN_ID = 19
_POLICY_HEX = "0x" + bytes(range(1, 97)).hex()  # 96 bytes
_PAYLOAD_HEX = "0x" + "ab" * 38


# ---------------------------------------------------------------------------
# Golden-vector tests
# ---------------------------------------------------------------------------


def test_voter_reg_legacy_golden() -> None:
    m = build_fsp_message(
        VOTER_REGISTRATION,
        _EPOCH,
        address=_ADDR,
        registration_variant="legacy",
    )
    assert m is not None
    assert m.message_hash == _GO_VOTER_REG_LEGACY
    assert m.message_type == VOTER_REGISTRATION
    assert m.reward_epoch_id == _EPOCH


def test_voter_reg_chain_scoped_golden() -> None:
    m = build_fsp_message(
        VOTER_REGISTRATION,
        _EPOCH,
        chain_id=_CHAIN_ID,
        address=_ADDR,
        registration_variant="chain_scoped",
    )
    assert m is not None
    assert m.message_hash == _GO_VOTER_REG_CHAIN_SCOPED
    assert m.message_type == VOTER_REGISTRATION
    assert m.reward_epoch_id == _EPOCH


def test_signing_policy_golden() -> None:
    m = build_fsp_message(
        SIGNING_POLICY,
        _EPOCH,
        signing_policy=_POLICY_HEX,
    )
    assert m is not None
    assert m.message_hash == _GO_SIGNING_POLICY
    assert m.message_type == SIGNING_POLICY


def test_protocol_payload_golden() -> None:
    m = build_fsp_message(
        PROTOCOL_PAYLOAD,
        _EPOCH,
        payload=_PAYLOAD_HEX,
    )
    assert m is not None
    assert m.message_hash == _PROTOCOL_PAYLOAD_HASH
    assert m.message_type == PROTOCOL_PAYLOAD


# ---------------------------------------------------------------------------
# Field-hygiene: each type rejects foreign fields
# ---------------------------------------------------------------------------


def test_voter_reg_legacy_rejects_chain_id() -> None:
    assert (
        build_fsp_message(
            VOTER_REGISTRATION,
            _EPOCH,
            chain_id=_CHAIN_ID,  # must be None for legacy
            address=_ADDR,
            registration_variant="legacy",
        )
        is None
    )


def test_voter_reg_legacy_rejects_rewards_hash() -> None:
    assert (
        build_fsp_message(
            VOTER_REGISTRATION,
            _EPOCH,
            address=_ADDR,
            registration_variant="legacy",
            rewards_hash="0x" + "ab" * 32,
        )
        is None
    )


def test_voter_reg_chain_scoped_requires_chain_id() -> None:
    # chain_id=None for chain_scoped → invalid (int check fails)
    assert (
        build_fsp_message(
            VOTER_REGISTRATION,
            _EPOCH,
            address=_ADDR,
            registration_variant="chain_scoped",
        )
        is None
    )


def test_voter_reg_rejects_no_of_weight_based_claims() -> None:
    assert (
        build_fsp_message(
            VOTER_REGISTRATION,
            _EPOCH,
            address=_ADDR,
            registration_variant="legacy",
            no_of_weight_based_claims=5,
        )
        is None
    )


def test_voter_reg_rejects_signing_policy() -> None:
    assert (
        build_fsp_message(
            VOTER_REGISTRATION,
            _EPOCH,
            address=_ADDR,
            registration_variant="legacy",
            signing_policy=_POLICY_HEX,
        )
        is None
    )


def test_voter_reg_rejects_payload() -> None:
    assert (
        build_fsp_message(
            VOTER_REGISTRATION,
            _EPOCH,
            address=_ADDR,
            registration_variant="legacy",
            payload=_PAYLOAD_HEX,
        )
        is None
    )


def test_voter_reg_invalid_variant() -> None:
    assert (
        build_fsp_message(
            VOTER_REGISTRATION,
            _EPOCH,
            address=_ADDR,
            registration_variant="bogus",  # type: ignore[arg-type]
        )
        is None
    )


def test_voter_reg_invalid_address() -> None:
    assert (
        build_fsp_message(
            VOTER_REGISTRATION,
            _EPOCH,
            address="not-an-address",
            registration_variant="legacy",
        )
        is None
    )


def test_signing_policy_rejects_chain_id() -> None:
    assert (
        build_fsp_message(
            SIGNING_POLICY,
            _EPOCH,
            chain_id=_CHAIN_ID,
            signing_policy=_POLICY_HEX,
        )
        is None
    )


def test_signing_policy_rejects_rewards_hash() -> None:
    assert (
        build_fsp_message(
            SIGNING_POLICY,
            _EPOCH,
            signing_policy=_POLICY_HEX,
            rewards_hash="0x" + "ab" * 32,
        )
        is None
    )


def test_signing_policy_rejects_address() -> None:
    assert (
        build_fsp_message(
            SIGNING_POLICY,
            _EPOCH,
            signing_policy=_POLICY_HEX,
            address=_ADDR,
        )
        is None
    )


def test_signing_policy_rejects_payload() -> None:
    assert (
        build_fsp_message(
            SIGNING_POLICY,
            _EPOCH,
            signing_policy=_POLICY_HEX,
            payload=_PAYLOAD_HEX,
        )
        is None
    )


def test_signing_policy_too_short_after_padding() -> None:
    # 32 bytes: pad to 32 → < 64 → None
    short_policy = "0x" + "aa" * 32
    assert build_fsp_message(SIGNING_POLICY, _EPOCH, signing_policy=short_policy) is None


def test_signing_policy_exactly_64_bytes() -> None:
    # 64 bytes = 2 chunks: valid (no loop iterations, just the seed hash)
    exact_64 = "0x" + "aa" * 64
    m = build_fsp_message(SIGNING_POLICY, _EPOCH, signing_policy=exact_64)
    assert m is not None


def test_signing_policy_padding_exercised() -> None:
    # 65 bytes: padded to 96 (3 chunks), exercises the loop
    padded = "0x" + "aa" * 65
    m = build_fsp_message(SIGNING_POLICY, _EPOCH, signing_policy=padded)
    assert m is not None


def test_signing_policy_bad_hex() -> None:
    assert build_fsp_message(SIGNING_POLICY, _EPOCH, signing_policy="0xzzzz") is None


def test_signing_policy_missing() -> None:
    assert build_fsp_message(SIGNING_POLICY, _EPOCH) is None


def test_protocol_payload_rejects_address() -> None:
    assert (
        build_fsp_message(
            PROTOCOL_PAYLOAD,
            _EPOCH,
            payload=_PAYLOAD_HEX,
            address=_ADDR,
        )
        is None
    )


def test_protocol_payload_rejects_signing_policy() -> None:
    assert (
        build_fsp_message(
            PROTOCOL_PAYLOAD,
            _EPOCH,
            payload=_PAYLOAD_HEX,
            signing_policy=_POLICY_HEX,
        )
        is None
    )


def test_protocol_payload_rejects_rewards_hash() -> None:
    assert (
        build_fsp_message(
            PROTOCOL_PAYLOAD,
            _EPOCH,
            payload=_PAYLOAD_HEX,
            rewards_hash="0x" + "ab" * 32,
        )
        is None
    )


def test_protocol_payload_over_length_bound() -> None:
    over = "0x" + "ab" * 4097
    assert build_fsp_message(PROTOCOL_PAYLOAD, _EPOCH, payload=over) is None


def test_protocol_payload_at_length_bound() -> None:
    at_bound = "0x" + "ab" * 4096
    m = build_fsp_message(PROTOCOL_PAYLOAD, _EPOCH, payload=at_bound)
    assert m is not None


def test_protocol_payload_missing() -> None:
    assert build_fsp_message(PROTOCOL_PAYLOAD, _EPOCH) is None


def test_protocol_payload_empty() -> None:
    assert build_fsp_message(PROTOCOL_PAYLOAD, _EPOCH, payload="0x") is None


def test_protocol_payload_bad_hex() -> None:
    assert build_fsp_message(PROTOCOL_PAYLOAD, _EPOCH, payload="0xzz") is None


def test_protocol_payload_accepts_protocol_id() -> None:
    """protocol_id is audit-only; accepted without affecting the hash."""
    m1 = build_fsp_message(PROTOCOL_PAYLOAD, _EPOCH, payload=_PAYLOAD_HEX, protocol_id=42)
    m2 = build_fsp_message(PROTOCOL_PAYLOAD, _EPOCH, payload=_PAYLOAD_HEX)
    assert m1 is not None and m2 is not None
    assert m1.message_hash == m2.message_hash


# ---------------------------------------------------------------------------
# Cross-contamination: SIGNING_POLICY with reward field → None
# ---------------------------------------------------------------------------


def test_signing_policy_with_reward_fields_none() -> None:
    assert (
        build_fsp_message(
            SIGNING_POLICY,
            _EPOCH,
            signing_policy=_POLICY_HEX,
            no_of_weight_based_claims=1,
        )
        is None
    )


# ---------------------------------------------------------------------------
# Existing UPTIME/REWARD vectors still pass (regression)
# ---------------------------------------------------------------------------

_UPTIME_EPOCH0_MSGHASH = "0xb7e97e6b4b2c7cd5fb9b51a86ad7eae441872b770b5953443024cb1e0bc6f67d"
_REWARDS_MSGHASH = "0x3f2025e652f0c582e59f6c0f8c7f1fde4fbd80e6f02771d0ab961cbc6ed742c0"


def test_uptime_regression() -> None:
    m = build_fsp_message(UPTIME, 0)
    assert m is not None
    assert "0x" + m.message_hash.hex() == _UPTIME_EPOCH0_MSGHASH


def test_rewards_regression() -> None:
    m = build_fsp_message(
        REWARD_DISTRIBUTION,
        3,
        chain_id=114,
        no_of_weight_based_claims=56,
        rewards_hash="0x" + "ab" * 32,
    )
    assert m is not None
    assert "0x" + m.message_hash.hex() == _REWARDS_MSGHASH


# ---------------------------------------------------------------------------
# API model: SignFspMessageBody — accept valid, raise on malformed
# ---------------------------------------------------------------------------

_BASE_WALLET = "test-wallet"


def _voter_reg_legacy_body(**overrides):  # type: ignore[no-untyped-def]
    return {
        "wallet": _BASE_WALLET,
        "message_type": "VOTER_REGISTRATION",
        "reward_epoch_id": _EPOCH,
        "chain_id": _CHAIN_ID,  # required gate field; legacy carries it for scoping, excluded from hash
        "address": _ADDR,
        "registration_variant": "legacy",
        **overrides,
    }


def _voter_reg_chain_body(**overrides):  # type: ignore[no-untyped-def]
    return {
        "wallet": _BASE_WALLET,
        "message_type": "VOTER_REGISTRATION",
        "reward_epoch_id": _EPOCH,
        "chain_id": _CHAIN_ID,
        "address": _ADDR,
        "registration_variant": "chain_scoped",
        **overrides,
    }


def _signing_policy_body(**overrides):  # type: ignore[no-untyped-def]
    return {
        "wallet": _BASE_WALLET,
        "message_type": "SIGNING_POLICY",
        "reward_epoch_id": _EPOCH,
        "chain_id": _CHAIN_ID,  # required gate field; excluded from the SIGNING_POLICY hash
        "signing_policy": _POLICY_HEX,
        **overrides,
    }


def _protocol_payload_body(**overrides):  # type: ignore[no-untyped-def]
    return {
        "wallet": _BASE_WALLET,
        "message_type": "PROTOCOL_PAYLOAD",
        "reward_epoch_id": _EPOCH,
        "chain_id": _CHAIN_ID,  # required gate field
        "payload": _PAYLOAD_HEX,
        **overrides,
    }


def test_api_voter_reg_legacy_valid() -> None:
    b = SignFspMessageBody(**_voter_reg_legacy_body())
    assert b.registration_variant == "legacy"
    assert b.chain_id == _CHAIN_ID  # legacy now carries chain_id for gate-scoping (excluded from hash)


def test_api_voter_reg_chain_scoped_valid() -> None:
    b = SignFspMessageBody(**_voter_reg_chain_body())
    assert b.registration_variant == "chain_scoped"
    assert b.chain_id == _CHAIN_ID


def test_api_voter_reg_legacy_missing_chain_id_raises() -> None:
    # chain_id is now a universal required gate field — legacy must carry it too.
    body = _voter_reg_legacy_body()
    del body["chain_id"]
    with pytest.raises(ValidationError):
        SignFspMessageBody(**body)


def test_api_voter_reg_chain_scoped_missing_chain_id_raises() -> None:
    with pytest.raises(ValidationError):
        SignFspMessageBody(
            wallet=_BASE_WALLET,
            message_type="VOTER_REGISTRATION",
            reward_epoch_id=_EPOCH,
            address=_ADDR,
            registration_variant="chain_scoped",
        )


def test_api_voter_reg_missing_address_raises() -> None:
    with pytest.raises(ValidationError):
        SignFspMessageBody(
            wallet=_BASE_WALLET,
            message_type="VOTER_REGISTRATION",
            reward_epoch_id=_EPOCH,
            chain_id=_CHAIN_ID,
            registration_variant="legacy",
        )


def test_api_voter_reg_with_payload_raises() -> None:
    with pytest.raises(ValidationError):
        SignFspMessageBody(**_voter_reg_legacy_body(payload=_PAYLOAD_HEX))


def test_api_signing_policy_valid() -> None:
    b = SignFspMessageBody(**_signing_policy_body())
    assert b.signing_policy == _POLICY_HEX


def test_api_signing_policy_missing_raises() -> None:
    with pytest.raises(ValidationError):
        SignFspMessageBody(
            wallet=_BASE_WALLET,
            message_type="SIGNING_POLICY",
            reward_epoch_id=_EPOCH,
            chain_id=_CHAIN_ID,
        )


def test_api_signing_policy_missing_chain_id_raises() -> None:
    # SIGNING_POLICY now requires chain_id (gate replay-scoping; excluded from hash).
    body = _signing_policy_body()
    del body["chain_id"]
    with pytest.raises(ValidationError):
        SignFspMessageBody(**body)


def test_api_signing_policy_with_rewards_hash_raises() -> None:
    with pytest.raises(ValidationError):
        SignFspMessageBody(**_signing_policy_body(rewards_hash="0x" + "ab" * 32))


def test_api_protocol_payload_valid() -> None:
    b = SignFspMessageBody(**_protocol_payload_body())
    assert b.payload == _PAYLOAD_HEX


def test_api_protocol_payload_missing_raises() -> None:
    with pytest.raises(ValidationError):
        SignFspMessageBody(
            wallet=_BASE_WALLET,
            message_type="PROTOCOL_PAYLOAD",
            reward_epoch_id=_EPOCH,
            chain_id=_CHAIN_ID,
        )


def test_api_protocol_payload_with_address_raises() -> None:
    with pytest.raises(ValidationError):
        SignFspMessageBody(**_protocol_payload_body(address=_ADDR))


def test_api_protocol_payload_with_signing_policy_raises() -> None:
    with pytest.raises(ValidationError):
        SignFspMessageBody(**_protocol_payload_body(signing_policy=_POLICY_HEX))


def test_api_protocol_payload_accepts_protocol_id() -> None:
    b = SignFspMessageBody(**_protocol_payload_body(protocol_id=7))
    assert b.protocol_id == 7


def test_api_uptime_regression() -> None:
    b = SignFspMessageBody(
        wallet=_BASE_WALLET,
        message_type="UPTIME",
        reward_epoch_id=0,
        chain_id=_CHAIN_ID,  # UPTIME now carries chain_id (gate replay-scoping; excluded from hash)
    )
    assert b.message_type == "UPTIME"
    assert b.chain_id == _CHAIN_ID


def test_api_uptime_missing_chain_id_raises() -> None:
    # The structurally-unsignable bug: UPTIME used to forbid chain_id while the gate required it.
    # chain_id is now required; a UPTIME body without it fails at the API boundary (422), not silently.
    with pytest.raises(ValidationError):
        SignFspMessageBody(
            wallet=_BASE_WALLET,
            message_type="UPTIME",
            reward_epoch_id=0,
        )


def test_api_uptime_with_new_fields_raises() -> None:
    with pytest.raises(ValidationError):
        SignFspMessageBody(
            wallet=_BASE_WALLET,
            message_type="UPTIME",
            reward_epoch_id=0,
            chain_id=_CHAIN_ID,
            address=_ADDR,
        )
