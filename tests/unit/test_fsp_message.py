"""KAT + default-deny tests for domain/fsp_message.build_fsp_message.

Vectors byte-verified against signing-tool@838b87f (v1.2.1) and FROZEN.
Do NOT edit the expected hex without re-deriving from upstream (Step-0 gate).
The EIP-191 signature KATs pin build -> eth-account personal_sign end-to-end.
"""

from __future__ import annotations

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

from fwd.domain.fsp_message import REWARD_DISTRIBUTION, UPTIME, build_fsp_message

_UPTIME_VOTE_HASH = "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
_UPTIME_EPOCH0_MSGHASH = "0xb7e97e6b4b2c7cd5fb9b51a86ad7eae441872b770b5953443024cb1e0bc6f67d"
_REWARDS_MSGHASH = "0x3f2025e652f0c582e59f6c0f8c7f1fde4fbd80e6f02771d0ab961cbc6ed742c0"
_KAT_KEY = "0x" + "11" * 32
_KAT_ADDR = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"
_UPTIME_SIG = (
    27,
    0x9938AFC59DAE94CB20E0C5982E00C6A88AFC01F6FF8C058024F999857A32E785,
    0x1E926390FBDECE399AA1C56DBCBC66D128D43FBA246B9459D5018D0C2DE9B4B5,
)
_REWARDS_SIG = (
    27,
    0x641235A188DAC8467DC0E8F3A71073312C4F0DDE0F91058DB0ACA10BEE275D5E,
    0x53C2ACF6985B72A9657C57368D9B5F83858F9E988EF52190C0B21410A5ACFA7A,
)


def test_uptime_vote_hash_constant() -> None:
    assert "0x" + keccak(b"\x00" * 32).hex() == _UPTIME_VOTE_HASH
    assert keccak(b"\x00" * 32) != keccak(b"")  # NOT keccak256("")


def test_uptime_kat_epoch0() -> None:
    m = build_fsp_message(UPTIME, 0)
    assert m is not None
    assert "0x" + m.message_hash.hex() == _UPTIME_EPOCH0_MSGHASH
    assert m.message_type == UPTIME
    assert m.reward_epoch_id == 0


def test_rewards_kat() -> None:
    m = build_fsp_message(
        REWARD_DISTRIBUTION,
        3,
        chain_id=114,
        no_of_weight_based_claims=56,
        rewards_hash="0x" + "ab" * 32,
    )
    assert m is not None
    assert "0x" + m.message_hash.hex() == _REWARDS_MSGHASH


def test_uptime_eip191_signature_kat() -> None:
    m = build_fsp_message(UPTIME, 0)
    assert m is not None
    signed = Account.from_key(_KAT_KEY).sign_message(encode_defunct(primitive=m.message_hash))
    assert (signed.v, signed.r, signed.s) == _UPTIME_SIG
    assert (
        Account.recover_message(
            encode_defunct(primitive=m.message_hash), signature=signed.signature
        )
        == _KAT_ADDR
    )


def test_rewards_eip191_signature_kat() -> None:
    m = build_fsp_message(
        REWARD_DISTRIBUTION,
        3,
        chain_id=114,
        no_of_weight_based_claims=56,
        rewards_hash="0x" + "ab" * 32,
    )
    assert m is not None
    signed = Account.from_key(_KAT_KEY).sign_message(encode_defunct(primitive=m.message_hash))
    assert (signed.v, signed.r, signed.s) == _REWARDS_SIG


def test_field_order_is_load_bearing() -> None:
    a = build_fsp_message(
        REWARD_DISTRIBUTION,
        3,
        chain_id=114,
        no_of_weight_based_claims=56,
        rewards_hash="0x" + "ab" * 32,
    )
    b = build_fsp_message(
        REWARD_DISTRIBUTION,
        3,
        chain_id=56,
        no_of_weight_based_claims=114,
        rewards_hash="0x" + "ab" * 32,
    )
    assert a is not None and b is not None
    assert a.message_hash != b.message_hash


def test_malformed_returns_none() -> None:
    assert build_fsp_message("BOGUS", 0) is None
    assert build_fsp_message(UPTIME, -1) is None
    assert build_fsp_message(UPTIME, 16_777_216) is None
    assert build_fsp_message(UPTIME, 0, chain_id=114) is None
    assert build_fsp_message(REWARD_DISTRIBUTION, 3) is None
    assert (
        build_fsp_message(
            REWARD_DISTRIBUTION,
            3,
            chain_id=114,
            no_of_weight_based_claims=1,
            rewards_hash="0xzz",
        )
        is None
    )
    assert (
        build_fsp_message(
            REWARD_DISTRIBUTION,
            3,
            chain_id=114,
            no_of_weight_based_claims=1,
            rewards_hash="0x" + "ab" * 31,
        )
        is None
    )
