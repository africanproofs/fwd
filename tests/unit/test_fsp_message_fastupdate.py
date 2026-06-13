"""Unit tests for FAST_UPDATE FSP message type.

Golden vector pinned from Go oracle (fast-updates/go-client/updates/updates.go
PrepareUpdates, run 2026-06-13):
  abi.encode(uint256*6, bytes)[block_number=1000000, replicate=7,
    gamma_x=12345678901234567890, gamma_y=98765432109876543210,
    c=111, s=222, deltas=0xdeadbeef]
  sha256(packed) = 4dbbd63397be2b796ac411a47369afbbb91f0fb6fc470a62889183d8b1594be4
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fwd.domain.fsp_message import FAST_UPDATE, build_fsp_message

# ---------------------------------------------------------------------------
# Golden constants
# ---------------------------------------------------------------------------

_BLOCK_NUMBER = 1_000_000
_REPLICATE = 7
_GAMMA_X = 12_345_678_901_234_567_890
_GAMMA_Y = 98_765_432_109_876_543_210
_C = 111
_S = 222
_DELTAS = "0xdeadbeef"

_GOLDEN_SHA256 = "4dbbd63397be2b796ac411a47369afbbb91f0fb6fc470a62889183d8b1594be4"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _build(**kwargs):
    """Call build_fsp_message with the golden inputs, overriding with kwargs."""
    defaults = dict(
        block_number=_BLOCK_NUMBER,
        replicate=_REPLICATE,
        gamma_x=_GAMMA_X,
        gamma_y=_GAMMA_Y,
        c=_C,
        s=_S,
        deltas=_DELTAS,
    )
    defaults.update(kwargs)
    return build_fsp_message(FAST_UPDATE, 0, **defaults)


# ---------------------------------------------------------------------------
# 1. Golden vector — hash matches Go oracle
# ---------------------------------------------------------------------------


def test_fast_update_golden_hash():
    result = _build()
    assert result is not None, "build_fsp_message returned None on valid input"
    assert result.message_hash.hex() == _GOLDEN_SHA256


def test_fast_update_message_type_and_epoch():
    result = _build()
    assert result is not None
    assert result.message_type == FAST_UPDATE
    assert result.reward_epoch_id == 0


# ---------------------------------------------------------------------------
# 2. Field hygiene — foreign fields → None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "foreign_kwargs",
    [
        {"no_of_weight_based_claims": 1},
        {"rewards_hash": "0x" + "ab" * 32},
        {"address": "0x" + "aa" * 20},
        {"signing_policy": "0x" + "cc" * 64},
        {"payload": "0xdeadbeef"},
        {"protocol_id": 3},
        {"registration_variant": "legacy"},
    ],
)
def test_fast_update_foreign_field_rejected(foreign_kwargs):
    result = _build(**foreign_kwargs)
    assert result is None, f"Expected None for foreign field: {foreign_kwargs}"


# ---------------------------------------------------------------------------
# 3. deltas > 4096 bytes → None
# ---------------------------------------------------------------------------


def test_fast_update_deltas_too_long():
    big_deltas = "0x" + "ab" * 4097  # 4097 bytes > 4096
    result = _build(deltas=big_deltas)
    assert result is None


def test_fast_update_deltas_exactly_4096_bytes_ok():
    ok_deltas = "0x" + "ab" * 4096  # exactly 4096 bytes
    result = _build(deltas=ok_deltas)
    assert result is not None


# ---------------------------------------------------------------------------
# 4. A six-int value of 2**256 (out of range) → None
# ---------------------------------------------------------------------------


_OUT_OF_RANGE = 2**256


@pytest.mark.parametrize(
    "field",
    ["block_number", "replicate", "gamma_x", "gamma_y", "c", "s"],
)
def test_fast_update_int_out_of_range(field):
    result = _build(**{field: _OUT_OF_RANGE})
    assert result is None, f"Expected None for out-of-range {field}=2**256"


# ---------------------------------------------------------------------------
# 5. Bad deltas hex → None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_deltas",
    [
        "deadbeef",       # missing 0x prefix
        "0xgg",           # invalid hex chars
        "0x1",            # odd length
        None,             # None instead of str
        123,              # wrong type
        "",               # empty string, no 0x
    ],
)
def test_fast_update_bad_deltas_hex(bad_deltas):
    result = build_fsp_message(
        FAST_UPDATE,
        0,
        block_number=_BLOCK_NUMBER,
        replicate=_REPLICATE,
        gamma_x=_GAMMA_X,
        gamma_y=_GAMMA_Y,
        c=_C,
        s=_S,
        deltas=bad_deltas,
    )
    assert result is None, f"Expected None for bad deltas: {bad_deltas!r}"


# ---------------------------------------------------------------------------
# 6. Missing required fields → None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "missing_field",
    ["block_number", "replicate", "gamma_x", "gamma_y", "c", "s", "deltas"],
)
def test_fast_update_missing_required_field(missing_field):
    kwargs = dict(
        block_number=_BLOCK_NUMBER,
        replicate=_REPLICATE,
        gamma_x=_GAMMA_X,
        gamma_y=_GAMMA_Y,
        c=_C,
        s=_S,
        deltas=_DELTAS,
    )
    kwargs[missing_field] = None
    result = build_fsp_message(FAST_UPDATE, 0, **kwargs)
    assert result is None, f"Expected None when {missing_field} is None"


# ---------------------------------------------------------------------------
# 7. Bool rejected for int fields (non-bool int requirement)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["block_number", "replicate", "gamma_x", "gamma_y", "c", "s"],
)
def test_fast_update_bool_rejected_for_int_field(field):
    result = _build(**{field: True})
    assert result is None, f"Expected None for bool True in {field}"


# ---------------------------------------------------------------------------
# 8. API model validates FAST_UPDATE shape
# ---------------------------------------------------------------------------


def test_api_accepts_valid_fast_update_shape():
    from fwd.api.sign_fsp_message import SignFspMessageBody

    body = SignFspMessageBody(
        wallet="test-wallet",
        message_type="FAST_UPDATE",
        reward_epoch_id=0,
        block_number=_BLOCK_NUMBER,
        replicate=_REPLICATE,
        gamma_x=_GAMMA_X,
        gamma_y=_GAMMA_Y,
        c=_C,
        s=_S,
        deltas=_DELTAS,
    )
    assert body.message_type == "FAST_UPDATE"
    assert body.block_number == _BLOCK_NUMBER
    assert body.deltas == _DELTAS


def test_api_422_on_missing_fast_update_fields():
    from fwd.api.sign_fsp_message import SignFspMessageBody

    with pytest.raises(ValidationError):
        SignFspMessageBody(
            wallet="test-wallet",
            message_type="FAST_UPDATE",
            reward_epoch_id=0,
            # all fast_update fields missing
        )


def test_api_422_on_fast_update_with_foreign_field():
    from fwd.api.sign_fsp_message import SignFspMessageBody

    with pytest.raises(ValidationError):
        SignFspMessageBody(
            wallet="test-wallet",
            message_type="FAST_UPDATE",
            reward_epoch_id=0,
            block_number=_BLOCK_NUMBER,
            replicate=_REPLICATE,
            gamma_x=_GAMMA_X,
            gamma_y=_GAMMA_Y,
            c=_C,
            s=_S,
            deltas=_DELTAS,
            payload="0xdeadbeef",  # foreign field
        )


def test_api_422_on_uptime_with_fast_update_fields():
    from fwd.api.sign_fsp_message import SignFspMessageBody

    with pytest.raises(ValidationError):
        SignFspMessageBody(
            wallet="test-wallet",
            message_type="UPTIME",
            reward_epoch_id=5,
            block_number=_BLOCK_NUMBER,  # forbidden for UPTIME
        )
