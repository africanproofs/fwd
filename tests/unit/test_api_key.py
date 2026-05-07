"""api_key.py unit tests: round-trip, prefix extraction, key shape."""

from __future__ import annotations

from fwd.infra.api_key import (
    extract_prefix,
    generate_api_key,
    verify_api_key,
)


def test_generate_key_shape() -> None:
    g = generate_api_key()
    assert g.key.startswith("fwd_live_")
    # `fwd_live_` (9) + 43 random base64url chars = 52 total.
    assert len(g.key) == 52
    assert len(g.key_prefix) == 8
    # Prefix is the first 8 chars of the random portion (NOT `fwd_live_`).
    assert g.key_prefix == g.key[len("fwd_live_") : len("fwd_live_") + 8]


def test_round_trip_verify() -> None:
    g = generate_api_key()
    assert verify_api_key(g.key, g.key_hash) is True
    assert verify_api_key("fwd_live_wrong" + "x" * 38, g.key_hash) is False
    assert verify_api_key(g.key + "extra", g.key_hash) is False


def test_extract_prefix_happy() -> None:
    g = generate_api_key()
    assert extract_prefix(g.key) == g.key_prefix


def test_extract_prefix_bad_shape() -> None:
    assert extract_prefix("not-a-key") is None
    assert extract_prefix("fwd_live_short") is None
    assert extract_prefix("fwd_test_" + "x" * 43) is None  # wrong env prefix
    assert extract_prefix("") is None


def test_two_keys_have_different_hashes() -> None:
    a = generate_api_key()
    b = generate_api_key()
    assert a.key != b.key
    assert a.key_hash != b.key_hash


def test_verify_unrelated_key_against_hash() -> None:
    a = generate_api_key()
    b = generate_api_key()
    assert verify_api_key(b.key, a.key_hash) is False
