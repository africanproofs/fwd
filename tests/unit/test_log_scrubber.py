"""Tests for the structlog hex-secret scrubber.

Per architecture.md § Implementation hazards #3: a custom processor
redacts 32-byte hex strings unless they're in a known-public field.
This is the field-aware version (v0.3.2) — see fwd/main.py for the
_PUBLIC_HEX_FIELDS whitelist.
"""

from __future__ import annotations

from fwd.main import _PUBLIC_HEX_FIELDS, _REDACTED, _scrub_hex_secrets


def test_redacts_unknown_field_with_64hex_value() -> None:
    """A 32-byte hex value in an unrecognised field is treated as a privkey."""
    event = {"my_secret": "0x" + "ab" * 32}
    out = _scrub_hex_secrets(None, "info", event)
    assert out["my_secret"] == _REDACTED


def test_redacts_no_prefix_64hex_value() -> None:
    """No-0x-prefix 64-hex strings are also redacted (eth-account .key shape)."""
    event = {"foo": "ab" * 32}
    out = _scrub_hex_secrets(None, "info", event)
    assert out["foo"] == _REDACTED


def test_passes_known_public_tx_hash() -> None:
    """tx_hash field is whitelisted — must NOT be redacted."""
    h = "0x" + "ab" * 32
    event = {"tx_hash": h}
    out = _scrub_hex_secrets(None, "info", event)
    assert out["tx_hash"] == h


def test_passes_all_whitelisted_fields() -> None:
    """Every entry in _PUBLIC_HEX_FIELDS must pass through untouched."""
    h = "0x" + "cd" * 32
    for field in _PUBLIC_HEX_FIELDS:
        event = {field: h}
        out = _scrub_hex_secrets(None, "info", event)
        assert out[field] == h, f"field {field!r} was redacted"


def test_passes_short_hex_address() -> None:
    """20-byte addresses (40 hex chars) are not 32-byte values; not redacted."""
    addr = "0x" + "ab" * 20
    event = {"some_field": addr}
    out = _scrub_hex_secrets(None, "info", event)
    assert out["some_field"] == addr


def test_passes_non_string_values() -> None:
    """Non-string values are untouched (ints, floats, bools, None)."""
    event = {"nonce": 42, "gas": 21000, "ok": True, "missing": None}
    out = _scrub_hex_secrets(None, "info", event)
    assert dict(out) == {"nonce": 42, "gas": 21000, "ok": True, "missing": None}


def test_redacts_all_three_unknown_fields_simultaneously() -> None:
    """Multiple privkey-shaped values in one event are all redacted."""
    event = {
        "privkey1": "0x" + "11" * 32,
        "privkey2": "22" * 32,
        "tx_hash": "0x" + "33" * 32,  # whitelisted
        "address": "0x" + "44" * 20,  # too short
    }
    out = _scrub_hex_secrets(None, "info", event)
    assert out["privkey1"] == _REDACTED
    assert out["privkey2"] == _REDACTED
    assert out["tx_hash"] == "0x" + "33" * 32
    assert out["address"] == "0x" + "44" * 20


def test_uppercase_hex_is_redacted() -> None:
    """Hex matching is case-insensitive — uppercase 64-char hex also redacts."""
    event = {"foo": "0x" + "AB" * 32}
    out = _scrub_hex_secrets(None, "info", event)
    assert out["foo"] == _REDACTED


def test_mixed_case_hex_is_redacted() -> None:
    event = {"foo": "0x" + ("aB" * 32)}
    out = _scrub_hex_secrets(None, "info", event)
    assert out["foo"] == _REDACTED


def test_63hex_passes_through() -> None:
    """One char short of 32-byte hex must NOT be redacted."""
    event = {"foo": "0x" + "ab" * 31 + "a"}  # 63 hex chars
    out = _scrub_hex_secrets(None, "info", event)
    assert out["foo"] == "0x" + "ab" * 31 + "a"


def test_65hex_passes_through() -> None:
    """One char too long must NOT be redacted."""
    event = {"foo": "0x" + "ab" * 32 + "a"}  # 65 hex chars
    out = _scrub_hex_secrets(None, "info", event)
    assert out["foo"] == "0x" + "ab" * 32 + "a"
