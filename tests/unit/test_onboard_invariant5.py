"""Invariant #5 closure (Unit 4b): `fwd onboard` reads OR writes NO consumer `.env`.

`install/onboard` is a host shell script (not unit-tested at runtime); the
prescribed closure proof is behavioural/grep (spec §4/§7). These tests read the
script as text and assert the breach `fwd` existed to close is closed:

  - `env_write` (the `.env` WRITE) is gone;
  - `getval` (the `.env` READ helper) is gone;
  - no `$CLIF_ENV_DIR/.env.<net>` path is read or written anywhere — the only
    file onboard touches under the clif dir is the `.fwd-bundle.<net>.json` it
    emits (the sanctioned handoff, consumer-contract-v1 §5);
  - the per-network handoff loop calls `bundle_emit` (the sole handoff);
  - a re-onboard of an existing caller ROTATES (revoke + `--replace`) — recovery
    from clif's `.env` is no longer possible (fwd holds no plaintext, Core #1/#16).
"""

from __future__ import annotations

from pathlib import Path

_ONBOARD = Path(__file__).resolve().parents[2] / "install" / "onboard"


def _text() -> str:
    return _ONBOARD.read_text()


def test_env_write_is_gone() -> None:
    text = _text()
    assert "env_write" not in text, "env_write (the .env WRITE) must be retired (Invariant #5)"


def test_getval_env_reader_is_gone() -> None:
    # getval existed ONLY to read clif's .env (preserve-existing + token recovery);
    # its removal closes the .env READ path.
    assert "getval" not in _text(), "getval (the .env READ helper) must be retired (Invariant #5)"


def test_no_clif_env_path_read_or_written() -> None:
    """The load-bearing assertion: onboard constructs NO $CLIF_ENV_DIR/.env path.

    The only file it touches under the clif dir is the .fwd-bundle.<net>.json.
    """
    text = _text()
    assert "CLIF_ENV_DIR/.env" not in text, (
        "onboard must not read or write any $CLIF_ENV_DIR/.env path (Invariant #5 closed)"
    )
    # The sanctioned handoff IS present.
    assert "CLIF_ENV_DIR/.fwd-bundle." in text


def test_handoff_loop_emits_bundle_only() -> None:
    text = _text()
    # The per-network handoff loop calls bundle_emit (the sole handoff) and not env_write.
    assert "bundle_emit " in text
    assert "env_write " not in text


def test_reonboard_rotates_existing_caller() -> None:
    """rc=3 (caller exists) rotates: revoke + re-mint (--replace), no .env recovery."""
    text = _text()
    assert "clifwd callers revoke --name" in text
    assert "--replace" in text
    # The ungoverned recovery read is gone (no getval anywhere — see above).
