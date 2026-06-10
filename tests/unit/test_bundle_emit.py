"""Unit tests for app/bundle_emit.py — compose + write + Core #7 guard + the
clif `validate_bundle` golden oracle.

The golden test runs fwd's composed bundle through clif's REAL
`credentials.py::validate_bundle` (the frozen acceptance oracle) — never a
hand-copied fixture (which silently drifts). It imports clif from the co-located
sibling repo and SKIPS if clif is not present (e.g. CI without the umbrella).
"""

from __future__ import annotations

import json
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fwd.app.bundle_emit import (
    BundleCapability,
    BundleEmitError,
    compose_bundle,
    write_bundle,
)

_FWD_ROOT = Path(__file__).resolve().parents[2]
_CLIF_ROOT = _FWD_ROOT.parent / "clif"

_TOKEN = "fwd_live_" + "a" * 43
_SONGBIRD_CAPS = [
    BundleCapability("clif/songbird/claim", "FWD_CALLER_TOKEN", _TOKEN, "claimer-songbird"),
    BundleCapability(
        "clif/songbird/fsp-sign", "FSP_SIGN_CALLER_TOKEN", "fwd_live_" + "b" * 43, "fsp-signing-songbird"
    ),
    BundleCapability(
        "clif/songbird/fsp-submit", "FSP_SUBMIT_CALLER_TOKEN", "fwd_live_" + "c" * 43, "fsp-sender-songbird"
    ),
]


# --- compose_bundle: §4 shape + TTL -----------------------------------------


def test_compose_shape_and_keys() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    bundle = compose_bundle(
        consumer="clif", network="songbird", ttl_seconds=600, capabilities=_SONGBIRD_CAPS, now=now
    )
    assert bundle["version"] == 1
    assert bundle["consumer"] == "clif"
    assert bundle["network"] == "songbird"
    assert bundle["issued_at"] == "2026-01-01T00:00:00+00:00"
    assert bundle["expires_at"] == "2026-01-01T00:10:00+00:00"
    assert [c["capability_id"] for c in bundle["capabilities"]] == [
        "clif/songbird/claim",
        "clif/songbird/fsp-sign",
        "clif/songbird/fsp-submit",
    ]
    # Each entry has EXACTLY the 4 pinned keys.
    for entry in bundle["capabilities"]:
        assert set(entry) == {"capability_id", "caller_token_env", "caller_token", "wallet_name"}


def test_compose_empty_capabilities_refused() -> None:
    with pytest.raises(BundleEmitError):
        compose_bundle(consumer="clif", network="songbird", ttl_seconds=600, capabilities=[])


def test_compose_nonpositive_ttl_refused() -> None:
    with pytest.raises(BundleEmitError):
        compose_bundle(
            consumer="clif", network="songbird", ttl_seconds=0, capabilities=_SONGBIRD_CAPS
        )


# --- Core #7: never a signing key -------------------------------------------


def test_compose_refuses_private_key_in_env_name() -> None:
    caps = [BundleCapability("clif/songbird/claim", "FWD_PRIVATE_KEY", _TOKEN, "w")]
    with pytest.raises(BundleEmitError, match="PRIVATE_KEY"):
        compose_bundle(consumer="clif", network="songbird", ttl_seconds=600, capabilities=caps)


def test_compose_refuses_private_key_in_token_value() -> None:
    caps = [BundleCapability("clif/songbird/claim", "FWD_CALLER_TOKEN", "MY_PRIVATE_KEY_abc", "w")]
    with pytest.raises(BundleEmitError, match="PRIVATE_KEY"):
        compose_bundle(consumer="clif", network="songbird", ttl_seconds=600, capabilities=caps)


def test_compose_refuses_unclean_token_and_does_not_leak_it() -> None:
    secret = "fwd_live_with\nnewline"
    caps = [BundleCapability("clif/songbird/claim", "FWD_CALLER_TOKEN", secret, "w")]
    with pytest.raises(BundleEmitError) as exc_info:
        compose_bundle(consumer="clif", network="songbird", ttl_seconds=600, capabilities=caps)
    # No-leak: the refusal message names the capability, never the token value.
    assert secret not in str(exc_info.value)


# --- write_bundle: 0600 + atomic + round-trip -------------------------------


def test_write_bundle_is_0600_and_round_trips(tmp_path: Path) -> None:
    bundle = compose_bundle(
        consumer="clif", network="songbird", ttl_seconds=600, capabilities=_SONGBIRD_CAPS
    )
    out = tmp_path / ".fwd-bundle.songbird.json"
    write_bundle(bundle, out)
    assert out.is_file()
    mode = stat.S_IMODE(out.stat().st_mode)
    assert mode == 0o600, f"bundle must be 0600, got {oct(mode)}"
    assert json.loads(out.read_text()) == bundle
    # No stray temp files left behind.
    assert list(tmp_path.glob("*.tmp")) == []


# --- GOLDEN: clif's REAL validate_bundle is the acceptance oracle ------------


def _clif_oracle():  # type: ignore[no-untyped-def]
    if not (_CLIF_ROOT / "clif" / "credentials.py").is_file():
        pytest.skip(f"clif not co-located at {_CLIF_ROOT} — golden oracle unavailable")
    if str(_CLIF_ROOT) not in sys.path:
        sys.path.insert(0, str(_CLIF_ROOT))
    try:
        from clif.config import Settings
        from clif.credentials import BundleError, validate_bundle
    except Exception as exc:  # noqa: BLE001 — any import failure → skip, not fail
        pytest.skip(f"clif import failed ({exc}) — golden oracle unavailable")
    return validate_bundle, Settings, BundleError


def test_golden_compose_accepted_by_clif_validate_bundle() -> None:
    validate_bundle, settings_cls, _ = _clif_oracle()
    bundle = compose_bundle(
        consumer="clif", network="songbird", ttl_seconds=600, capabilities=_SONGBIRD_CAPS
    )
    assert validate_bundle(bundle, settings_cls(network="songbird")) == "songbird"


def test_golden_ungoverned_capability_rejected_by_oracle() -> None:
    """Sanity that the oracle is real (not a no-op): an ungoverned id is rejected."""
    validate_bundle, settings_cls, bundle_error = _clif_oracle()
    caps = [BundleCapability("clif/songbird/bogus", "FWD_CALLER_TOKEN", _TOKEN, "w")]
    bundle = compose_bundle(
        consumer="clif", network="songbird", ttl_seconds=600, capabilities=caps
    )
    with pytest.raises(bundle_error):
        validate_bundle(bundle, settings_cls(network="songbird"))
