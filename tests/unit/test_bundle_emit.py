"""Unit tests for app/bundle_emit.py — compose + write + Core #7 guard +
`consumer-contract-v1` §4 (v2) conformance.

fwd is the custody daemon; the membrane runs ONE way — consumers depend on fwd's
contract, NEVER the reverse. So these tests are **self-contained**: they pin the
`consumer-contract-v1` §4 v2 bundle shape directly (a small canonical fixture),
and do NOT import clif (no sibling-repo reach). Interop with a consumer's real
importer is proven by the live **canary**, never a unit-test code dependency.
"""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003

import pytest

from fwd.app.bundle_emit import (
    BundleCapability,
    BundleEmitError,
    compose_bundle,
    write_bundle,
)

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
    assert bundle["version"] == 2  # v2 = complete handoff (config + capabilities)
    assert bundle["consumer"] == "clif"
    assert bundle["network"] == "songbird"
    assert bundle["issued_at"] == "2026-01-01T00:00:00+00:00"
    assert bundle["expires_at"] == "2026-01-01T00:10:00+00:00"
    assert bundle["config"] == {}  # no config passed → empty (a tokens-only v2 bundle)
    assert [c["capability_id"] for c in bundle["capabilities"]] == [
        "clif/songbird/claim",
        "clif/songbird/fsp-sign",
        "clif/songbird/fsp-submit",
    ]
    # Each entry has EXACTLY the 4 pinned keys.
    for entry in bundle["capabilities"]:
        assert set(entry) == {"capability_id", "caller_token_env", "caller_token", "wallet_name"}


def test_compose_emits_config_section() -> None:
    cfg = {
        "FWD_ENDPOINT": "http://fwd:8080",
        "WRAP_REWARDS": "false",
        "IDENTITY_ADDRESS": "0xabc",
    }
    bundle = compose_bundle(
        consumer="clif",
        network="songbird",
        ttl_seconds=600,
        capabilities=_SONGBIRD_CAPS,
        config=cfg,
    )
    assert bundle["version"] == 2
    assert bundle["config"] == cfg
    # config carries no token value.
    assert all("fwd_live_" not in v for v in bundle["config"].values())


def test_compose_refuses_private_key_in_config() -> None:
    for bad in ({"FWD_PRIVATE_KEY": "x"}, {"K": "this is a PRIVATE_KEY"}):
        with pytest.raises(BundleEmitError, match="PRIVATE_KEY"):
            compose_bundle(
                consumer="clif",
                network="songbird",
                ttl_seconds=600,
                capabilities=_SONGBIRD_CAPS,
                config=bad,
            )


def test_compose_refuses_unclean_config_value_no_leak() -> None:
    secret = "0xabc\nINJECTED=evil"
    with pytest.raises(BundleEmitError) as exc_info:
        compose_bundle(
            consumer="clif",
            network="songbird",
            ttl_seconds=600,
            capabilities=_SONGBIRD_CAPS,
            config={"IDENTITY_ADDRESS": secret},
        )
    assert secret not in str(exc_info.value)


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


# --- consumer-contract-v1 §4 (v2) conformance (self-contained — no clif import) --

# The pinned §4 v2 shape (fwd⊥clif: the daemon never imports a consumer; this is
# the contract, not clif's code). Live interop is proven by the canary.
_CONTRACT_V2_TOP_KEYS = {
    "version",
    "consumer",
    "network",
    "issued_at",
    "expires_at",
    "config",
    "capabilities",
}
_CONTRACT_V2_CAP_KEYS = {"capability_id", "caller_token_env", "caller_token", "wallet_name"}


def test_contract_v2_structural_conformance() -> None:
    bundle = compose_bundle(
        consumer="clif",
        network="songbird",
        ttl_seconds=600,
        capabilities=_SONGBIRD_CAPS,
        config={"FWD_ENDPOINT": "http://fwd:8080", "WRAP_REWARDS": "false"},
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    # Top-level shape is EXACTLY the §4 v2 keys.
    assert set(bundle) == _CONTRACT_V2_TOP_KEYS
    assert bundle["version"] == 2
    # config is a flat {str: str} map.
    assert isinstance(bundle["config"], dict)
    assert all(
        isinstance(k, str) and isinstance(v, str) for k, v in bundle["config"].items()
    )
    # Each capability entry has EXACTLY the 4 pinned keys (no token leaks into config).
    for entry in bundle["capabilities"]:
        assert set(entry) == _CONTRACT_V2_CAP_KEYS


def test_contract_v2_matches_pinned_fixture() -> None:
    """Pin the canonical §4 v2 JSON byte-for-byte (timestamps + token normalized)."""
    bundle = compose_bundle(
        consumer="clif",
        network="songbird",
        ttl_seconds=600,
        capabilities=[
            BundleCapability(
                "clif/songbird/claim", "FWD_CALLER_TOKEN", _TOKEN, "claimer-songbird"
            )
        ],
        config={
            "FWD_ENDPOINT": "http://fwd:8080",
            "IDENTITY_ADDRESS": "0xID",
            "CLAIM_RECIPIENT_ADDRESS": "0xRECIP",
        },
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert bundle == {
        "version": 2,
        "consumer": "clif",
        "network": "songbird",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2026-01-01T00:10:00+00:00",
        "config": {
            "FWD_ENDPOINT": "http://fwd:8080",
            "IDENTITY_ADDRESS": "0xID",
            "CLAIM_RECIPIENT_ADDRESS": "0xRECIP",
        },
        "capabilities": [
            {
                "capability_id": "clif/songbird/claim",
                "caller_token_env": "FWD_CALLER_TOKEN",
                "caller_token": _TOKEN,
                "wallet_name": "claimer-songbird",
            }
        ],
    }
