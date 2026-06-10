"""App-layer one-shot credential-bundle emission (ADR-0001 — the handoff bundle).

fwd composes a pinned **v1 bundle** carrying the bearer caller-token VALUES it
just minted, to a local mode-0600 host file. A keyless consumer (clif, the
reference) imports it (`import-credentials`), writes each token into its
per-network `.env.<network>`, then consumes (deletes) the bundle.

This is the ONLY artifact outside fwd's DB that ever carries plaintext
caller-token values. **Core #7 is load-bearing: the bundle holds BEARER tokens,
NEVER a signing key** — `compose_bundle` refuses any `*PRIVATE_KEY*` env name or
value (mirrors the `env_write` refuse-guard) and rejects a token clif's importer
would reject (so fwd never emits a bundle that fails acceptance). The token
plaintext exists only at mint/compose time — fwd retains none (Core #1/#16), so
re-emit ⇒ re-mint (the `--replace` rotation channel).

Zero-egress: emission is a local file write; the timestamps use fwd's LOCAL
clock (zero-egress is about the network, not the clock). No infra import; no
outbound connection.

The bundle SHAPE is pinned by `consumer-contract-v1` §4 and clif's
`credentials.py::validate_bundle` — the frozen acceptance oracle the golden test
runs fwd's output through (never a hand-copied fixture).
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

__all__ = [
    "BundleCapability",
    "BundleEmitError",
    "compose_bundle",
    "write_bundle",
]

BUNDLE_VERSION = 1


class BundleEmitError(Exception):
    """Raised when a bundle cannot be safely composed (Core #7 / malformed token)."""


@dataclass(frozen=True)
class BundleCapability:
    """One granted capability's bundle entry. `caller_token` is a BEARER token
    value (`fwd_live_…`), NEVER a signing key."""

    capability_id: str
    caller_token_env: str
    caller_token: str
    wallet_name: str | None


def _reject_if_private_key(cap: BundleCapability) -> None:
    """Core #7: the bundle carries bearer tokens, never a signing key. Refuse if
    the env NAME or the token VALUE looks like a `*PRIVATE_KEY*` (carries over the
    `env_write` `grep -qi PRIVATE_KEY` refuse-guard)."""
    for field in (cap.caller_token_env, cap.caller_token):
        if "PRIVATE_KEY" in field.upper():
            raise BundleEmitError(
                f"refusing to emit capability {cap.capability_id!r}: an env name or value looks "
                "like a *PRIVATE_KEY* — the bundle carries bearer caller tokens, never a signing "
                "key (Core #7)"
            )


def _reject_if_unclean_token(cap: BundleCapability) -> None:
    """Reject a token clif's importer would reject (empty / not stripped / control
    chars → `.env` injection), so fwd fails closed at compose rather than emitting
    a bundle that cannot be accepted."""
    t = cap.caller_token
    if not t or t != t.strip() or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in t):
        raise BundleEmitError(
            f"capability {cap.capability_id!r} caller_token is empty or contains illegal "
            "characters (refusing to emit an un-importable bundle)"
        )


def compose_bundle(
    *,
    consumer: str,
    network: str,
    ttl_seconds: int,
    capabilities: list[BundleCapability],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the pinned v1 bundle dict (consumer-contract-v1 §4).

    `issued_at` = now (fwd's local clock); `expires_at` = now + ttl_seconds.
    Raises BundleEmitError on a `*PRIVATE_KEY*` env/value (Core #7) or an unclean
    token. Never logs a token value.
    """
    if not capabilities:
        raise BundleEmitError("refusing to emit a bundle with no capabilities")
    if ttl_seconds <= 0:
        raise BundleEmitError(f"ttl_seconds must be positive, got {ttl_seconds}")
    moment = now if now is not None else datetime.now(UTC)
    for cap in capabilities:
        _reject_if_private_key(cap)
        _reject_if_unclean_token(cap)
    return {
        "version": BUNDLE_VERSION,
        "consumer": consumer,
        "network": network,
        "issued_at": moment.isoformat(),
        "expires_at": (moment + timedelta(seconds=ttl_seconds)).isoformat(),
        "capabilities": [
            {
                "capability_id": c.capability_id,
                "caller_token_env": c.caller_token_env,
                "caller_token": c.caller_token,
                "wallet_name": c.wallet_name,
            }
            for c in capabilities
        ],
    }


def write_bundle(bundle: dict[str, Any], path: Path) -> None:
    """Write *bundle* to *path* as JSON, mode-0600, atomically.

    The temp file is created 0600 (mkstemp default) BEFORE the token bytes land,
    so they never briefly sit world-readable; `os.replace` is the atomic publish.
    The path MUST be OUTSIDE fwd's backup/litestream scope (R3) — the bundle is a
    transient consumer-side secret, never a fwd-replicated artifact (caller's
    responsibility; the default onboard path `${CLIF_ENV_DIR}/.fwd-bundle.<net>.json`
    satisfies this).
    """
    path = Path(path)
    data = json.dumps(bundle, indent=2) + "\n"
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f"{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise
    os.chmod(path, 0o600)
