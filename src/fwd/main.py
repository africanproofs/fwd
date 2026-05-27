"""FastAPI ASGI entry point.

The uvicorn entry is `fwd.main:app`. Lives at the top level of the package
(not inside a layer directory) so the layer-boundary import-graph test
correctly skips it - the FastAPI app instance composes routers from the
api/ layer but is itself an ASGI runtime artifact, not a layer member.

Phase 2 wires only /healthz. Phase 3b adds /v1/admin/wallets.
Phase 3c adds /v1/sign-and-send.
v0.3.2 adds:
  - mlockall() in the lifespan startup hook (Core invariants #1, #16).
  - structlog scrubber for hex-shaped 32-byte values (architecture.md hazard #3).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import logging
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
from fastapi import FastAPI

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, MutableMapping

from fwd.api.callers import router as callers_router
from fwd.api.health import router as health_router
from fwd.api.nonce import router as nonce_router
from fwd.api.sign import router as sign_router
from fwd.api.sign_fsp_message import router as sign_fsp_router
from fwd.api.transactions import router as transactions_router
from fwd.api.wallets import router as wallets_router
from fwd.settings import get_settings
from fwd.version import __version__

# --- structlog scrubber (architecture.md § Implementation hazards #3) -----

# Field names whose 32-byte hex values are PUBLIC and must NOT be redacted.
# Tx hashes, block hashes, state roots, and similar Ethereum/EVM artefacts
# are operationally important in logs (request tracing, on-chain follow-up).
# Phase 7 may extend this set with ABI-decoded field names.
_PUBLIC_HEX_FIELDS: frozenset[str] = frozenset(
    {
        "tx_hash",
        "hash",
        "block_hash",
        "transactionHash",
        "blockHash",
        "stateRoot",
        "transactionsRoot",
        "receiptsRoot",
        "parentHash",
        "mixHash",
    }
)

# A 32-byte hex string (with or without 0x prefix). secp256k1 privkeys, tx
# hashes, block hashes, state roots all match this shape. The scrubber
# distinguishes them by field name (above): unrecognised field + matching
# value = redact (privkey-shaped); recognised field = pass through.
_PRIVKEY_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")

_REDACTED = "<redacted-32-byte-hex>"


def _scrub_hex_secrets(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> Mapping[str, Any]:
    """Redact 32-byte hex strings unless they're in a known-public field.

    Per architecture.md § Implementation hazards #3: the most severe
    disclosure path is a logged privkey. This processor inspects every
    string value in the event dict; if it matches the 32-byte hex shape
    AND its key is not in `_PUBLIC_HEX_FIELDS`, the value is replaced
    with `<redacted-32-byte-hex>`.

    Phase 7 may extend `_PUBLIC_HEX_FIELDS` for ABI-decoded values; the
    scrubber's contract (field-aware redaction) does not change.
    """
    for k, v in list(event_dict.items()):
        if k in _PUBLIC_HEX_FIELDS:
            continue
        if isinstance(v, str) and _PRIVKEY_HEX_RE.match(v):
            event_dict[k] = _REDACTED
    return event_dict


def _configure_logging() -> None:
    """Configure structlog for JSON output to stdout.

    Includes the `_scrub_hex_secrets` processor (added in v0.3.2 per
    architecture.md hazard #3) before `JSONRenderer` so any redaction
    happens before the event is serialised.
    """
    log_level = os.environ.get("FWD_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _scrub_hex_secrets,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level, logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


_configure_logging()


# --- mlockall (Core invariant #1, #16) ------------------------------------

# mlockall constants from <sys/mman.h>. POSIX-defined values; portable
# across Linux glibc/musl, macOS, BSDs.
_MCL_CURRENT = 1
_MCL_FUTURE = 2


def _mlockall() -> None:
    """Lock fwd's process memory against swap.

    Per Core invariants #1 (keys never persist plaintext) and #16
    (decrypt-on-demand, zeroize-on-completion). The mlockall(MCL_CURRENT
    | MCL_FUTURE) syscall ensures plaintext keys briefly held in process
    memory during signing are never paged to /swapfile.

    Requires CAP_IPC_LOCK in the container (granted via cap_add: [IPC_LOCK]
    in docker-compose.yml).

    What this does NOT defend:
    - core dumps (container hardening required separately).
    - /proc/$pid/mem reads by privileged processes on the host.
    - Python GC copying values to other addresses (each copy may not
      land in a locked region; Phase 10's optional ctypes-based memory
      pinning addresses that).

    These limits are documented in Core invariant #1.
    """
    libname = ctypes.util.find_library("c") or "libc.so.6"
    libc = ctypes.CDLL(libname, use_errno=True)
    if libc.mlockall(_MCL_CURRENT | _MCL_FUTURE) != 0:
        errno = ctypes.get_errno()
        raise RuntimeError(
            f"mlockall failed: errno={errno} ({os.strerror(errno)}). "
            f"fwd requires CAP_IPC_LOCK; ensure the container has "
            f"cap_add: [IPC_LOCK] in docker-compose.yml. "
            f"To skip mlock in dev/test environments, set FWD_DISABLE_MLOCK=1."
        )


async def _startup_policy_load(_app: FastAPI) -> None:
    """Load and validate policy.yaml + ABI registry at startup (D14 fail-fast).

    Stashes the loaded Policy and AbiRegistry on app.state for use by the
    sign-and-send handler. Writes a policy-load audit row (D16). On
    consistency errors, logs each error and raises SystemExit(1) per the
    D14 fail-fast mandate.
    """
    from fwd.infra.abi_registry import AbiRegistry, AbiRegistryError
    from fwd.infra.audit_repo import AuditRepo, _canonical_json
    from fwd.infra.caller_repo import CallerRepo
    from fwd.infra.db import session_scope
    from fwd.infra.policy_loader import PolicyLoadError, check_consistency, load_policy
    from fwd.infra.wallet_repo import WalletRepo

    s = get_settings()
    policy_path = Path(s.fwd_policy_path)
    abis_dir = Path(s.fwd_abis_dir)

    log = structlog.get_logger(__name__)

    try:
        registry = AbiRegistry.load(abis_dir)
    except AbiRegistryError as exc:
        log.error("lifespan.abi_registry_load_failed", error=str(exc))
        raise SystemExit(1) from exc

    try:
        policy = load_policy(policy_path)
    except PolicyLoadError as exc:
        log.error("lifespan.policy_load_failed", error=str(exc))
        raise SystemExit(1) from exc

    outcome_dict = {
        "policy_yaml_path": str(policy_path),
        "policy_yaml_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "callers_count": len(policy.callers),
        "permissions_count": len(policy.permissions),
        "wallet_constraints_count": len(policy.wallet_constraints),
        "abis_loaded": sorted(registry.abi_names()),
        "fwd_version": __version__,
    }

    async with session_scope() as session:
        callers = await CallerRepo(session).list_all(include_revoked=False)
        wallets = await WalletRepo(session).list_all()
        errors = check_consistency(policy, callers, wallets, registry)
        audit_repo = AuditRepo(session)
        if errors:
            for err in errors:
                log.error("lifespan.policy_consistency_error", error=err)
            await audit_repo.append(
                action="policy-load",
                decision="error",
                caller=None,
                request_json=None,
                decision_reason=("; ".join(errors))[:2000],
                outcome=_canonical_json(outcome_dict),
            )
            # SystemExit is BaseException; session_scope's `except Exception`
            # neither commits nor rolls back, so commit the forensic error
            # row explicitly before exiting — D16 "the row remains as
            # evidence" (decisions.md:686).
            await session.commit()
            raise SystemExit(1)
        await audit_repo.append(
            action="policy-load",
            decision="approved",
            caller=None,
            request_json=None,
            decision_reason=(
                f"policy loaded: {len(policy.callers)} callers, "
                f"{len(policy.permissions)} permissions, "
                f"{len(policy.wallet_constraints)} wallet_constraints, "
                f"{len(registry.abi_names())} abis"
            ),
            outcome=_canonical_json(outcome_dict),
        )

        # Prune stale rate buckets (>2 days old) as a startup housekeeping step.
        # Failure here must not block boot — best-effort only.
        from datetime import UTC, datetime, timedelta

        from fwd.infra.rate_repo import RateRepo

        cutoff = datetime.now(UTC) - timedelta(days=2)
        try:
            deleted = await RateRepo(session).delete_stale(before=cutoff)
            log.info(
                "lifespan.rate_buckets_pruned",
                deleted=deleted,
                cutoff=cutoff.isoformat(),
            )
        except Exception as exc:  # noqa: BLE001 — housekeeping must not block boot
            log.warning("lifespan.delete_stale_failed", error=str(exc))

    _app.state.policy = policy
    _app.state.abi_registry = registry

    log.info(
        "lifespan.policy_loaded",
        callers=len(policy.callers),
        permissions=len(policy.permissions),
        abis=sorted(registry.abi_names()),
    )


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """ASGI lifespan: lock process memory + load policy.

    Runs when uvicorn boots the app, NOT when pytest imports `fwd.main`
    without context-managing TestClient. This means tests that do
    `client = TestClient(app)` (no `with`) skip mlockall naturally.
    Tests that do `with TestClient(app) as client:` AND don't set
    `FWD_DISABLE_MLOCK=1` will trigger mlockall and fail without
    CAP_IPC_LOCK; gate via env when needed.

    v1.1.0a9: receipt watcher, nonce reconcile, and RPC egress removed.
    """
    if os.environ.get("FWD_DISABLE_MLOCK") != "1":
        _mlockall()
        await _startup_policy_load(_app)
    elif os.environ.get("FWD_POLICY_PATH"):
        await _startup_policy_load(_app)

    yield


app = FastAPI(
    title="fwd",
    version=__version__,
    description="Flare Wallet Daemon — policy-gated signing service",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.include_router(health_router)
app.include_router(wallets_router)
app.include_router(nonce_router)
app.include_router(sign_router)
app.include_router(sign_fsp_router)
app.include_router(callers_router)
app.include_router(transactions_router)
