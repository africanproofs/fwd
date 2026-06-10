"""Caller-create use case.

Generates a fresh API key, stores its hash + prefix, returns the
plaintext key (which `clifwd callers create` will print ONCE).

v0.5.0a7 adds the hash-chained audit-log row (D16): one row per call
(success or known-failure) on the shared AdminScope session. request_json
carries name + policy_path only — NEVER the api_key plaintext or hash.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from fwd.infra.api_key import generate_api_key
from fwd.infra.audit_repo import _canonical_json
from fwd.infra.caller_repo import CallerExistsError

if TYPE_CHECKING:
    from fwd.infra.audit_repo import AuditRepo
    from fwd.infra.caller_repo import CallerRepo

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class CallerCreateRequest:
    name: str
    policy_path: str
    replace: bool = False
    # Optional <consumer>/<network>/<role> join key (ADR-0001 §3). Threaded into
    # the audit row only — NOT a custody-DB column (Unit-3 narrowing: no Alembic
    # migration; capability_id persists in the policy schema, not the callers table).
    capability_id: str | None = None


@dataclass(frozen=True)
class CallerCreateResult:
    """One-time response. The `api_key` field is the only place the
    operator ever sees the plaintext.
    """

    name: str
    api_key: str  # plaintext, shown once
    api_key_prefix: str
    policy_path: str
    capability_id: str | None = None


class CallerNameTaken(Exception):  # noqa: N818
    """409 — name already exists."""


async def create_caller(
    request: CallerCreateRequest,
    repo: CallerRepo,
    *,
    audit_repo: AuditRepo,
) -> CallerCreateResult:
    """Mint a fresh caller key and persist its hash.

    D16: one audit row per call. caller=None (admin action). request_json
    carries name + policy_path + capability_id only — NEVER api_key or key_hash.
    """
    _request_json = _canonical_json(
        {
            "name": request.name,
            "policy_path": request.policy_path,
            "replace": request.replace,
            "capability_id": request.capability_id,
        }
    )
    generated = generate_api_key()
    try:
        caller = await repo.create(
            name=request.name,
            api_key_hash=generated.key_hash,
            api_key_prefix=generated.key_prefix,
            policy_path=request.policy_path,
            replace=request.replace,
        )
    except CallerExistsError as exc:
        logger.info("caller.create.exists", name=request.name)
        await audit_repo.append(
            action="caller-create",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc).__name__}: {exc}",
        )
        await audit_repo.commit()
        raise CallerNameTaken(request.name) from exc

    await audit_repo.append(
        action="caller-create",
        decision="approved",
        caller=None,
        request_json=_request_json,
        # prefix is NOT secret; NEVER the key or hash
        outcome=_canonical_json({"api_key_prefix": caller.api_key_prefix}),
    )
    logger.info(
        "caller.create.ok",
        name=caller.name,
        api_key_prefix=caller.api_key_prefix,
        policy_path=caller.policy_path,
        capability_id=request.capability_id,
    )

    return CallerCreateResult(
        name=caller.name,
        api_key=generated.key,  # plaintext — return-once contract
        api_key_prefix=caller.api_key_prefix,
        policy_path=caller.policy_path,
        capability_id=request.capability_id,
    )
