"""Caller-revoke use case.

v0.5.0a7 adds the hash-chained audit-log row (D16): one row per call
(success or known-failure) on the shared AdminScope session.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from fwd.infra.audit_repo import _canonical_json
from fwd.infra.caller_repo import CallerAlreadyRevokedError, CallerNotFoundError

if TYPE_CHECKING:
    from fwd.infra.audit_repo import AuditRepo
    from fwd.infra.caller_repo import CallerRepo

logger = structlog.get_logger(__name__)


class CallerNotFound(Exception):  # noqa: N818
    """404 — caller name doesn't exist."""


class CallerAlreadyRevoked(Exception):  # noqa: N818
    """409 — caller is already revoked."""


async def revoke_caller(name: str, repo: CallerRepo, *, audit_repo: AuditRepo) -> None:
    """Revoke a caller by name.

    D16: one audit row per call. caller=None (admin action). request_json
    carries the caller name only — no secrets.
    """
    _request_json = _canonical_json({"name": name})
    try:
        await repo.revoke(name)
    except CallerNotFoundError as exc:
        logger.info("caller.revoke.not_found", name=name)
        await audit_repo.append(
            action="caller-revoke",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc).__name__}: {exc}",
        )
        await audit_repo.commit()
        raise CallerNotFound(name) from exc
    except CallerAlreadyRevokedError as exc:
        logger.info("caller.revoke.already_revoked", name=name)
        await audit_repo.append(
            action="caller-revoke",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc).__name__}: {exc}",
        )
        await audit_repo.commit()
        raise CallerAlreadyRevoked(name) from exc

    await audit_repo.append(
        action="caller-revoke",
        decision="approved",
        caller=None,
        request_json=_request_json,
    )
    logger.info("caller.revoke.ok", name=name)
