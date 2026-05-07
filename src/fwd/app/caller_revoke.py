"""Caller-revoke use case."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from fwd.infra.caller_repo import CallerAlreadyRevokedError, CallerNotFoundError

if TYPE_CHECKING:
    from fwd.infra.caller_repo import CallerRepo

logger = structlog.get_logger(__name__)


class CallerNotFound(Exception):  # noqa: N818
    """404 — caller name doesn't exist."""


class CallerAlreadyRevoked(Exception):  # noqa: N818
    """409 — caller is already revoked."""


async def revoke_caller(name: str, repo: CallerRepo) -> None:
    try:
        await repo.revoke(name)
    except CallerNotFoundError as exc:
        logger.info("caller.revoke.not_found", name=name)
        raise CallerNotFound(name) from exc
    except CallerAlreadyRevokedError as exc:
        logger.info("caller.revoke.already_revoked", name=name)
        raise CallerAlreadyRevoked(name) from exc
    logger.info("caller.revoke.ok", name=name)
