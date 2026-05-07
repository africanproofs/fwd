"""Caller-resolution use case.

Given a presented bearer token, return the matching active Caller or
None. Used by api/caller_auth.py::require_caller. Argon2id verifies
each prefix-matching row until a match (or all exhausted).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from fwd.infra.api_key import extract_prefix, verify_api_key

if TYPE_CHECKING:
    from fwd.infra.caller_repo import Caller, CallerRepo

logger = structlog.get_logger(__name__)


async def resolve_caller(presented_key: str, repo: CallerRepo) -> Caller | None:
    """Resolve a bearer token to a Caller.

    Returns None if:
      - The token doesn't have the `fwd_live_<43chars>` shape.
      - No active caller matches the prefix.
      - All prefix-matching callers fail argon2id verification.

    Logs prefix on failure for ops debugging (not the full key).
    """
    prefix = extract_prefix(presented_key)
    if prefix is None:
        logger.info("caller.resolve.bad_shape")
        return None

    candidates = await repo.list_by_prefix_active(prefix)
    if not candidates:
        logger.info("caller.resolve.no_match", api_key_prefix=prefix)
        return None

    for candidate in candidates:
        if verify_api_key(presented_key, candidate.api_key_hash):
            logger.info("caller.resolve.ok", name=candidate.name, api_key_prefix=prefix)
            return candidate

    logger.info(
        "caller.resolve.argon2_mismatch",
        api_key_prefix=prefix,
        candidates=len(candidates),
    )
    return None
