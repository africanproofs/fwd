"""Caller-auth bearer middleware for /v1/sign-and-send and other
caller-facing endpoints (Phase 4+).

Per decisions.md D11: this is a SEPARATE module from api/admin_auth.py.
There is no fallback bridge: an admin token presented here returns 401
exactly as a forged token would.

The dependency name `caller_required` is intentional and stable; later
phases (per-call rate limit, per-caller policy evaluation) extend the
dependency without renaming.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from fwd.app.caller_resolution import resolve_caller
from fwd.app.dependencies import CallerRepoCM, get_caller_repo

if TYPE_CHECKING:
    from fwd.app.dependencies import Caller

logger = logging.getLogger(__name__)


async def require_caller(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    caller_repo_cm: Annotated[CallerRepoCM, Depends(get_caller_repo)] = ...,  # type: ignore[assignment]
) -> Caller:
    """Resolve the bearer token to an active Caller.

    Returns the resolved Caller (and stashes it on request.state.caller
    for downstream use). Raises 401 on any failure.

    NEVER accepts admin tokens — D11 bright line. The argon2id verify
    step requires a stored hash matching the presented key; admin tokens
    are not in the callers table and would never match.
    """
    if authorization is None or not authorization.lower().startswith("bearer "):
        logger.warning("auth.failed key_prefix=%s", "<missing>")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "missing bearer token"},
        )
    presented = authorization[len("bearer ") :].strip()

    async with caller_repo_cm as repo:
        caller = await resolve_caller(presented, repo)

    if caller is None:
        # Log only the first 8 chars of the presented key (already masked).
        key_prefix = presented[:8] if len(presented) >= 8 else presented
        logger.warning("auth.failed key_prefix=%s", key_prefix)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "invalid bearer token"},
        )

    # Stash for downstream handlers / Phase 7 audit attribution.
    request.state.caller = caller
    return caller


# Re-export as a Depends-compatible value for `dependencies=[caller_required]`.
caller_required = Depends(require_caller)
