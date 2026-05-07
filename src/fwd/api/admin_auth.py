"""Admin-key bearer auth for /v1/admin/* endpoints.

Phase 3b minimum: constant-time compare of the request's Authorization:
Bearer <token> header against the FWD_ADMIN_KEY env var. If FWD_ADMIN_KEY
is empty, ALL admin requests are refused (fail-closed).

Phase 4 will replace this with the full caller-auth machinery from
architecture.md § Caller authentication. The dependency name stays
require_admin so consumers don't churn.
"""

from __future__ import annotations

import hmac

from fastapi import Depends, Header, HTTPException, status

from fwd.settings import get_settings


def require_admin(authorization: str | None = Header(default=None)) -> None:
    expected = get_settings().fwd_admin_key
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "admin_unavailable", "message": "FWD_ADMIN_KEY not configured"},
        )
    if authorization is None or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "missing bearer token"},
        )
    presented = authorization[len("bearer ") :].strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "invalid bearer token"},
        )


# Re-export as a FastAPI Depends-compatible value so routers can write:
#     @router.post("/...", dependencies=[admin_required])
admin_required = Depends(require_admin)
