"""Admin-key bearer auth for /v1/admin/* endpoints.

Phase 3b minimum (still in force at v0.4.0a2): constant-time compare of
the request's Authorization: Bearer <token> header against the
FWD_ADMIN_KEY env var. If FWD_ADMIN_KEY is empty, ALL admin requests are
refused (fail-closed).

Per decisions.md D11 (Phase 4): admin auth and caller auth are distinct,
never bridged. Phase 4 ADDED `api/caller_auth.py::require_caller` as a
SEPARATE module for caller-facing endpoints (/v1/sign-and-send and
future caller endpoints); it did NOT replace `require_admin`. Both
modules continue to exist; admin endpoints (/v1/admin/*) keep using
`require_admin`. There is no fallback path between the two — an admin
token presented to a caller endpoint returns 401, and vice versa. The
canonical D11 attestation lives in
`tests/unit/test_admin_caller_bright_line.py`.

Closes v0.4.0a1 audit F5.2 (the prior comment incorrectly said Phase 4
would replace this module).
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
