"""Caller-list use case (admin-only)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fwd.infra.caller_repo import Caller, CallerRepo


async def list_callers(repo: CallerRepo, *, include_revoked: bool = True) -> list[Caller]:
    """Return all callers ordered by created_at desc.

    Admin-only consumer (POST /v1/admin/callers shows recently-created;
    GET /v1/admin/callers shows everything). The Caller dataclass exposes
    api_key_hash; the api/ layer is responsible for stripping it from the
    response (NEVER return the hash to the client).
    """
    return await repo.list_all(include_revoked=include_revoked)
