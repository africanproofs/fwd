"""Caller-create use case.

Generates a fresh API key, stores its hash + prefix, returns the
plaintext key (which `clifwd callers create` will print ONCE).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from fwd.infra.api_key import generate_api_key
from fwd.infra.caller_repo import CallerExistsError

if TYPE_CHECKING:
    from fwd.infra.caller_repo import CallerRepo

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class CallerCreateRequest:
    name: str
    policy_path: str


@dataclass(frozen=True)
class CallerCreateResult:
    """One-time response. The `api_key` field is the only place the
    operator ever sees the plaintext.
    """

    name: str
    api_key: str  # plaintext, shown once
    api_key_prefix: str
    policy_path: str


class CallerNameTaken(Exception):  # noqa: N818
    """409 — name already exists."""


async def create_caller(request: CallerCreateRequest, repo: CallerRepo) -> CallerCreateResult:
    """Mint a fresh caller key and persist its hash."""
    generated = generate_api_key()
    try:
        caller = await repo.create(
            name=request.name,
            api_key_hash=generated.key_hash,
            api_key_prefix=generated.key_prefix,
            policy_path=request.policy_path,
        )
    except CallerExistsError as exc:
        logger.info("caller.create.exists", name=request.name)
        raise CallerNameTaken(request.name) from exc

    logger.info(
        "caller.create.ok",
        name=caller.name,
        api_key_prefix=caller.api_key_prefix,
        policy_path=caller.policy_path,
    )

    return CallerCreateResult(
        name=caller.name,
        api_key=generated.key,  # plaintext — return-once contract
        api_key_prefix=caller.api_key_prefix,
        policy_path=caller.policy_path,
    )
