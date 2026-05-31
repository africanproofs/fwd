"""App-layer policy validation use case (CLI-facing).

Wraps infra/policy_loader so the cli layer can validate a policy.yaml WITHOUT
importing infra directly (layer boundary: cli -> {app, domain}). Mirrors the
re-export pattern in app/wallet_import.py.

Runs the SAME checks the daemon runs at startup (load_policy +
check_consistency) so an operator can validate a policy.yaml edit before
`docker compose up -d` recreates the container.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fwd.infra.abi_registry import AbiRegistry
from fwd.infra.caller_repo import CallerRepo
from fwd.infra.db import session_scope
from fwd.infra.policy_loader import (
    PolicyLoadError,  # re-exported for cli/ (layer boundary)
    check_consistency,
    load_policy,
)
from fwd.infra.wallet_repo import WalletRepo

if TYPE_CHECKING:
    from pathlib import Path

    from fwd.domain.policy import Policy

__all__ = ["PolicyLoadError", "load_policy_schema", "consistency_errors"]


def load_policy_schema(path: Path) -> Policy:
    """Load + schema-validate policy.yaml. Raises PolicyLoadError on schema error."""
    return load_policy(path)


async def consistency_errors(policy: Policy, abis_dir: Path) -> list[str]:
    """Run the daemon's startup consistency check against the live DB + ABI registry.

    Returns the human-readable error list (empty == consistent). Mirrors
    main.py::_startup_policy_load (include_revoked=False).
    """
    registry = AbiRegistry.load(abis_dir)
    async with session_scope() as session:
        callers = await CallerRepo(session).list_all(include_revoked=False)
        wallets = await WalletRepo(session).list_all()
        return check_consistency(policy, callers, wallets, registry)
