"""clifwd policy — operator policy tooling.

`validate` runs the SAME checks the daemon runs at startup (load_policy +
check_consistency) WITHOUT starting the daemon, so an operator can verify a
policy.yaml edit BEFORE `docker compose up -d` recreates the container — a bad
edit is caught here instead of wedging the daemon on restart.

This is read-only: it never mutates policy.yaml (private config) or any state.
The actual checks live in app/policy_check.py (cli -> app layer boundary).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer

from fwd.app.policy_check import PolicyLoadError, consistency_errors, load_policy_schema
from fwd.settings import get_settings

app = typer.Typer(name="policy", help="Operator policy tooling (validate).")


@app.command()
def validate(
    policy: Optional[str] = typer.Option(  # noqa: B008,UP007
        None,
        "--policy",
        help="Path to policy.yaml (default: FWD_POLICY_PATH).",
    ),
    schema_only: bool = typer.Option(  # noqa: B008
        False,
        "--schema-only",
        help=(
            "Validate schema only; skip the DB+ABI consistency check. Use on a "
            "fresh host before the daemon/DB exists."
        ),
    ),
) -> None:
    """Validate a policy.yaml before deploying it.

    Schema is always checked (load_policy). Unless --schema-only, the
    daemon's full startup consistency check also runs against the live DB +
    ABI registry (callers/wallets/abis/methods/chains/wallet-bindings). Run via
    `docker exec fwd clifwd policy validate` so it sees the same DB the daemon
    will load.

    Exit: 0 = valid; 2 = invalid (schema error OR consistency error(s)).
    """
    s = get_settings()
    path = Path(policy) if policy else Path(s.fwd_policy_path)

    # 1. Schema (pure; no DB).
    try:
        pol = load_policy_schema(path)
    except PolicyLoadError as exc:
        typer.echo(f"INVALID (schema): {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(
        f"schema OK — version={pol.version} callers={len(pol.callers)} "
        f"permissions={len(pol.permissions)} "
        f"wallet_constraints={len(pol.wallet_constraints)} "
        f"fsp_permissions={len(pol.fsp_permissions)}"
    )

    if schema_only:
        typer.echo("VALID (schema-only)")
        raise typer.Exit(code=0)

    # 2. Consistency vs the live DB + ABI registry (the startup check).
    try:
        errors = asyncio.run(consistency_errors(pol, Path(s.fwd_abis_dir)))
    except Exception as exc:  # noqa: BLE001 — surface DB/registry access failures clearly
        typer.echo(
            f"could not run consistency check ({exc}); "
            "use --schema-only on a host without a daemon/DB yet",
            err=True,
        )
        raise typer.Exit(code=2) from exc

    if errors:
        for e in errors:
            typer.echo(f"  - {e}", err=True)
        typer.echo(f"INVALID — {len(errors)} consistency error(s)", err=True)
        raise typer.Exit(code=2)

    typer.echo("VALID (schema + consistency)")
