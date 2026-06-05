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
from fwd.app.policy_init import PolicyInitError, generate_policy
from fwd.settings import get_settings

app = typer.Typer(name="policy", help="Operator policy tooling (validate, init).")


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


@app.command()
def init(
    networks: str = typer.Option(  # noqa: B008
        ...,
        "--networks",
        help="Comma-separated networks (flare,songbird,coston2).",
    ),
    capabilities: str = typer.Option(  # noqa: B008
        "claim,fsp",
        "--capabilities",
        help="Comma-separated: claim,fsp (default both).",
    ),
    recipient: Optional[str] = typer.Option(  # noqa: B008,UP007
        None,
        "--recipient",
        help="Claim recipient address, pinned in the claim arg-predicate (required for 'claim').",
    ),
    fsp_sender: str = typer.Option(  # noqa: B008
        "per-network",
        "--fsp-sender",
        help="FSP gas-paying sender wallet scope: per-network (fsp-sender-<net>) or shared (fsp-sender).",
    ),
    out: Optional[str] = typer.Option(  # noqa: B008,UP007
        None,
        "--out",
        help="Write to this path instead of stdout.",
    ),
    merge: bool = typer.Option(  # noqa: B008
        False,
        "--merge",
        help=(
            "Additive: union the generated network rules INTO the current policy "
            "(FWD_POLICY_PATH) instead of generating fresh — preserves networks "
            "already configured. Onboarding passes this so adding a network never "
            "removes an existing one."
        ),
    ),
) -> None:
    """Generate a correct a29-schema policy.yaml from networks + recipient.

    Emits required `chains`, `allow_unconstrained_args`, the recipient
    arg-predicate, the fsp_self_submit carve-out, and wallet_constraints (method
    signatures derived from the shipped ABIs). The output is a STARTING POINT:
    rename wallets/callers to taste, create/import each wallet + mint each caller
    token in fwd, then `clifwd policy validate` before deploy. Prints to stdout
    by default — never writes over an existing policy.yaml unless you point
    --out at one.

    Exit: 0 = generated; 2 = bad input.
    """
    s = get_settings()
    merge_into: str | None = None
    if merge:
        cur = Path(s.fwd_policy_path)
        if cur.exists():
            merge_into = cur.read_text()
    try:
        text = generate_policy(
            networks=networks.split(","),
            capabilities=capabilities.split(","),
            recipient=recipient,
            abis_dir=Path(s.fwd_abis_dir),
            networks_file=Path(s.fwd_networks_file),
            fsp_sender_mode=fsp_sender,
            merge_into=merge_into,
        )
    except PolicyInitError as exc:
        typer.echo(f"policy init failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if out:
        Path(out).write_text(text)
        typer.echo(f"wrote {out}", err=True)
    else:
        typer.echo(text)
