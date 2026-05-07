"""clifwd wallets — wallet management subcommands.

Phase 3b ships `create` only. `list` and `import` land in Phase 4 per
decisions.md D9.

The CLI is an HTTP client (mirrors the `clifwd health` pattern). It does
NOT instantiate Vault/SQLite directly — that would mean the daemon isn't
the single owner of state.
"""

from __future__ import annotations

import os

import httpx
import typer

app = typer.Typer(name="wallets", help="Manage fwd-custodied wallets.")


@app.command()
def create(
    name: str = typer.Option(
        ..., "--name", help="Unique wallet name (e.g. 'register-coston2-test')."
    ),
    policy: str = typer.Option(
        ..., "--policy", help="policy_path that maps to permissions in policy.yaml."
    ),
) -> None:
    """Create a fresh wallet by calling POST /v1/admin/wallets."""
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    admin = os.environ.get("FWD_ADMIN_KEY", "")
    if not admin:
        typer.echo("FWD_ADMIN_KEY env var not set", err=True)
        raise typer.Exit(code=2)
    try:
        r = httpx.post(
            f"{url}/v1/admin/wallets",
            json={"name": name, "policy_path": policy},
            headers={"Authorization": f"Bearer {admin}"},
            timeout=30.0,
        )
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if r.status_code == 201:
        body = r.json()
        typer.echo(f"created: {body['name']} @ {body['address']}")
        return
    if r.status_code == 409:
        typer.echo(f"wallet exists: {name}", err=True)
        raise typer.Exit(code=3)
    typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
    raise typer.Exit(code=1)
