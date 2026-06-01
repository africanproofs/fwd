"""clifwd callers — caller management subcommands.

HTTP-admin client (mirrors clifwd wallets create). Talks to /v1/admin/callers.
Requires FWD_ADMIN_KEY in env.
"""

from __future__ import annotations

import os
import sys

import httpx
import typer

app = typer.Typer(name="callers", help="Manage fwd callers.")


def _admin_headers() -> dict[str, str]:
    admin = os.environ.get("FWD_ADMIN_KEY", "")
    if not admin:
        typer.echo("FWD_ADMIN_KEY env var not set", err=True)
        raise typer.Exit(code=2)
    return {"Authorization": f"Bearer {admin}"}


@app.command()
def create(
    name: str = typer.Option(
        ..., "--name", help="Unique caller name (e.g. 'ftso-fee-claimer-prod')."
    ),
    policy: str = typer.Option(
        ...,
        "--policy",
        help="policy_path that maps to permissions in policy.yaml (Phase 7).",
    ),
    replace: bool = typer.Option(
        False,
        "--replace",
        help="Re-mint a REVOKED caller of the same name (rotation). Fails on an active caller.",
    ),
) -> None:
    """Create a fresh caller. Returns the API key ONCE — capture it."""
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    try:
        r = httpx.post(
            f"{url}/v1/admin/callers",
            json={"name": name, "policy_path": policy, "replace": replace},
            headers={**_admin_headers(), "Content-Type": "application/json"},
            timeout=30.0,
        )
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if r.status_code == 201:
        body = r.json()
        print("created caller:", body["name"], file=sys.stderr)
        print("policy_path:   ", body["policy_path"], file=sys.stderr)
        print("api_key_prefix:", body["api_key_prefix"], file=sys.stderr)
        print("API KEY (returned ONCE — capture now):", file=sys.stderr)
        # The actual key goes to stdout for shell capture.
        print(body["api_key"])
        return
    if r.status_code == 409:
        typer.echo(f"caller exists: {name}", err=True)
        raise typer.Exit(code=3)
    typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
    raise typer.Exit(code=1)


@app.command(name="list")
def list_command() -> None:
    """List all callers (active + revoked)."""
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    try:
        r = httpx.get(f"{url}/v1/admin/callers", headers=_admin_headers(), timeout=10.0)
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if r.status_code != 200:
        typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
        raise typer.Exit(code=1)

    body = r.json()
    if not body["callers"]:
        typer.echo("(no callers)", err=True)
        return

    typer.echo(f"{'name':<32}  {'prefix':<10}  {'policy_path':<32}  status")
    typer.echo(f"{'-'*32}  {'-'*10}  {'-'*32}  ------")
    for c in body["callers"]:
        row_status = "REVOKED" if c["revoked_at"] else "active"
        typer.echo(
            f"{c['name']:<32}  {c['api_key_prefix']:<10}  {c['policy_path']:<32}  {row_status}"
        )


@app.command()
def revoke(
    name: str = typer.Option(..., "--name", help="Caller name to revoke."),
) -> None:
    """Revoke a caller's API key. The key cannot be un-revoked."""
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    try:
        r = httpx.delete(f"{url}/v1/admin/callers/{name}", headers=_admin_headers(), timeout=10.0)
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if r.status_code == 204:
        typer.echo(f"revoked caller: {name}", err=True)
        return
    if r.status_code == 404:
        typer.echo(f"caller not found: {name}", err=True)
        raise typer.Exit(code=4)
    if r.status_code == 409:
        typer.echo(f"caller already revoked: {name}", err=True)
        raise typer.Exit(code=5)
    typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
    raise typer.Exit(code=1)
