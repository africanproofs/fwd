"""clifwd nonce — nonce administration subcommands.

init — HTTP client (POST /v1/admin/nonce-init), mirrors `clifwd wallets create`.
       Seeds the next_nonce for a (wallet, chain) so it can sign without an
       on-chain transaction-count probe. Admin-authenticated (FWD_ADMIN_KEY).
"""

from __future__ import annotations

import os

import httpx
import typer

app = typer.Typer(name="nonce", help="Administer fwd nonce state.")


@app.command()
def init(
    wallet: str = typer.Option(..., "--wallet", help="Wallet name."),
    chain: int = typer.Option(
        ..., "--chain", help="Chain id (14 Flare, 19 Songbird, 114 Coston2)."
    ),
    starting_nonce: int = typer.Option(
        ..., "--starting-nonce", help="Initial next_nonce (a fresh wallet = 0)."
    ),
) -> None:
    """Seed the next_nonce for a (wallet, chain). Admin-authenticated."""
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    admin = os.environ.get("FWD_ADMIN_KEY", "")
    if not admin:
        typer.echo("FWD_ADMIN_KEY env var not set", err=True)
        raise typer.Exit(code=2)
    try:
        r = httpx.post(
            f"{url}/v1/admin/nonce-init",
            json={"wallet": wallet, "chain": chain, "starting_nonce": starting_nonce},
            headers={"Authorization": f"Bearer {admin}"},
            timeout=30.0,
        )
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(r.text)
    raise typer.Exit(code=0 if r.status_code == 201 else 1)
