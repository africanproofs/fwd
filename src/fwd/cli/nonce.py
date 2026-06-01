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
    force: bool = typer.Option(
        False, "--force", help="Overwrite an existing nonce (correct a mis-seed). Audited."
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
            json={"wallet": wallet, "chain": chain, "starting_nonce": starting_nonce, "force": force},
            headers={"Authorization": f"Bearer {admin}"},
            timeout=30.0,
        )
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(r.text)
    raise typer.Exit(code=0 if r.status_code == 201 else 1)


def _admin() -> tuple[str, dict[str, str]]:
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    admin = os.environ.get("FWD_ADMIN_KEY", "")
    if not admin:
        typer.echo("FWD_ADMIN_KEY env var not set", err=True)
        raise typer.Exit(code=2)
    return url, {"Authorization": f"Bearer {admin}"}


@app.command()
def get(
    wallet: str = typer.Option(..., "--wallet", help="Wallet name."),
    chain: int = typer.Option(
        ..., "--chain", help="Chain id (14 Flare, 19 Songbird, 114 Coston2)."
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit the raw JSON body to stdout."),
) -> None:
    """Read the current next_nonce for a (wallet, chain). Admin-authenticated.

    Exit: 0 = found (body printed); 4 = absent (no row); 2 = unreachable/no key;
    1 = other HTTP error.
    """
    url, headers = _admin()
    try:
        r = httpx.get(f"{url}/v1/admin/nonce/{wallet}/{chain}", headers=headers, timeout=10.0)
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if r.status_code == 200:
        print(r.text) if json_out else typer.echo(r.text)
        raise typer.Exit(code=0)
    if r.status_code == 404:
        typer.echo(f"nonce_not_initialized: {wallet}/{chain}", err=True)
        raise typer.Exit(code=4)
    typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
    raise typer.Exit(code=1)


@app.command()
def sync(
    wallet: str = typer.Option(..., "--wallet", help="Wallet name."),
    chain: int = typer.Option(
        ..., "--chain", help="Chain id (14 Flare, 19 Songbird, 114 Coston2)."
    ),
    on_chain_count: int = typer.Option(
        ...,
        "--on-chain-count",
        help="Authoritative on-chain tx count (supplied by an egressing client).",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit the raw JSON body to stdout."),
) -> None:
    """Bounded-monotonic advance of fwd's nonce view to chain truth.

    Exit: 0 = in_sync/advanced (body printed); 4 = not initialized;
    5 = out of bounds (large jump/rewind — use `nonce init --force`);
    2 = unreachable/no key; 1 = other HTTP error.
    """
    url, headers = _admin()
    try:
        r = httpx.post(
            f"{url}/v1/admin/nonce-sync",
            json={"wallet": wallet, "chain": chain, "on_chain_count": on_chain_count},
            headers=headers,
            timeout=30.0,
        )
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if r.status_code == 200:
        print(r.text) if json_out else typer.echo(r.text)
        raise typer.Exit(code=0)
    if r.status_code == 404:
        typer.echo(f"nonce_not_initialized: {wallet}/{chain}", err=True)
        raise typer.Exit(code=4)
    if r.status_code == 409:
        typer.echo(r.text, err=True)
        raise typer.Exit(code=5)
    typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
    raise typer.Exit(code=1)
