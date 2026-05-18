"""clifwd — Flare Wallet Daemon CLI (pronounced 'Clifford').

v0.4.0-alpha (Phase 4): adds `callers` and `wallets import|list`.
"""

from __future__ import annotations

import os

import httpx
import typer

from fwd.cli.audit import app as audit_app
from fwd.cli.callers import app as callers_app
from fwd.cli.master import app as master_app
from fwd.cli.wallets import app as wallets_app
from fwd.version import __version__

app = typer.Typer(
    name="clifwd",
    help="fwd — Flare Wallet Daemon CLI (pronounced 'Clifford').",
    no_args_is_help=True,
)

app.add_typer(wallets_app, name="wallets")
app.add_typer(callers_app, name="callers")
app.add_typer(audit_app, name="audit")
app.add_typer(master_app, name="master")


@app.command()
def version() -> None:
    """Print fwd's version."""
    typer.echo(__version__)


@app.command()
def health() -> None:
    """Probe fwd's /healthz endpoint and print the JSON status.

    Honors the FWD_URL env var (default: http://127.0.0.1:8080).
    """
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    try:
        r = httpx.get(f"{url}/healthz", timeout=5.0)
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(r.text)
    raise typer.Exit(code=0 if r.status_code == 200 else 1)


if __name__ == "__main__":
    app()
