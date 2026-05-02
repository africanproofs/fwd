"""clifwd — Flare Wallet Daemon CLI.

Phase 2: only `version` and `health`. Phase 4 adds `callers` and `wallets`
subcommands per decisions.md D9.
"""

from __future__ import annotations

import os

import httpx
import typer

from fwd.version import __version__

app = typer.Typer(
    name="clifwd",
    help="fwd — Flare Wallet Daemon CLI (pronounced 'Clifford').",
    no_args_is_help=True,
)


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
