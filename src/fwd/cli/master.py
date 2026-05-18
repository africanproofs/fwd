"""clifwd master — sealed master key management subcommands.

generate  — Write a fresh 32-byte random master key to a 0600 host file.
            Must be run once before fwd starts; the file is bind-mounted
            read-only into the container at /run/fwd/master.key.
"""

from __future__ import annotations

import os

import typer

app = typer.Typer(name="master", help="Manage the fwd sealed master key.")


@app.command()
def generate(
    out: str = typer.Option(
        ...,
        "--out",
        help="Destination path for the 32-byte master key file (e.g. ./config/master.key).",
    ),
) -> None:
    """Generate a fresh 32-byte master key and write it to OUT (mode 0600).

    Refuses to overwrite an existing file (exit code 2).
    """
    if os.path.exists(out):
        typer.echo(f"refusing to overwrite existing file: {out}", err=True)
        raise typer.Exit(code=2)

    key = os.urandom(32)
    with open(out, "wb") as f:
        f.write(key)
    os.chmod(out, 0o600)
    typer.echo(f"wrote 32-byte master key to {out} (mode 0600)")
