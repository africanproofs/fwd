"""clifwd audit — walk and verify the hash-chained audit log.

In-process, read-only. No HTTP, no admin auth. Calls the app-layer walker
functions (fwd.app.audit_walk) which open their own session_scope internally.

Layer: cli (imports fwd.app.* only — must NOT import fwd.infra.*).
"""

from __future__ import annotations

import asyncio
import json

import typer

from fwd.app.audit_walk import show_row, tail_rows, verify_chain

app = typer.Typer(
    name="audit",
    help="Walk and verify the hash-chained audit log.",
    no_args_is_help=True,
)


@app.command()
def verify(
    from_seq: int | None = typer.Option(None, "--from", help="Start seq (inclusive)."),
    to_seq: int | None = typer.Option(None, "--to", help="End seq (inclusive)."),
) -> None:
    """Verify the hash chain. Exits 0 if intact, 2 if broken."""
    result = asyncio.run(verify_chain(from_seq=from_seq, to_seq=to_seq))
    if result.ok:
        typer.echo(result.detail)
        raise typer.Exit(code=0)
    else:
        typer.echo(
            f"CHAIN BROKEN at seq={result.first_break_seq}: {result.detail}",
            err=True,
        )
        raise typer.Exit(code=2)


@app.command()
def show(seq: int) -> None:
    """Show a single audit row by seq number."""
    row = asyncio.run(show_row(seq))
    if row is None:
        typer.echo(f"no audit row at seq={seq}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"seq:             {row.seq}")
    typer.echo(f"ts:              {row.ts.isoformat()}")
    typer.echo(f"caller:          {row.caller or '-'}")
    typer.echo(f"action:          {row.action}")
    typer.echo(f"decision:        {row.decision}")
    typer.echo(f"decision_reason: {row.decision_reason or '-'}")

    # Pretty-print JSON fields when parseable.
    for field_name in ("request_json", "outcome"):
        raw = getattr(row, field_name)
        if raw is None:
            typer.echo(f"{field_name:<16} -")
        else:
            try:
                parsed = json.loads(raw)
                pretty = json.dumps(parsed, indent=2)
                typer.echo(f"{field_name}:\n{pretty}")
            except json.JSONDecodeError:
                typer.echo(f"{field_name}: {raw}")

    typer.echo(f"prev_hash:       {row.prev_hash}")
    typer.echo(f"row_hash:        {row.row_hash}")
    raise typer.Exit(code=0)


@app.command()
def tail(
    n: int = typer.Option(20, "-n", "--num", help="Number of rows to show."),
) -> None:
    """Show the last N audit rows (default 20)."""
    rows = asyncio.run(tail_rows(n))
    for row in rows:
        typer.echo(
            f"{row.seq}\t{row.ts.isoformat()}\t{row.action}\t"
            f"{row.decision}\t{row.caller or '-'}"
        )
    raise typer.Exit(code=0)
