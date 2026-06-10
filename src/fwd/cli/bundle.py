"""clifwd bundle — compose the one-shot credential handoff bundle (ADR-0001).

`bundle compose` reads capability tuples on STDIN and emits the pinned v1 bundle
JSON to STDOUT. It is the in-container composer for the HOST-side emit path:
`fwd onboard` (which runs on the host, where clif's `${CLIF_ENV_DIR}` lives —
NOT mounted into fwd, by the de-intermingle design) captures stdout and writes
it to a mode-0600 host file itself. The token VALUES travel on the stdin/stdout
capture pipe (never argv, never a log) — the same exposure as `callers create`.

stdin format: one line per capability, TAB-separated —
    capability_id<TAB>caller_token_env<TAB>caller_token<TAB>wallet_name
(`wallet_name` may be empty). Tokens are base64url-safe, so TAB-splitting is
unambiguous.
"""

from __future__ import annotations

import json
import sys

import typer

from fwd.app.bundle_emit import BundleCapability, BundleEmitError, compose_bundle

app = typer.Typer(name="bundle", help="Compose the one-shot credential handoff bundle (ADR-0001).")


@app.command()
def compose(
    network: str = typer.Option(..., "--network", help="The bundle's network (singular, ADR §4)."),
    consumer: str = typer.Option("clif", "--consumer", help="The consumer (default: clif)."),
    ttl_seconds: int = typer.Option(
        600, "--ttl-seconds", help="Bundle TTL in seconds (expires_at = now + ttl)."
    ),
) -> None:
    """Read TAB-separated capability tuples on stdin; emit the pinned v1 bundle JSON to stdout.

    Token values are never logged; the only place a value lands is the emitted
    JSON (which the caller writes to a 0600 file). Exit: 0 = composed; 2 = bad
    input / Core-#7 refusal.
    """
    caps: list[BundleCapability] = []
    for raw in sys.stdin.read().splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) != 4:
            # Report the field count only — NEVER echo the line (it carries a token).
            typer.echo(
                f"malformed tuple line: need 4 TAB-separated fields, got {len(parts)}", err=True
            )
            raise typer.Exit(code=2)
        cid, env, token, wallet = parts
        caps.append(
            BundleCapability(
                capability_id=cid,
                caller_token_env=env,
                caller_token=token,
                wallet_name=wallet or None,
            )
        )

    if not caps:
        typer.echo("no capability tuples on stdin", err=True)
        raise typer.Exit(code=2)

    try:
        bundle = compose_bundle(
            consumer=consumer,
            network=network,
            ttl_seconds=ttl_seconds,
            capabilities=caps,
        )
    except BundleEmitError as exc:
        typer.echo(f"bundle compose failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    # The composed bundle (with token values) goes to stdout for the caller to
    # capture + write 0600. NOT a log/print to a terminal in normal use.
    typer.echo(json.dumps(bundle, indent=2))
