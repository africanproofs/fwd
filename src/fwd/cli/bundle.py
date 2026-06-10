"""clifwd bundle — compose the one-shot credential handoff bundle (ADR-0001).

`bundle compose` reads stdin lines and emits the pinned v2 bundle JSON to
STDOUT. It is the in-container composer for the HOST-side emit path: `fwd
onboard` (which runs on the host, where clif's `${CLIF_ENV_DIR}` lives — NOT
mounted into fwd, by the de-intermingle design) captures stdout and writes it to
a mode-0600 host file itself. The token VALUES travel on the stdin/stdout
capture pipe (never argv, never a log) — the same exposure as `callers create`.

stdin format: TAB-separated lines, two types —
    capability_id<TAB>caller_token_env<TAB>caller_token<TAB>wallet_name   (a capability)
    CONFIG<TAB>KEY<TAB>VALUE                                              (a config entry)
(`wallet_name` may be empty). Tokens are base64url-safe and config values carry
no TAB, so TAB-splitting is unambiguous. `config` = non-secret network config
(never a token/key) the consumer writes into its own `.env` (v2 complete handoff).
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
    """Read TAB-separated stdin lines; emit the pinned v2 bundle JSON to stdout.

    Two line types (TAB-separated):
      - a capability tuple: `capability_id<TAB>caller_token_env<TAB>caller_token<TAB>wallet_name`
      - a config entry:     `CONFIG<TAB>KEY<TAB>VALUE` (non-secret network config)

    Token values are never logged; the only place a value lands is the emitted
    JSON (which the caller writes to a 0600 file). Exit: 0 = composed; 2 = bad
    input / Core-#7 refusal.
    """
    caps: list[BundleCapability] = []
    config: dict[str, str] = {}
    for raw in sys.stdin.read().splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if parts[0] == "CONFIG":
            if len(parts) != 3:
                typer.echo(
                    f"malformed CONFIG line: need CONFIG<TAB>KEY<TAB>VALUE (3 fields), "
                    f"got {len(parts)}",
                    err=True,
                )
                raise typer.Exit(code=2)
            config[parts[1]] = parts[2]
        elif len(parts) == 4:
            cid, env, token, wallet = parts
            caps.append(
                BundleCapability(
                    capability_id=cid,
                    caller_token_env=env,
                    caller_token=token,
                    wallet_name=wallet or None,
                )
            )
        else:
            # Report the field count only — NEVER echo the line (it may carry a token).
            typer.echo(
                f"malformed line: need a 4-field capability tuple or a CONFIG line, "
                f"got {len(parts)} fields",
                err=True,
            )
            raise typer.Exit(code=2)

    if not caps:
        typer.echo("no capability tuples on stdin", err=True)
        raise typer.Exit(code=2)

    try:
        bundle = compose_bundle(
            consumer=consumer,
            network=network,
            ttl_seconds=ttl_seconds,
            capabilities=caps,
            config=config,
        )
    except BundleEmitError as exc:
        typer.echo(f"bundle compose failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    # The composed bundle (with token values) goes to stdout for the caller to
    # capture + write 0600. NOT a log/print to a terminal in normal use.
    typer.echo(json.dumps(bundle, indent=2))
