"""clifwd fsp — FSP signing operator helpers (read-only).

Emits the policy.yaml stanza an operator must merge to authorize an FSP
signing caller+wallet. Does not mutate policy.yaml (private config).
"""

from __future__ import annotations

import typer

app = typer.Typer(name="fsp", help="FSP signing operator helpers.")


@app.command()
def scope(
    caller: str = typer.Option(..., "--caller", help="Caller name."),
    wallet: str = typer.Option(..., "--wallet", help="FSP signing wallet name."),
    policy_path: str = typer.Option(..., "--policy-path", help="fsp_permissions key."),
    message_types: str = typer.Option(
        "UPTIME,REWARD_DISTRIBUTION",
        "--message-types",
        help="Comma-separated permitted FSP message types.",
    ),
) -> None:
    """Print the policy.yaml callers + fsp_permissions stanza to merge.

    The wallet MUST NOT also appear in any EVM permissions wallet_allowlist
    (address-level segmentation is enforced at daemon startup).
    """
    mts = [m.strip() for m in message_types.split(",") if m.strip()]
    typer.echo("# --- merge into policy.yaml (private config) ---")
    typer.echo("callers:")
    typer.echo(f"  {caller}:")
    typer.echo(f"    policy_path: {policy_path}")
    typer.echo("fsp_permissions:")
    typer.echo(f"  {policy_path}:")
    typer.echo(f"    message_types: {mts}")
    typer.echo(f"    wallet_allowlist: [{wallet}]")
    typer.echo("    rate:")
    typer.echo("      per_hour: 50")
    typer.echo("      per_day: 500")
