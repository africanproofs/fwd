"""clifwd wallets — wallet management subcommands.

create  — HTTP client (POST /v1/admin/wallets), mirrors clifwd health.
list    — HTTP client (GET /v1/admin/wallets stub; prints not-yet message).
import  — IN-PROCESS per D12 (file-based privkey; never traverses HTTP).
          Opens AdminScopeCM from app.dependencies and calls
          app.wallet_import.import_wallet. v0.5.0a7: switched from
          SignerCM to AdminScopeCM so the wallet-import audit row is
          written on the shared AdminScope session (D16 authorship).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path  # noqa: TC003

import httpx
import typer

from fwd.app.dependencies import get_admin_scope
from fwd.app.wallet_import import (
    PrivkeyFileBadContent,
    PrivkeyFileBadMode,
    PrivkeyFileBadOwner,
    PrivkeyFileNotFound,
    ShredSourceFailed,
    WalletAddressMismatch,
    WalletImportRequest,
    WalletNameTakenImport,
    import_wallet,
)

app = typer.Typer(name="wallets", help="Manage fwd-custodied wallets.")


@app.command()
def create(
    name: str = typer.Option(
        ..., "--name", help="Unique wallet name (e.g. 'register-coston2-test')."
    ),
    policy: str = typer.Option(
        ..., "--policy", help="policy_path that maps to permissions in policy.yaml."
    ),
) -> None:
    """Create a fresh wallet by calling POST /v1/admin/wallets."""
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    admin = os.environ.get("FWD_ADMIN_KEY", "")
    if not admin:
        typer.echo("FWD_ADMIN_KEY env var not set", err=True)
        raise typer.Exit(code=2)
    try:
        r = httpx.post(
            f"{url}/v1/admin/wallets",
            json={"name": name, "policy_path": policy},
            headers={"Authorization": f"Bearer {admin}"},
            timeout=30.0,
        )
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if r.status_code == 201:
        body = r.json()
        typer.echo(f"created: {body['name']} @ {body['address']}")
        return
    if r.status_code == 409:
        typer.echo(f"wallet exists: {name}", err=True)
        raise typer.Exit(code=3)
    typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
    raise typer.Exit(code=1)


@app.command(name="list")
def list_command() -> None:
    """List all wallets fwd custodies (admin-only HTTP).

    NOTE: the caller-facing GET /v1/wallets endpoint is Phase 7+ (needs
    policy.yaml's wallet_allowlist). This is the admin-side equivalent;
    requires FWD_ADMIN_KEY in env.
    """
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    admin = os.environ.get("FWD_ADMIN_KEY", "")
    if not admin:
        typer.echo("FWD_ADMIN_KEY env var not set", err=True)
        raise typer.Exit(code=2)
    try:
        r = httpx.get(
            f"{url}/v1/admin/wallets",
            headers={"Authorization": f"Bearer {admin}"},
            timeout=10.0,
        )
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if r.status_code != 200:
        typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
        raise typer.Exit(code=1)

    body = r.json()
    if not body["wallets"]:
        typer.echo("(no wallets)", err=True)
        return

    typer.echo(f"{'name':<32}  {'address':<44}  policy_path")
    typer.echo(f"{'-' * 32}  {'-' * 44}  {'-' * 32}")
    for w in body["wallets"]:
        typer.echo(f"{w['name']:<32}  {w['address']:<44}  {w['policy_path']}")


@app.command(name="import")
def import_command(
    name: str = typer.Option(..., "--name", help="Unique wallet name."),  # noqa: B008
    policy: str = typer.Option(..., "--policy", help="policy_path."),  # noqa: B008
    privkey_file: Path = typer.Option(  # noqa: B008
        ...,
        "--privkey-file",
        help=(
            "Absolute path to a 32-byte hex-encoded privkey file "
            "(mode 0600, owner=current user)."
        ),
    ),
    expected_address: str | None = typer.Option(  # noqa: B008
        None,
        "--expected-address",
        help=("Optional EIP-55 address; reject import if derived address doesn't match."),
    ),
    shred_source: bool = typer.Option(  # noqa: B008
        False,
        "--shred-source",
        help="Run `shred -u` on the source file after successful import.",
    ),
) -> None:
    """Import a wallet from a host file (in-process per D12).

    Refusal table (D9):
      - File must exist.
      - File mode must be exactly 0600.
      - File owner must match the user running clifwd.
      - File content (after strip) must decode to exactly 32 bytes hex.
      - Wallet name must not exist.
      - --expected-address (if provided) must match the derived address.
    """
    asyncio.run(
        _run_import(
            WalletImportRequest(
                name=name,
                policy_path=policy,
                privkey_file=privkey_file.resolve(),
                expected_address=expected_address,
                shred_source=shred_source,
            )
        )
    )


async def _run_import(request: WalletImportRequest) -> None:
    """Open AdminScopeCM and call the import use case in-process.

    v0.5.0a7: switched from SignerCM to AdminScopeCM so the wallet-import
    audit row is written on the shared session (D16 authorship). CLI exit
    codes are unchanged.
    """
    cm = get_admin_scope()
    try:
        async with cm as scope:
            wallet = await import_wallet(request, scope.signer, audit_repo=scope.audit_repo)
    except PrivkeyFileNotFound as exc:
        typer.echo(f"privkey-file not found: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except PrivkeyFileBadMode as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    except PrivkeyFileBadOwner as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    except PrivkeyFileBadContent as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    except WalletNameTakenImport as exc:
        typer.echo(f"wallet '{exc}' already exists", err=True)
        raise typer.Exit(code=3) from exc
    except WalletAddressMismatch as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    except ShredSourceFailed as exc:
        typer.echo(f"warning: shred failed: {exc}", err=True)
        typer.echo("  wallet was imported successfully; manually shred the source.", err=True)
        raise typer.Exit(code=6) from exc

    typer.echo(f"imported: {wallet.name} @ {wallet.address}")


_CHAIN_NAME = {14: "flare", 19: "songbird", 114: "coston2"}


@app.command()
def balances(
    chain: int | None = typer.Option(
        None, "--chain", help="filter to one chain_id (14|19|114)."
    ),
    include_all: bool = typer.Option(
        False, "--all",
        help="include non-transacting wallets across all chains (broad scan).",
    ),
    low_water: float | None = typer.Option(
        None, "--low-water",
        help="highlight balances below N native units (e.g. 0.1).",
    ),
    output_json: bool = typer.Option(
        False, "--json", help="emit raw JSON instead of a table.",
    ),
) -> None:
    """Per-(wallet, chain) gas balance for fwd-custodied transacting wallets.

    Default: only wallets reachable from any `permissions` allowlist, on
    the chains implied by their block(s)' contracts. Requires
    FWD_ADMIN_KEY in env. v1.1.0a7.
    """
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    admin = os.environ.get("FWD_ADMIN_KEY", "")
    if not admin:
        typer.echo("FWD_ADMIN_KEY env var not set", err=True)
        raise typer.Exit(code=2)
    params: dict[str, str] = {}
    if include_all:
        params["include_all"] = "true"
    if chain is not None:
        params["chain"] = str(chain)
    try:
        r = httpx.get(
            f"{url}/v1/admin/wallets/balances",
            headers={"Authorization": f"Bearer {admin}"},
            params=params,
            timeout=30.0,
        )
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if r.status_code != 200:
        typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
        raise typer.Exit(code=1)

    body = r.json()

    if output_json:
        typer.echo(r.text)
        for w in body.get("warnings", []):
            typer.echo(f"warning: {w}", err=True)
        return

    bals = body["balances"]
    if not bals:
        typer.echo("(no transacting wallets)", err=True)
        for w in body.get("warnings", []):
            typer.echo(f"warning: {w}", err=True)
        return

    typer.echo(
        f"{'wallet':<34}  {'network':<9}  {'address':<44}  balance"
    )
    typer.echo(f"{'-' * 34}  {'-' * 9}  {'-' * 44}  {'-' * 16}")
    for e in bals:
        net = _CHAIN_NAME.get(e["chain"], str(e["chain"]))
        if e.get("error"):
            bal_col = f"(rpc error: {e['error'][:40]})"
        else:
            bal_col = e["balance_native"]
            if low_water is not None:
                try:
                    if float(e["balance_native"]) < low_water:
                        bal_col = f"{bal_col}  ⚠ low"
                except ValueError:
                    pass
        typer.echo(
            f"{e['wallet']:<34}  {net:<9}  {e['address']:<44}  {bal_col}"
        )
    for w in body.get("warnings", []):
        typer.echo(f"warning: {w}", err=True)
