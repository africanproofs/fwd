"""clifwd wallets — wallet management subcommands.

create  — HTTP client (POST /v1/admin/wallets), mirrors clifwd health.
list    — HTTP client (GET /v1/admin/wallets stub; prints not-yet message).
import  — IN-PROCESS per D12 (file-based privkey; never traverses HTTP).
          Opens SignerCM from app.dependencies and calls
          app.wallet_import.import_wallet.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path  # noqa: TC003

import httpx
import typer

from fwd.app.dependencies import get_signer
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
    """Open SignerCM and call the import use case in-process."""
    cm = get_signer()
    try:
        async with cm as signer:
            wallet = await import_wallet(request, signer)
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
