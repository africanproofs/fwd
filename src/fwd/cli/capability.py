"""clifwd capability — capability-grant tooling (ADR-0001 §3/§4).

`grant` ingests a consumer's `<consumer> spec --json` (the reference consumer is
clif) from stdin or --spec-file, **re-renders the custody diff itself** (D3), and
— default-deny, only with explicit --approve (Core #15) — instantiates the grant
by minting each capability's caller via the audited POST /v1/admin/callers,
keyed by `capability_id`.

fwd derives the fwd caller name + policy_path from each capability's role (the
canonical clif/onboard convention) because the spec carries the wallet NAME but
not the fwd caller name / policy_path. fwd does NOT write policy.yaml and does
NOT emit a bundle (Unit 4) — the minted token is return-once, as `callers
create` is today. Requires FWD_ADMIN_KEY in env (like `callers create`).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path  # noqa: TC003
from typing import Optional

import httpx
import typer

from fwd.app.capability_grant import (
    CapabilitySpecError,
    parse_spec,
    provisioning_plan,
    render_custody_diff,
)

app = typer.Typer(name="capability", help="Capability-grant tooling (ADR-0001 §3/§4).")


def _admin_headers() -> dict[str, str]:
    admin = os.environ.get("FWD_ADMIN_KEY", "")
    if not admin:
        typer.echo("FWD_ADMIN_KEY env var not set", err=True)
        raise typer.Exit(code=2)
    return {"Authorization": f"Bearer {admin}"}


@app.command()
def grant(
    spec_file: Optional[Path] = typer.Option(  # noqa: B008,UP007
        None,
        "--spec-file",
        help="Path to a `<consumer> spec --json` file. Omit to read from stdin.",
    ),
    approve: bool = typer.Option(
        False,
        "--approve",
        help="Explicit operator approval of the custody diff (Core #15). Without it: render only.",
    ),
) -> None:
    """Ingest a consumer spec, re-render the custody diff, and (with --approve) mint by capability_id.

    Default-deny: without --approve nothing is minted — the diff + provisioning
    plan are rendered for operator judgment only.

    Exit: 0 = rendered (no --approve) or all capabilities minted; 1 = one or more
    capabilities failed/were skipped; 2 = bad input / unreachable / no admin key.
    """
    if spec_file is not None:
        try:
            text = spec_file.read_text()
        except OSError as exc:
            typer.echo(f"cannot read --spec-file: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    else:
        text = sys.stdin.read()
        if not text.strip():
            typer.echo(
                "no spec given: pass --spec-file or pipe `<consumer> spec --json` to stdin",
                err=True,
            )
            raise typer.Exit(code=2)

    try:
        spec = parse_spec(text)
    except CapabilitySpecError as exc:
        typer.echo(f"INVALID spec: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    # D3: fwd re-renders the custody diff from its own decode (to stderr — the
    # operator reads it; stdout is reserved for the return-once tokens).
    typer.echo(render_custody_diff(spec), err=True)

    plan = provisioning_plan(spec)

    if not approve:
        typer.echo("review-only (default-deny). To instantiate this grant, re-run with:", err=True)
        typer.echo("  ... | clifwd capability grant --approve", err=True)
        typer.echo("planned grants (caller name <- role convention):", err=True)
        for g in plan:
            if g.caller_name is None:
                typer.echo(
                    f"  - {g.capability_id}: role '{g.role}' is outside the known "
                    f"convention — map the caller name + policy_path by hand",
                    err=True,
                )
            else:
                typer.echo(
                    f"  - {g.capability_id}: mint caller '{g.caller_name}' "
                    f"(policy_path '{g.policy_path}', token -> env {g.caller_token_env})",
                    err=True,
                )
        return

    # --approve: instantiate via the audited admin mint, keyed by capability_id.
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    headers = {**_admin_headers(), "Content-Type": "application/json"}
    failures = 0
    for g in plan:
        if g.caller_name is None or g.policy_path is None:
            typer.echo(
                f"skip {g.capability_id}: role '{g.role}' has no caller-name convention "
                "— map + mint manually with `clifwd callers create --capability-id ...`",
                err=True,
            )
            failures += 1
            continue
        try:
            r = httpx.post(
                f"{url}/v1/admin/callers",
                json={
                    "name": g.caller_name,
                    "policy_path": g.policy_path,
                    "replace": False,
                    "capability_id": g.capability_id,
                },
                headers=headers,
                timeout=30.0,
            )
        except (httpx.HTTPError, OSError) as exc:
            typer.echo(f"unreachable minting {g.capability_id}: {exc}", err=True)
            raise typer.Exit(code=2) from exc

        if r.status_code == 201:
            body = r.json()
            typer.echo(
                f"granted {g.capability_id}: caller '{g.caller_name}' "
                f"(prefix {body['api_key_prefix']}). Token (return-once) -> env {g.caller_token_env}:",
                err=True,
            )
            # The token plaintext goes to stdout as <env>=<token> for capture
            # (return-once, as `callers create` today). fwd does not persist it.
            typer.echo(f"{g.caller_token_env}={body['api_key']}")
        elif r.status_code == 409:
            typer.echo(
                f"exists {g.capability_id}: caller '{g.caller_name}' already active "
                "(its token was shown once; revoke+re-grant to rotate)",
                err=True,
            )
            failures += 1
        else:
            typer.echo(
                f"FAILED {g.capability_id}: http {r.status_code}: {r.text[:200]}",
                err=True,
            )
            failures += 1

    if failures:
        typer.echo(f"{failures} capability(ies) not minted — see above", err=True)
        raise typer.Exit(code=1)
