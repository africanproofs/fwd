"""clifwd capability — capability grant + read tooling (ADR-0001 §3/§4/§6).

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

`list` is the read-only doctor 'fwd=granted' leg: the capability_ids the LIVE
POLICY governs, joined with each caller's status (admin-gated GET
/v1/admin/capabilities; `--json` for the coordinator scrape). NEVER a token/hash.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path  # noqa: TC003
from typing import Optional

import httpx
import typer

from fwd.app.bundle_emit import (
    BundleCapability,
    BundleEmitError,
    compose_bundle,
    write_bundle,
)
from fwd.app.capability_grant import (
    CapabilitySpecError,
    parse_spec,
    provisioning_plan,
    render_custody_diff,
)

app = typer.Typer(name="capability", help="Capability grant + read tooling (ADR-0001 §3/§4/§6).")


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
    replace: bool = typer.Option(
        False,
        "--replace",
        help="Re-mint a REVOKED caller of the same name (rotation). Pairs with --emit-bundle.",
    ),
    emit_bundle: Optional[Path] = typer.Option(  # noqa: B008,UP007
        None,
        "--emit-bundle",
        help=(
            "Write the minted tokens + --config entries into a 0600 COMPLETE v2 bundle at this "
            "path instead of stdout. NOTE: this CLI runs in-container, so the path is "
            "container-relative — point it at a host-visible mount, or use `fwd onboard` for the "
            "host-side bundle next to clif's .env."
        ),
    ),
    ttl_seconds: int = typer.Option(
        600, "--ttl-seconds", help="Bundle TTL in seconds (only with --emit-bundle)."
    ),
    config: list[str] = typer.Option(  # noqa: B008
        [],
        "--config",
        help=(
            "Repeatable KEY=VALUE config entry for the v2 bundle's `config` section "
            "(non-secret consumer env — MUST include NETWORK; only with --emit-bundle). "
            "Example: --config NETWORK=songbird --config FWD_ENDPOINT=http://fwd:8080"
        ),
    ),
) -> None:
    """Ingest a consumer spec, re-render the custody diff, and (with --approve) mint by capability_id.

    Default-deny: without --approve nothing is minted — the diff + provisioning
    plan are rendered for operator judgment only. With --emit-bundle, minted token
    VALUES go to a 0600 bundle file (never stdout); fail-closed (no partial bundle).

    Exit: 0 = rendered (no --approve) or all capabilities minted; 1 = one or more
    capabilities failed/were skipped; 2 = bad input / unreachable / no admin key.
    """
    # Parse --config KEY=VALUE entries into the v2 bundle config dict. Each item
    # MUST contain '=' with a non-empty key; a repeated key is last-one-wins. No
    # secret/character validation here — compose_bundle applies the Core-#7 guard.
    cfg: dict[str, str] = {}
    for item in config:
        key, sep, value = item.partition("=")
        if not sep or not key:
            typer.echo(
                f"malformed --config entry {item!r}: expected KEY=VALUE with a non-empty key",
                err=True,
            )
            raise typer.Exit(code=2)
        cfg[key] = value

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

    # PRE-MINT conformance gate. Minted tokens are return-once — fwd retains no
    # plaintext, so a post-mint refusal would strand fresh tokens and force a
    # rotation. Refuse a non-conformant --emit-bundle request BEFORE any mint.
    if emit_bundle is not None:
        for g in plan:
            if not g.wallet_name:
                typer.echo(
                    f"refusing --emit-bundle: capability {g.capability_id} has no configured "
                    "wallet (spec shows configured:false) — configure the wallet first; a v2 "
                    "bundle with a null wallet_name is rejected by the importer",
                    err=True,
                )
                raise typer.Exit(code=2)
        if "NETWORK" not in cfg:
            typer.echo(
                f"refusing --emit-bundle: --config NETWORK={spec.network} is required "
                "(consumer-contract-v1 §4: the v2 config MUST carry the consumer's network "
                "selector; without it the consumer silently defaults to flare)",
                err=True,
            )
            raise typer.Exit(code=2)
        if cfg["NETWORK"] != spec.network:
            typer.echo(
                f"refusing --emit-bundle: --config NETWORK={cfg['NETWORK']} contradicts the "
                f"spec's network {spec.network}",
                err=True,
            )
            raise typer.Exit(code=2)

    # --approve: instantiate via the audited admin mint, keyed by capability_id.
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    headers = {**_admin_headers(), "Content-Type": "application/json"}
    failures = 0
    minted: list[BundleCapability] = []
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
                    "replace": replace,
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
            if emit_bundle is not None:
                # Token VALUE goes to the 0600 bundle, NEVER stdout.
                minted.append(
                    BundleCapability(
                        capability_id=g.capability_id,
                        caller_token_env=g.caller_token_env,
                        caller_token=body["api_key"],
                        wallet_name=g.wallet_name,
                    )
                )
                typer.echo(
                    f"granted {g.capability_id}: caller '{g.caller_name}' "
                    f"(prefix {body['api_key_prefix']}) -> bundle (env {g.caller_token_env})",
                    err=True,
                )
            else:
                typer.echo(
                    f"granted {g.capability_id}: caller '{g.caller_name}' "
                    f"(prefix {body['api_key_prefix']}). Token (return-once) -> env "
                    f"{g.caller_token_env}:",
                    err=True,
                )
                # The token plaintext goes to stdout as <env>=<token> for capture
                # (return-once, as `callers create` today). fwd does not persist it.
                typer.echo(f"{g.caller_token_env}={body['api_key']}")
        elif r.status_code == 409:
            typer.echo(
                f"exists {g.capability_id}: caller '{g.caller_name}' already active "
                "(its token was shown once; revoke+re-grant, or --replace to rotate)",
                err=True,
            )
            failures += 1
        else:
            typer.echo(
                f"FAILED {g.capability_id}: http {r.status_code}: {r.text[:200]}",
                err=True,
            )
            failures += 1

    # --emit-bundle: fail-closed — only write a COMPLETE bundle (every planned
    # capability minted), never a partial one that would leave clif short a token.
    if emit_bundle is not None and not failures:
        try:
            bundle = compose_bundle(
                consumer=spec.consumer,
                network=spec.network,
                ttl_seconds=ttl_seconds,
                capabilities=minted,
                config=cfg,
            )
            write_bundle(bundle, emit_bundle)
        except (BundleEmitError, OSError) as exc:
            typer.echo(f"bundle emit failed: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        typer.echo(
            f"bundle written 0600 to {emit_bundle} "
            f"({len(minted)} capabilities: {', '.join(c.capability_id for c in minted)})",
            err=True,
        )
    elif emit_bundle is not None and failures:
        typer.echo(
            "bundle NOT written: not every capability minted (fail-closed — no partial bundle)",
            err=True,
        )

    if failures:
        typer.echo(f"{failures} capability(ies) not minted — see above", err=True)
        raise typer.Exit(code=1)


@app.command(name="list")
def list_command(
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Emit the raw /v1/admin/capabilities JSON instead of the human table.",
    ),
) -> None:
    """List the capability_ids the live policy governs, joined with caller status.

    The read-only doctor 'fwd=granted' leg — derived from the LIVE POLICY (so a
    hand-edited ungoverned grant is detectable), sorted by capability_id,
    admin-gated. NEVER a token value or hash. Exit: 0 ok; 1 http error; 2 no
    admin key / unreachable.
    """
    url = os.environ.get("FWD_URL", "http://127.0.0.1:8080")
    try:
        r = httpx.get(f"{url}/v1/admin/capabilities", headers=_admin_headers(), timeout=10.0)
    except (httpx.HTTPError, OSError) as exc:
        typer.echo(f"unreachable: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if r.status_code != 200:
        typer.echo(f"http {r.status_code}: {r.text[:200]}", err=True)
        raise typer.Exit(code=1)

    if json_out:
        # The /v1/admin/capabilities response is already JSON and carries NO
        # token/hash (GrantedCapabilitySummary) — emit it raw.
        typer.echo(r.text)
        return

    body = r.json()
    if not body["capabilities"]:
        typer.echo("(no granted capabilities)", err=True)
        return

    typer.echo(f"{'capability_id':<32}  {'caller':<24}  {'policy_path':<24}  status")
    typer.echo(f"{'-' * 32}  {'-' * 24}  {'-' * 24}  ------")
    for c in body["capabilities"]:
        typer.echo(
            f"{c['capability_id']:<32}  {c['caller_name']:<24}  "
            f"{c['policy_path']:<24}  {c['status']}"
        )
