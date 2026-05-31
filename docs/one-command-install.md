# One-command install — the FTSO provider stack

`fwd` (and, optionally, the `clif` claim/FSP layer) should install with the same
operational simplicity as tools such as K3s:

```sh
curl -sfL https://get.proofs.africa/fwd | sh -            # fwd custody daemon
curl -sfL https://get.proofs.africa/fwd | sh -s -- --with-clif   # + clif layer
```

This is the **target operator experience** for any Flare FTSO provider running
their own stack (not just AP). It does not remove Docker Compose from the
runtime — the installer uses Compose underneath; the point is that a normal
operator should not have to copy compose files, remember `docker exec`, or learn
container volume names for day-to-day use.

## Positioning

A **single-host installation is a fully-functional FTSO provider signing
stack** — `fwd` (the policy-gated custody/signing daemon), optionally `clif`
(keyless reward-claiming + FSP signing), and all the sealed-key custody, nonce,
and hash-chained audit state needed to operate. It is **not necessary — and by
design not possible — to add more signer nodes**: `fwd` is a *coherence
boundary, not a scaling unit* (one container, one wallet set, one nonce manager
per (wallet, chain) — Core invariant #9). Signing is low-rate, so capacity is
never the constraint; resilience is **restore-from-backup** (the local
Litestream replica + regenerate-key-and-re-authorize-on-chain), not failover or
clustering.

## Two layers, one hard custody gate

Mirroring K3s for the *software*, with an explicit gate for the
*secrets/authorization* — which, unlike a stateless K3s node, cannot be safely
defaulted for a signer:

1. **Software install (reversible).** `curl … | sh -` brings the stack up
   **inert**: an empty default-deny policy, zero wallets, healthy. The worst case
   of running the installer is a daemon that can sign **nothing** — that is the
   safety property that makes `curl | sh` acceptable for a custody tool.
2. **Custody init (a security event).** The installer **stops** before any key
   or on-chain authorization. The operator then runs the gated onboarding
   (below). *Installing software is reversible; initializing custody is not.*

## Install unit — fwd core, `--with-clif` opt-in

The base unit is **fwd** (the reusable signer): its own `internal: true`
network, no egress, no host port. `--with-clif` layers a Compose overlay
(`docker-compose.clif.yml`) adding the `clif` claim/FSP daemons, dual-homed to
fwd's `fwd-callers` network plus an `egress` bridge for their own RPC/broadcast.
fwd stands alone; clif is opt-in.

## Image delivery — build from source on the host

The installer fetches **pinned source** (a release tag + commit sha) and
`docker compose build`s locally. There is **no dependency on a published image
registry** and **no trust in a prebuilt binary** for a custody tool — the
operator builds from auditable, pinned source. The host needs `docker`,
`docker compose v2`, and `git`; the language/build toolchain stays inside the
Docker multi-stage build. First install is slower (a source build); that is the
accepted trade for the zero-trust posture.

## Installer responsibilities

The install script should:

1. Detect OS, architecture, and required host tools (`docker`,
   `docker compose v2`, `git`); stop with a clear instruction if a tool is
   missing and host policy forbids auto-install.
2. Resolve the target version from a pinned manifest (never blindly track
   `main`); honor `FWD_VERSION` / `--channel`.
3. Create stable host paths (operator-overridable via `FWD_DIR`):
   ```text
   /opt/fwd          release files + compose bundle + fetched source
   /etc/fwd          operator configuration (.env, mounted policy.yaml)
   /var/lib/fwd      persistent state mount root (if host paths are used)
   /var/backups/fwd  local backup export point
   ```
4. Fetch + checksum-verify the pinned source (fwd; clif too under `--with-clif`).
5. `docker compose build` from that source.
6. Generate the sealed master **locally** (`clifwd master generate`, mode 0600,
   owned by the `fwd` uid) — it is **never fetched or transmitted**.
7. Generate a strong `FWD_ADMIN_KEY` into `/etc/fwd/fwd.env` (preserving
   existing operator values on re-run).
8. Install the host `fwd` lifecycle wrapper and the `clifwd` CLI wrapper.
9. Start the stack **inert** (empty default-deny policy, zero wallets); under
   `--with-clif`, build clif but leave its daemons stopped until onboarding
   completes.
10. Run `clifwd health`, then print the next required operator action — and
    refuse to imply production custody is complete before it is.

## Host command contract

### `fwd` (lifecycle wrapper)
```sh
sudo fwd start | stop | restart | status | logs | upgrade
sudo fwd backup status
```
Compose is an implementation detail of these.

### `clifwd` (application CLI, delegates into the container)
```sh
#!/bin/sh
exec docker exec fwd clifwd "$@"
```
So normal usage is `clifwd health` / `clifwd policy validate` / `clifwd wallets
import …` / `clifwd audit verify` — same Python package, env, mounted state,
policy, and custody backend as the daemon. For file-based ops (`wallets import`),
the wrapper must make explicit that `--privkey-file` is evaluated **inside** the
container.

## Custody init + phased onboarding (the gate)

The installer stages the runtime but stops before keys/authorization. Onboarding
is **phased**:

**Now — runbook + tooling (operator-driven, validated at each step):**
1. `clifwd master generate` — done by the installer (the sealed master).
2. `clifwd policy init --networks … --recipient … [--capabilities claim,fsp]`
   → generate a correct a29-schema `policy.yaml` (chains, the non-scalar-arg
   opt-in, the recipient pin, the FSP `fsp_self_submit` carve-out,
   wallet_constraints). Rename wallets/callers to taste.
3. `clifwd wallets create|import …` — generate or import the executor / FSP
   signing-policy / sender keys (key material handled only here, by the
   operator).
4. `clifwd callers create …` — mint the caller token(s); inject into clif's env.
5. `clifwd policy validate` — the gate: must pass before recreate.
6. `clifwd nonce init …` — seed each sender wallet's nonce (fwd is zero-egress).
7. **On-chain, from the operator's OFFLINE identity key** (fwd never custodies
   it): `ClaimSetupManager.setClaimExecutors` to authorize the executor wallet,
   `setAllowedClaimRecipient`, and FSP signing-policy registration.
8. Rehearse on Coston2, then go live.

**Later — `sudo fwd custody init` wizard** wraps steps 2–7 interactively and
prints the exact on-chain commands; deferred to a later phase.

## Release & pinning

The install URL resolves to a small, auditable POSIX script pinned to a release
tag (the vanity URL only redirects to the in-repo `install/install.sh` at that
tag). It fetches a versioned manifest — **source refs + checksums, not image
digests** (build-from-source):

```yaml
version: 1.1.0
fwd_source: { repo: https://gitlab.com/proofs.africa/fwd.git, tag: v1.1.0, sha: <hex> }
clif_source: { repo: <public clif url>, tag: v0.5.x, sha: <hex> }   # --with-clif
compose_sha256: <hex>
networks_sha256: <hex>
```

The installer verifies every fetched artifact's checksum.

## Modes

- **Dev / Coston2** — `… | sh -s -- --dev`: relaxed defaults for test keys and
  live Coston2 rehearsal only.
- **Production** — `… | sh -s -- --production`: conservative; requires explicit
  custody init before the first production wallet, and refuses known-unsafe
  states (e.g. a dev master reused for production).

## Upgrade

`sudo fwd upgrade`: read current version → fetch target manifest → fetch + build
new source → stop only after the build succeeds → preserve `/etc/fwd` + state →
run migrations via the container entrypoint → start → `clifwd health` → print
rollback steps on failure. **Never** overwrites operator policy or secrets.

## Security model of `curl | sh` for a custody tool

- TLS, and the script pinned to an **immutable release tag**, published and
  **auditable in the public repo** (the vanity URL only redirects).
- **Checksums** on every fetched artifact; build from pinned source.
- The installer **never fetches or handles key material** — the master is
  generated locally; provider keys are imported only at the post-gate step.
- **Default-deny inert bring-up** — nothing is signable until the operator
  authors policy and imports keys.
- Inspect-first is documented: `curl -o install.sh <url>; less install.sh; sh install.sh`.

## Non-goals

The installer is **not**: a public hosted service; a Kubernetes migration; a
reason to expose `fwd` on the public internet; a multi-tenant key host (Core
invariant #9 — one operator, one host); a replacement for custody init; a place
to paste private keys; a published-image pipeline (build-from-source by choice).

## Acceptance checklist

A fresh supported host can run:
```sh
curl -sfL https://get.proofs.africa/fwd | sh -
sudo fwd status        # healthy
clifwd health          # master=ok
```
and get a clear, working, **non-production-ready** stack with a precise next step:
```text
fwd is installed. Runtime is healthy.
Production custody is not initialized.
Next: clifwd policy init … → wallets import … → policy validate → on-chain authorize.
```
Production readiness gate: custody init complete; `clifwd health` healthy;
`clifwd audit verify` succeeds; a wallet imported without leaking key material to
HTTP/shell-history/logs/audit; the first caller issued a policy-bound token;
`clifwd policy validate` green.
