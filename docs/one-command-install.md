# One-Command Install Target

`fwd` should install with the same operational simplicity as tools such as
K3s:

```sh
curl -sfL https://get.proofs.africa/fwd | sh -
```

That command is the target operator experience. It is not a requirement to
remove Docker Compose from the runtime. The installer may use Docker and
Compose underneath; the point is that normal operators should not need to
manually copy compose files, remember `docker exec`, or understand container
volume names for day-to-day use.

## Goal

Install a complete single-host `fwd` appliance with one command, then expose a
small host-native command surface:

```sh
sudo fwd start
sudo fwd stop
sudo fwd status
sudo fwd upgrade
clifwd health
clifwd wallets list
clifwd audit verify
```

The system remains the same product: a local, single-operator signing daemon
that replaces AP backend `.env PRIVATE_KEY` usage with policy-gated HTTP
signing and audit trails.

## Installer Responsibilities

The install script should:

1. Detect OS, architecture, and required host tools.
2. Install Docker Engine and Docker Compose v2 if absent, or stop with a clear
   instruction if the host policy forbids automatic package installation.
3. Create stable host paths:

   ```text
   /opt/fwd              release files and compose bundle
   /etc/fwd              operator configuration
   /var/lib/fwd          persistent state mount root, if host paths are used
   /var/backups/fwd      local backup export point
   /var/log/fwd          installer and lifecycle logs, if needed
   ```

4. Fetch a release-pinned `docker-compose.yml` and companion files.
5. Pull release-pinned images.
6. Write an initial `/etc/fwd/fwd.env` from a template, preserving existing
   operator values on re-run.
7. Install a host `fwd` lifecycle wrapper.
8. Install a host `clifwd` wrapper.
9. Start or stage the Compose stack according to the selected mode.
10. Print the next required operator action and refuse to imply production
    custody is complete before it is.

## Host Command Contract

### `fwd`

`fwd` is the host lifecycle wrapper. It owns appliance operations:

```sh
sudo fwd install
sudo fwd start
sudo fwd stop
sudo fwd restart
sudo fwd status
sudo fwd logs
sudo fwd upgrade
sudo fwd backup status
sudo fwd custody init
```

The wrapper may call `docker compose` internally, but Compose should be an
implementation detail for normal operation.

### `clifwd`

`clifwd` remains the application CLI. The host-installed `clifwd` should
delegate into the running `fwd` container by default:

```sh
#!/bin/sh
exec docker exec fwd clifwd "$@"
```

This keeps the CLI pointed at the same Python package, environment, mounted
state, policy files, and custody backend as the daemon. It also removes the
need for operators to type:

```sh
docker exec fwd clifwd ...
```

Normal usage becomes:

```sh
clifwd health
clifwd wallets create --name ftso-claim-flare-prod --policy ftso-claim-flare-prod
clifwd wallets import --name old-wallet --policy legacy --privkey-file /tmp/key.hex
clifwd callers create --name ftso-fee-claimer --policy ftso-claim-flare-prod
clifwd audit verify
```

For file-based operations such as `wallets import`, the wrapper must make the
container path rule explicit: `--privkey-file` is evaluated inside the
container unless the wrapper grows a deliberate `--host-file` helper. A helper
may safely copy a host file into a `0600` temporary file inside the container,
run the import, then shred the container copy.

## Custody Gate

The installer must not silently create production custody.

It may stage the runtime, create config templates, and start services, but it
must stop before production private keys are generated or imported until the
operator runs an explicit custody command:

```sh
sudo fwd custody init
```

That command should walk the operator through the selected custody backend,
backup expectations, share or master-key handling, and the first wallet
creation or import. If Vault is the selected backend, this is where the
production wipe-and-redo, unseal-share distribution, and audit-device check
belong. If a sealed-master backend is selected in a later release, this command
owns that initialization instead.

This boundary matters because installing software is reversible; initializing
custody is a security event.

## Release And Pinning

The install URL should resolve to a small script. That script should fetch a
versioned manifest, not blindly track whatever happens to be on `main`.

Minimum manifest fields:

```yaml
version: 1.0.0
compose_url: https://get.proofs.africa/fwd/releases/1.0.0/docker-compose.yml
compose_sha256: <hex>
images:
  fwd: registry.gitlab.com/proofs.africa/fwd/fwd:1.0.0
  vault: hashicorp/vault:1.18.2
  litestream: litestream/litestream:0.3.13
```

The installer should verify checksums for downloaded scripts and static
artifacts. Image digests should be preferred once the release process supports
them.

## Modes

### Development Mode

Development mode may use relaxed custody setup and local-only defaults. It is
for test keys and live Coston2 drills only.

```sh
curl -sfL https://get.proofs.africa/fwd | sh -s -- --dev
```

### Production Mode

Production mode must be conservative:

```sh
curl -sfL https://get.proofs.africa/fwd | sh -s -- --production
```

Production mode should require an explicit custody initialization step before
the first production wallet can exist. It should also refuse known-unsafe
states, such as a dev custody file being reused for production.

## Upgrade Behavior

`sudo fwd upgrade` should:

1. Read the current installed version.
2. Fetch the selected target manifest.
3. Pull new images.
4. Stop the stack only after downloads succeed.
5. Preserve `/etc/fwd` and persistent state.
6. Run database migrations through the `fwd` container entrypoint.
7. Start the stack.
8. Run `clifwd health`.
9. Print rollback instructions if health fails.

No upgrade command should overwrite operator policy or secrets.

## Backup And Restore Integration

The installer should not replace the existing restore runbook. It should make
the common paths predictable so the runbook is easier to execute.

Expected commands:

```sh
sudo fwd backup status
sudo fwd backup export /path/to/off-host/media
sudo fwd restore prepare
```

Off-host transport remains the operator's responsibility unless a later phase
explicitly adds a transport tool.

## Non-Goals

The one-command installer is not:

- a public hosted service;
- a Kubernetes migration;
- a reason to expose `fwd` on the public internet;
- a replacement for custody initialization;
- a place to paste private keys;
- a new policy engine;
- a new backup transport system.

## Acceptance Checklist

The installer is good enough when a fresh supported host can run:

```sh
curl -sfL https://get.proofs.africa/fwd | sh -
sudo fwd status
clifwd health
```

and get a clear, working, non-production-ready stack with a precise next step:

```text
fwd is installed.
Runtime is healthy.
Production custody is not initialized.
Next: sudo fwd custody init
```

For production readiness, the full gate is:

1. `sudo fwd custody init` completes.
2. `clifwd health` reports healthy service and custody backend.
3. `clifwd audit verify` succeeds.
4. A wallet can be created or imported without leaking private key material to
   HTTP, shell history, logs, or audit rows.
5. The first Phase 8 caller can be issued a policy-bound API key.

## Phase Placement

This is operator UX work for the first production era. It should not block the
custody or policy correctness gates, but it should be treated as part of making
Phase 8 repeatable by a human operator who should not need to memorize Docker
internals.

