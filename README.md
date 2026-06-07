# fwd

`fwd` is a single-host, policy-gated signing daemon for Flare-provider backend
automation. It holds EVM automation keys sealed under a local `master.key`,
decodes every signing request against policy, writes a hash-chained audit log,
and returns signatures to the caller.

It does not broadcast transactions, read chain state, expose a host port, or make
outbound network connections. Callers such as `clif` broadcast from their own
egress network and report the result back to `fwd`.

## Install

For a full FTSO reward-provider stack, install `fwd` with the optional `clif`
claim/FSP layer:

```sh
curl -sfL https://get.proofs.africa/fwd | sudo sh -s -- --with-clif
```

Until `get.proofs.africa` hosting is live, run the public source installer
directly:

```sh
git clone https://github.com/africanproofs/fwd.git
sudo sh fwd/install/install.sh --with-clif
```

The installer builds from source, creates `/opt/fwd`, starts only `fwd` and
`litestream`, and leaves the stack inert: empty default-deny policy, zero
wallets, no signable custody.

## Onboard Rewards

Reward custody is a separate opt-in step. Start with the Songbird canary, prove
it, then add Flare:

```sh
sudo fwd onboard rewards \
  --identity 0xYOUR_OFFLINE_IDENTITY_ADDRESS \
  --recipient 0xYOUR_CLAIM_RECIPIENT_ADDRESS \
  --networks songbird
```

The wizard creates or imports the reward wallets, writes the policy, mints caller
tokens into `clif` env files, reads sender nonces from chain truth through
keyless `clif`, and prints the on-chain authorizations you must perform from the
offline identity key. It is compact by default; add `--guided` for the full
walk-through.

Migrating an existing provider uses the same wizard with `--import-existing`.
Stop the old claimer/submitter before `fwd` takes over those keys, or the two
systems will collide on nonces.

## Start Automation

After onboarding, on-chain authorization, funding, and a manual Songbird
rehearsal are complete, enable automation in `/opt/fwd/clif/.env.songbird`:

```sh
FSP_AUTO_ENABLED=true
# optional:
# UPTIME_AUTO_ENABLED=true
```

Then start the one epoch-anchored sign-and-claim daemon for that network:

```sh
sudo fwd start songbird
sudo fwd status
```

`sudo fwd start songbird fsp` is accepted as a legacy form, but FSP signing and
claiming now run through the same `clif-epoch-songbird` daemon.

## Daily Commands

```sh
sudo fwd status
sudo fwd logs
clifwd health
clifwd audit verify
clif --network songbird claim --type fee
clif --network songbird fsp rewards --epoch <N>
```

`clifwd` is the operator CLI wrapper. It runs inside the `fwd` container because
the daemon is on an internal Docker network with no host port.

## What Gets Deployed

Base install:

- `fwd`: FastAPI signing daemon on the internal `fwd-callers` network.
- `litestream`: local SQLite replication to the `backup` volume.

With `--with-clif`:

- `clif` one-shot wrapper for manual reward operations.
- `clif-epoch-<network>` daemons, started only when you run `sudo fwd start <net>`.

The key files are operator-owned and gitignored:

- `/opt/fwd/src/config/master.key`
- `/opt/fwd/src/config/policy.yaml`
- `/opt/fwd/src/.env`
- `/opt/fwd/clif/.env.<network>`

Back up `master.key`, `policy.yaml`, `.env`, the clif env files, and the
Litestream `backup` volume out of band. Without the matching `master.key`, sealed
wallets in SQLite cannot be decrypted.

## Documentation

- [Full production setup](docs/production-setup.md): canonical operator runbook.
- [One-command install](docs/one-command-install.md): installer model, flags, and
  onboarding internals.
- [Restore runbook](docs/restore-runbook.md): recover a host from `master.key`,
  config, and SQLite backup state.
- [Architecture](docs/architecture.md): signing flow, policy model, API shape,
  storage, and trust boundaries.
- [Dependencies](docs/dependencies.md): host, service, and library inventory.
- [Threat model](docs/threat-model.md): attack surface and residual risks.
- [Policy example](docs/policy.example.yaml): current generated-policy shape.
- [Decision log](docs/decisions.md): append-only design rationale.
- [History](docs/history/): historical ship records and old implementation plan.
