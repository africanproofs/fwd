# fwd

`fwd` is a single-host, policy-gated signing daemon for Flare-provider backend
automation. It holds EVM automation keys sealed under a local `master.key`,
decodes every signing request against policy, writes a hash-chained audit log,
and returns signatures to the caller.

It does not broadcast transactions, read chain state, expose a host port, or make
outbound network connections. Callers such as `clif` broadcast from their own
egress network and report the result back to `fwd`.

## Install

`fwd` is the zero-egress **signer only**. Install it (the clif consumer is a
separate deployment — see [Start Automation](#start-automation-separate-clif-deployment)):

```sh
curl -sfL https://get.proofs.africa/fwd | sudo sh -
```

Until `get.proofs.africa` hosting is live, run the public source installer
directly:

```sh
git clone https://github.com/africanproofs/fwd.git
sudo sh fwd/install/install.sh
```

The installer builds from source, creates `/opt/fwd`, starts only `fwd` and
`litestream`, and leaves the stack inert: empty default-deny policy, zero
wallets, no signable custody. **It never clones, builds, or launches clif.**

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
tokens into clif's per-network env files at `/opt/clif` (`--clif-env-dir`), seeds
fresh wallets' nonces to 0, and prints the on-chain authorizations you perform from
the offline identity key. It **never invokes clif** — on-chain preflight and seeding
an *imported* wallet's nonce from chain truth are operator steps via the separate clif
(`clifctl run <net> preflight` / `chain nonce`). Compact by default; `--guided` for the
walk-through.

Migrating an existing provider uses the same wizard with `--import-existing`.
Stop the old claimer/submitter before `fwd` takes over those keys, or the two
systems will collide on nonces.

## Start Automation (separate clif deployment)

The automation is a **separate clif deployment** — its own compose project with
egress, joining fwd's internal callers network as an external network. fwd never
launches it. Clone clif and use its `clifctl`. `fwd onboard` writes
`FSP_AUTO_ENABLED=true` into `/opt/clif/.env.<net>` **by default** — the onboard
(and the `clifctl up <net>` bring-up) is the gate, not a flag you set by hand. So
after onboarding + on-chain authorization + funding + a manual Songbird rehearsal,
you just bring the daemon up. To keep a network idle (e.g. before you rehearse),
set `FSP_AUTO_ENABLED=false` in `/opt/clif/.env.<net>`:

```sh
# written =true by default by `fwd onboard`; set =false to keep the daemon idle
FSP_AUTO_ENABLED=true
# optional:
# UPTIME_AUTO_ENABLED=true
```

Then bring up that network's one epoch-anchored sign-and-claim daemon from the clif
deployment:

```sh
clifctl up songbird
clifctl status songbird
```

## Daily Commands

```sh
sudo fwd status
sudo fwd logs
clifwd health
clifwd audit verify
clifctl run songbird claim --type fee      # via the separate clif deployment
clifctl run songbird fsp rewards --epoch <N>
```

`clifwd` is the fwd operator CLI wrapper (runs inside the `fwd` container — the
daemon is on an internal network with no host port). `clifctl` is clif's own
lifecycle/one-shot tool in the separate clif deployment.

## What Gets Deployed

The fwd install is **fwd-only** (compose project `fwd`):

- `fwd`: FastAPI signing daemon on the internal `fwd-callers` network (`internal: true`).
- `litestream`: local SQLite replication to the `backup` volume.

No clif and no egress network live in the fwd project. The clif consumer is a
**separate deployment** (project `clif`): the `clif-epoch-<network>` daemon(s) + a
one-shot for manual ops, on their own egress bridge plus fwd's callers network as an
external network — managed by clif's `clifctl`.

The key files are operator-owned and gitignored:

- `/opt/fwd/src/config/master.key`
- `/opt/fwd/src/config/policy.yaml`
- `/opt/fwd/src/.env`
- `/opt/clif/.env.<network>` (clif's per-network env, written by onboarding)

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
