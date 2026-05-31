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

The installer git-clones **pinned source** (a release tag + commit sha) from the
public repository — `github.com/africanproofs/fwd` (and, under `--with-clif`,
`github.com/africanproofs/clif`) — and `docker compose build`s locally. There is
**no dependency on a published image registry** and **no trust in a prebuilt
binary** for a custody tool — the operator builds from auditable, pinned source.
The host needs `docker`, `docker compose v2`, and `git`; the language/build
toolchain stays inside the Docker multi-stage build. First install is slower (a
source build); that is the accepted trade for the zero-trust posture.

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
sudo fwd onboard rewards --recipient 0xADDR [--networks coston2]
```
Compose is an implementation detail of these. `onboard` is the one-command reward
custody setup (see below).

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

## Reward onboarding — the default claim + FSP policy (the custody gate)

The installer stages the runtime but stops before keys and on-chain authorization
— that is your custody event, not the installer's. fwd boots **inert**: empty
default-deny policy, zero wallets, signs nothing.

You do **not** have to learn the policy schema. fwd ships a **default reward
policy** covering the two revenue operations — claiming FTSO rewards
(`RewardManager.claim`) and signing FSP rewards (`signUptimeVote` /
`signRewards`) — with deterministic wallet + caller names.

### The one command

```sh
sudo fwd onboard rewards --recipient 0xYOUR_CLAIM_RECIPIENT_ADDRESS --networks coston2
```

`fwd onboard rewards` runs the whole sequence — generate the default policy,
validate it, load it (restart), create the fwd-generated wallets, mint the caller
tokens (printed once), seed the sender nonces — and prints the two operator-only
**GATES** (your FSP signing-key import + the on-chain authorization). It is
**idempotent**: re-running skips anything already created and skips the restart
if the policy hasn't changed. Flags: `--claim-only` / `--fsp-only`,
`--skip-fsp-import` (defer the FSP key), and a comma list for `--networks`. For
mainnet, use `--networks flare` / `--networks songbird` (the generator fills the
right contract addresses + chain id).

That is the whole onboarding. The manual runbook below is exactly what the one
command does, step by step — use it if you want to drive each step yourself or
`fwd` isn't on your `PATH`.

### The manual runbook (what `fwd onboard rewards` does)

The runbook is the exact ordered sequence for the default on **Coston2** (the
rehearsal network); every name matches the generator's output, so it is
copy-paste end to end. You change only **two** things: your reward recipient
(step 2) and your imported signing key (step 5). For mainnet, swap `coston2` →
`flare` / `songbird` everywhere.

`clifwd` runs each admin command inside the container; the `>` redirect (step 2)
and `sudo fwd restart` (step 3) run on the **host**. Only **two** steps need a
human decision — both are flagged GATE.

```sh
# 1. (the installer already generated the sealed master.)

# 2. Generate the default reward policy and pin YOUR recipient. The '>' redirect
#    runs on the host, so it writes the host file the container mounts read-only
#    as the live policy. (Back up any existing one first: cp config/policy.yaml{,.bak})
clifwd policy init --networks coston2 \
  --recipient 0xYOUR_CLAIM_RECIPIENT_ADDRESS \
  > config/policy.yaml
clifwd policy validate --schema-only          # reads the live mount; no daemon needed

# 3. LOAD it. REQUIRED before step 4 — wallets/callers create validate the
#    requested policy_path against the LOADED (in-memory) policy. (The policy
#    loads fine though its wallets/callers don't exist yet: they're declared in
#    policy.wallets / policy.callers, and there are no ACTIVE callers to fail the
#    startup consistency check until you create them.)
sudo fwd restart

# 4. Create the two fwd-GENERATED wallets — the claim executor + the FSP gas payer:
clifwd wallets create --name claimer-coston2 --policy wc/claimer-coston2
clifwd wallets create --name fsp-sender      --policy wc/fsp-sender

# 5. GATE 1 (operator-only) — IMPORT your registered signing-policy key. Key
#    material is handled here and nowhere else; the file must be mode 0600, owned
#    by you, and decode to exactly 32 bytes of hex:
clifwd wallets import --name fsp-signing-coston2 --policy wc/fsp-coston2 \
  --privkey-file /abs/path/to/signing.key --shred-source

# 6. Mint the three caller tokens (each printed ONCE — inject into clif's env):
clifwd callers create --name claim-coston2      --policy perm/claim-coston2
clifwd callers create --name fsp-sign-coston2   --policy fsp/coston2
clifwd callers create --name fsp-submit-coston2 --policy perm/fsp-submit-coston2

# 7. Full gate — must pass (schema + live DB / ABI / wallet-binding consistency):
clifwd policy validate

# 8. Seed the next nonce for the two SENDER wallets (fwd is zero-egress — it can't
#    read the chain). Both are freshly generated, so start at 0:
clifwd nonce init --wallet claimer-coston2 --chain 114 --starting-nonce 0
clifwd nonce init --wallet fsp-sender      --chain 114 --starting-nonce 0
#    (The signing key signs detached FSP messages — no nonce. Seed it as well only
#     if you opt it in as a self-submitter instead of using fsp-sender.)

# 9. GATE 2 (operator-only) — on-chain, from your OFFLINE identity key (fwd never
#    custodies it):
#      ClaimSetupManager.setClaimExecutors   -> authorize claimer-coston2
#      setAllowedClaimRecipients             -> allow 0xYOUR_CLAIM_RECIPIENT_ADDRESS
#      FSP signing-policy registration       -> register fsp-signing-coston2 as a voter
```

Then rehearse a real claim + FSP sign on Coston2 through clif, verify the
`RewardClaimed` event on-chain and `clifwd audit verify`, and only then add
flare / songbird and go to mainnet.

(`fwd onboard rewards` above runs exactly steps 2–8 and prints the step-9
checklist with your concrete addresses — the runbook is the manual equivalent.)

## Release & pinning

The install URL resolves to a small, auditable POSIX script pinned to a release
tag (the vanity URL only redirects to the in-repo `install/install.sh` at that
tag). It fetches a versioned manifest — **source refs + checksums, not image
digests** (build-from-source):

```yaml
version: 1.1.0
fwd_source:  { repo: https://github.com/africanproofs/fwd.git,  tag: v1.1.0, sha: <hex> }
clif_source: { repo: https://github.com/africanproofs/clif.git, tag: v0.5.x, sha: <hex> }   # --with-clif
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
  **auditable in the public repo** (`github.com/africanproofs/fwd`; the vanity
  URL only redirects).
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
Next: the reward-onboarding runbook (default claim + FSP): policy init → restart →
wallets create/import → callers create → policy validate → nonce init → on-chain authorize.
```
Production readiness gate: custody init complete; `clifwd health` healthy;
`clifwd audit verify` succeeds; a wallet imported without leaking key material to
HTTP/shell-history/logs/audit; the first caller issued a policy-bound token;
`clifwd policy validate` green.
