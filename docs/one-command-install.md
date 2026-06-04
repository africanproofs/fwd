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

The build-from-source installer (`install/install.sh`), the host wrappers
(`fwd` / `clifwd` / `clif`), and the guided onboarding (`install/onboard`) are
present. Two Phase-1 sub-steps are **deferred**: hosting the vanity
`get.proofs.africa/fwd` redirect, and a fetched-manifest + per-artifact
checksum step (today the installer pins source by git ref plus an optional
HEAD-sha integrity pin — see *Release & pinning*). Until the vanity URL is
hosted, the installer is run directly from the public source.

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

1. Detect required host tools (`docker`, `docker compose v2`, `git`) and reach
   the Docker daemon; stop with a clear instruction if any is missing.
2. Resolve the source ref to build (`FWD_REF` / `--ref`, default `main`; a
   release pins a tag) and, if `FWD_SHA` is set, require the cloned `HEAD` to
   equal it (integrity pin). *Deferred Phase-1 sub-step: resolving the ref from
   a fetched, checksummed manifest instead of a bare git ref.*
3. Create the install root (`FWD_DIR`, default `/opt/fwd`, overridable via
   `--dir`) and lay out everything under it:
   ```text
   $FWD_DIR             install root
   $FWD_DIR/src         fetched source + compose bundle (the compose dir)
   $FWD_DIR/src/.env    operator runtime config (FWD_ADMIN_KEY, FWD_IMAGE_TAG)
   $FWD_DIR/src/config  policy.yaml + sealed master.key (gitignored, host-owned)
   $FWD_DIR/clif        clif source + per-network .env files (under --with-clif)
   ```
   Persistent state and the local backup replica are Docker named volumes
   (`fwd-state`, `backup`) in the compose project — not host paths.
4. Fetch the pinned source (fwd; clif too under `--with-clif`). *Deferred
   Phase-1 sub-step: per-artifact checksum verification of the fetched source.*
5. `docker compose build` from that source.
6. Generate the sealed master **locally** (`clifwd master generate`, mode 0600,
   owned by the `fwd` uid) — it is **never fetched or transmitted**.
7. Generate a strong `FWD_ADMIN_KEY` into `$FWD_DIR/src/.env` (preserving
   existing operator values on re-run).
8. Install the host wrappers (`fwd` lifecycle, `clifwd` CLI, `clif` keyless
   client), baking the compose-dir and container-name defaults into each.
9. Start the stack **inert** (empty default-deny policy, zero wallets); under
   `--with-clif`, build clif but leave its daemons stopped until onboarding
   completes.
10. Run `clifwd health`, then print the next required operator action — and
    refuse to imply production custody is complete before it is.

## Host command contract

### `fwd` (lifecycle wrapper)
```sh
sudo fwd start [<net> [fsp]] | stop | restart | status | logs | onboard
sudo fwd upgrade | backup status     # Phase-1 stubs — exit 2 with a pointer to this doc
```
Compose is an implementation detail of these. `fwd start` brings up fwd (+ litestream)
only; `fwd start songbird` starts that network's **claim** daemon ONLY; `fwd start songbird
fsp` starts its **FSP auto-signer** ONLY (opt-in — only meaningful with `FSP_AUTO_ENABLED=true`;
clif refuses + exits otherwise). A claim+FSP provider runs **both** commands; keeping them
independent stops a sign-only (no-claim) host from launching a beneficiary-less claim daemon
(which clif `auto` exits on → restart-loop). Each network reads its own `.env.<net>`; there
is no single shared clif daemon. `fwd start` and `fwd status` print a compact started /
current-state cockpit (what came up, what didn't and how to start it, clif env presence per
network, the next action).

### `clifwd` (application CLI + reward onboarding)
```sh
clifwd health
clifwd policy init --networks … --recipient 0x…
clifwd wallets import --name … --privkey-file /path/in/container …
clifwd onboard rewards --recipient 0x… --networks songbird   # runs on the HOST
```
Normal usage delegates into the container (`docker exec "${FWD_CONTAINER:-fwd}"
clifwd …`) — same Python package, env, mounted state, policy, and custody backend
as the daemon; for file-based ops (`wallets import`), `--privkey-file` is evaluated
**inside** the container. The one exception is `clifwd onboard …`, which runs on
the **host** (it `docker compose restart`s the daemon and writes the host policy
file — neither possible from inside the container) — see the reward-onboarding
section below.

## Reward onboarding — an opt-in, one-terminal step

Install always ends **inert** (empty default-deny policy, signs nothing);
initializing custody is a **security event, not a default**. Reward signing + fee
claiming are a separate, **opt-in** step — run the guided wizard any time with the
host command:

```sh
sudo fwd onboard rewards --recipient 0xYOUR_CLAIM_RECIPIENT_ADDRESS --networks songbird
```

(or chain it onto the install with `--onboard-rewards`, which requires a TTY + a
started stack). `clifwd onboard rewards …` remains a compatibility alias for the
same host orchestrator; `fwd onboard` is the canonical entry point.

**FSP signing needs your key registered as a voter on the chosen network** —
Songbird / Flare for AP. `coston2` is a testnet: use it only if you are a registered
Coston2 voter (otherwise an FSP signature is rejected on-chain). The claim path has
no such constraint.

You do **not** have to learn the policy schema. In **guided mode** (`--guided`) the wizard
**narrates each step**; by default it runs **compact** (section headers, the addresses it
derived, a summary table, the on-chain next-step). Either way it
**groups the work into a clearly-demarcated section per function** (fee claiming;
FSP reward signing), **echoes each wallet's address** (so you can confirm a pasted
key derived the address you expect), and describes each key in the contract's own
terms (the claim executor that calls `RewardManager.claim`; your signing policy
address that signs `signUptimeVote`/`signRewards`; the `msg.sender` that submits the
tx). It does the whole sequence: build the default reward policy (your recipient
pinned), validate it, load it (restart out of inert), provision the wallets fwd
signs from, mint the caller tokens (written into clif's per-network env, not shown
unless `--show-secrets`), **read each sender's nonce from chain truth via the keyless
clif one-shot** (no hand-typing — fwd has no egress; clif does), write clif's
`.env.<net>` files, and print the final on-chain step. It is **idempotent**
(re-running skips what exists, preserves tokens already in the env, and re-reads the
chain nonce; no restart if the policy is unchanged). Flags: `--identity 0xOWNER`
(required when claiming), `--recipient 0xADDR`, `--fsp-sender per-network|shared`
(default per-network), `--import-existing` (migration — see below), `--claim-only` /
`--sign-only`, `--skip-fsp-import` (defer the key gate), `--accept-pending-nonces`
(cutover when pending > latest), `--rotate-missing-callers` (re-mint a lost token),
`--show-secrets`, `--guided` / `--explain` (the verbose walk-through — output is a compact
cockpit by default, or set `FWD_OUTPUT=guided`), and a comma list for `--networks`
(`flare` / `songbird` for mainnet).

**After onboarding (go-live).** onboard does not make you production-ready. Complete, in
order: (1) the printed on-chain authorization from your **offline identity key**
(`ClaimSetupManager.setClaimExecutors` + `setAllowedClaimRecipients`; register the FSP signer
as a voter) — or, with `--import-existing`, the **CUTOVER** (stop the old submitter first, so
it and fwd do not collide on nonces); (2) **rehearse** through the `clif` wrapper on the
**Songbird canary** before Flare; (3) **verify** the `RewardClaimed` event on-chain and
`clifwd audit verify`; (4) only then start always-on automation with `sudo fwd start <net>`
(add `… fsp` to also start the FSP auto-signer). The wizard prints this exact sequence at the
end, in both compact and guided modes.

**Pasting your key (single terminal).** At the import step the wizard prompts you to
**paste each private key directly (hidden input)** — no pre-placed file. fwd pipes
the pasted key straight into the daemon container, seals it under the master, and
shreds the transient input: it never touches this host's disk and never leaves the
box. (Transient surface only — terminal input → a cleared shell var → a local pipe →
a 0600 in-container temp that is shredded; proportionate to low-value automation
keys, per the threat model.) Paste blank to defer a key and import it later.

**Reward class.** The command takes a class: `rewards fsp` (the default — FTSO
claim + FSP signing, today's provider rewards) or `rewards validator`
(staking/validator rewards — a future class, not yet implemented). Bare
`clifwd onboard rewards` means `fsp`.

**Migrating an existing provider?** Add **`--import-existing`**. By default onboard
*generates* a fresh claim executor + FSP sender (greenfield; cleanest custody — the
keys are born inside fwd and never had a plaintext life). But if you already run a
provider, you already hold a funded, on-chain-authorized executor and submit key —
`--import-existing` imports those (and the signing key) instead of generating new
ones, so you skip re-running `setClaimExecutors` and re-funding a new sender. It
**reads each sender's current on-chain nonce via clif** (fwd is zero-egress; clif has
egress — no hand-typing; pending > latest aborts the cutover unless
`--accept-pending-nonces`) and prints a **cutover** checklist instead of new authorization. The
trade-off: an imported key carries its pre-fwd plaintext exposure into fwd, and you
must **stop the old submitter/claimer** for those accounts (fwd becomes their sole
user — otherwise the two collide on nonces).

That is the whole onboarding. The manual runbook below is exactly what the one
command does, step by step — use it if you want to drive each step yourself.

### The manual runbook (what `clifwd onboard rewards` does)

The runbook is the exact ordered sequence for the default on **Songbird** (AP's
canary); every name matches the generator's output, so it is copy-paste end to
end. You change only **two** things: your reward recipient (step 2) and your
imported signing key (step 5). For Flare, swap `songbird` → `flare` (chain 19 →
14) everywhere; `coston2` only if you are a registered Coston2 voter.

`clifwd` runs each admin command inside the container; the `>` redirect (step 2)
and `sudo fwd restart` (step 3) run on the **host**. Only **two** steps need a
human decision — both are flagged GATE.

```sh
# 1. (the installer already generated the sealed master.)

# 2. Generate the default reward policy and pin YOUR recipient. The '>' redirect
#    runs on the host, so it writes the host file the container mounts read-only
#    as the live policy. (Back up any existing one first: cp config/policy.yaml{,.bak})
clifwd policy init --networks songbird \
  --recipient 0xYOUR_CLAIM_RECIPIENT_ADDRESS \
  > config/policy.yaml
clifwd policy validate --schema-only          # reads the live mount; no daemon needed

# 3. LOAD it. REQUIRED before step 4 — wallets/callers create validate the
#    requested policy_path against the LOADED (in-memory) policy. (The policy
#    loads fine though its wallets/callers don't exist yet: they're declared in
#    policy.wallets / policy.callers, and there are no ACTIVE callers to fail the
#    startup consistency check until you create them.)
sudo fwd restart

# 4. Create the two fwd-GENERATED wallets — the claim executor + the FSP gas payer
#    (per-network default: fsp-sender-songbird; `--fsp-sender shared` uses one fsp-sender):
clifwd wallets create --name claimer-songbird    --policy wc/claimer-songbird
clifwd wallets create --name fsp-sender-songbird --policy wc/fsp-sender-songbird

# 5. GATE 1 (operator-only) — IMPORT your registered signing-policy key. Key
#    material is handled here and nowhere else; the file must be mode 0600, owned
#    by you, and decode to exactly 32 bytes of hex:
clifwd wallets import --name fsp-signing-songbird --policy wc/fsp-songbird \
  --privkey-file /abs/path/to/signing.key --shred-source

# 6. Mint the three caller tokens (each printed ONCE — inject into clif's env):
clifwd callers create --name claim-songbird      --policy perm/claim-songbird
clifwd callers create --name fsp-sign-songbird   --policy fsp/songbird
clifwd callers create --name fsp-submit-songbird --policy perm/fsp-submit-songbird

# 7. Full gate — must pass (schema + live DB / ABI / wallet-binding consistency):
clifwd policy validate

# 8. Seed the next nonce for the two SENDER wallets. The wizard reads this from chain
#    via clif (no hand-typing): `clif chain nonce --network songbird --address 0x..`,
#    then nonce init / nonce sync. Freshly generated wallets are 0, so the manual
#    greenfield equivalent is:
clifwd nonce init --wallet claimer-songbird    --chain 19 --starting-nonce 0
clifwd nonce init --wallet fsp-sender-songbird --chain 19 --starting-nonce 0
#    (The signing key signs detached FSP messages — no nonce. Seed it as well only
#     if you opt it in as a self-submitter instead of using fsp-sender-songbird.)

# 9. GATE 2 (operator-only) — on-chain, from your OFFLINE identity key (fwd never
#    custodies it):
#      ClaimSetupManager.setClaimExecutors   -> authorize claimer-songbird
#      setAllowedClaimRecipients             -> allow 0xYOUR_CLAIM_RECIPIENT_ADDRESS
#      FSP signing-policy registration       -> register fsp-signing-songbird as a voter
```

Then rehearse a real claim + FSP sign on Songbird (the canary) through clif, verify
the `RewardClaimed` event on-chain and `clifwd audit verify`, and only then go to
Flare.

(`clifwd onboard rewards` above runs exactly steps 2–8 and prints the step-9
checklist with your concrete addresses — the runbook is the manual equivalent.)

## Release & pinning

The installer clones **pinned source** — `FWD_REF` / `--ref` (a release pins a
tag; default `main`) plus an optional `FWD_SHA` that the cloned `HEAD` must
equal (the integrity pin). clif is pinned the same way via `CLIF_REF` under
`--with-clif`. Source repos default to the public
`github.com/africanproofs/{fwd,clif}.git`.

The **deferred Phase-1 sub-step** layers a fetched, checksummed manifest on top
of git-ref pinning — **source refs + checksums, not image digests**
(build-from-source) — at which point the installer also verifies every fetched
artifact's checksum:

```yaml
version: 1.1.0
fwd_source:  { repo: https://github.com/africanproofs/fwd.git,  tag: v1.1.0, sha: <hex> }
clif_source: { repo: https://github.com/africanproofs/clif.git, tag: v0.5.x, sha: <hex> }   # --with-clif
compose_sha256: <hex>
networks_sha256: <hex>
```

The same step pairs with the vanity `get.proofs.africa/fwd` URL, which redirects
to the in-repo `install/install.sh` at the pinned tag.

## Modes

- **Dev / Coston2** — `… | sh -s -- --dev`: relaxed defaults for test keys and
  live Coston2 rehearsal only.
- **Production** — `… | sh -s -- --production`: conservative; requires explicit
  custody init before the first production wallet, and refuses known-unsafe
  states (e.g. a dev master reused for production).

## Upgrade

`sudo fwd upgrade` is a **Phase-1 stub** (the host wrapper exits 2 with a
pointer to this doc); it is finalized together with the manifest-fetch step. The
target behaviour: read current version → fetch + build new source → stop only
after the build succeeds → preserve `$FWD_DIR/src/.env` + `config/` + the state
volume → run migrations via the container entrypoint → start → `clifwd health` →
print rollback steps on failure. **Never** overwrites operator policy or secrets.

## Security model of `curl | sh` for a custody tool

- The script is published and **auditable in the public repo**
  (`github.com/africanproofs/fwd`); a release pins it to an **immutable tag**.
- **Build from pinned source** — `FWD_REF` plus an optional `FWD_SHA` HEAD-equality
  integrity pin. (Per-artifact **checksum verification** lands with the deferred
  manifest step.)
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
