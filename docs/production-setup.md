# Full production setup (fwd + clif)

The canonical end-to-end sequence to take a host from nothing to a **fully operating**
FTSO-reward provider. A fresh setup is **more than the installer** — the installer only
brings up an *inert* signer. The system is fully set up only when **install, onboarding,
on-chain authorization, gas funding, rehearsal, audit verification, and the intended daemons**
are all complete. Until then it is not production-ready, and no step here implies otherwise.

For installer internals and the custody gate, see [`one-command-install.md`](one-command-install.md);
for the onboarding wizard's mechanics, see its "Reward onboarding" section.

## 1. Install the stack (with clif), inert

```sh
curl -sfL https://get.proofs.africa/fwd | sudo sh -s -- --with-clif
```

Until `get.proofs.africa` hosting lands (Phase-1 pending), clone the public source and run the
installer directly — identical effect:

```sh
git clone https://github.com/africanproofs/fwd.git && sudo sh fwd/install/install.sh --with-clif
```

This builds `fwd` + `clif`, installs the host wrappers (`fwd`, `clifwd`, `clif`), starts **only
`fwd` + `litestream`**, and leaves custody **inert** (empty default-deny policy, zero wallets,
signs nothing). Output is a compact operator cockpit by default; add `--guided` (or `FWD_OUTPUT=guided`) for the verbose, first-timer walk-through.

## 2. Run reward onboarding — canary first

Onboard the **Songbird canary first**, prove it, then expand (onboarding is idempotent — re-running
a network is a no-op and only adds the new one):

```sh
sudo fwd onboard rewards \
  --identity 0xYOUR_OFFLINE_IDENTITY_ADDRESS \
  --recipient 0xYOUR_CLAIM_RECIPIENT_ADDRESS \
  --networks songbird
```

Add `--guided` for the step-by-step walk-through; the default compact output still prints every safety gate and on-chain action.

Later, after the canary is clean (step 7), expand: re-run with `--networks songbird,flare`.
(You *may* pass `songbird,flare` up front; canary-first is the safer discipline.)

**Migrating an existing provider:** add `--import-existing` and **stop the old submitter/claimer
before fwd takes over those keys** — otherwise the old client and fwd collide on nonces.

## 3. Complete the custody gates (during onboarding)

The wizard walks these; each prints in compact and guided mode. **Blank/deferred = that function
is not set up:**

- confirm the recipient and identity addresses
- create (or, with `--import-existing`, import) the **claim executor** wallet (`claimer-<net>`)
- **import the FSP signing key** when prompted (`fsp-signing-<net>` — must match your registered voter key)
- create/import the **FSP gas sender** (`fsp-sender-<net>`)
- let onboarding **mint the clif caller tokens** (written to the env, not printed unless `--show-secrets`)
- let it **seed nonces from chain truth** through the keyless clif one-shot (no hand-typing; fwd has no egress)
- confirm it **writes `/opt/fwd/clif/.env.<net>`** (0600, keyless — never a `PRIVATE_KEY`)

## 4. Complete the on-chain authorization (from the offline identity key)

fwd never holds the identity key — you do these offline. The wizard prints the exact list:

- authorize `claimer-<net>` via `ClaimSetupManager.setClaimExecutors`
- allow the recipient via `setAllowedClaimRecipients`
- register `fsp-signing-<net>` as your signing-policy / voter address
- **fund the gas-paying wallets** with native FLR/SGB — `claimer-<net>` (pays `RewardManager.claim`
  gas) and `fsp-sender-<net>` (pays the FSP submit gas). Both are fresh, zero-balance wallets and
  cannot operate unfunded. The FSP signing key needs **no** gas (it signs detached).

## 5. Rehearse with the host `clif` wrapper (not raw Compose)

```sh
clif --network songbird claim --type fee
clif --network songbird fsp uptime --epoch <N>
clif --network songbird fsp rewards --epoch <N>
clifwd audit verify
```

**Verify the real `RewardClaimed` event on-chain** (a mined, status-0x1 tx is *not* proof — `claim`
no-ops silently if already claimed). Do not promote Flare until the Songbird canary is clean.

## 6. Enable and start automation

```sh
sudo fwd start songbird          # claim daemon only
```

For FSP automation, first set this in `/opt/fwd/clif/.env.songbird` (it is `false` by default — clif
`fsp auto` deliberately refuses and exits when disabled):

```
FSP_AUTO_ENABLED=true
```

Then start the FSP daemon:

```sh
sudo fwd start songbird fsp       # FSP auto-signer only
```

`fwd start <net>` reports what it *requested* — `up -d` returning 0 does not prove a daemon stayed
up; confirm with `fwd status` / `fwd logs <svc>`. After the canary is clean, repeat for Flare:

```sh
sudo fwd start flare
sudo fwd start flare fsp
```

## 7. Final checks

```sh
sudo fwd status          # exits non-zero if Docker/compose is unhealthy
sudo fwd logs
clifwd health
clifwd audit verify
```

**Done = all of:** install complete, onboarding complete (no blank/deferred functions),
on-chain authorization done, gas wallets funded, rehearsal passed with a verified on-chain effect,
`clifwd audit verify` green, and the intended daemons running (`fwd status`).
