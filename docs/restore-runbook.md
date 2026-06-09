# Restore Runbook

Use this when rebuilding a `fwd` host or recovering from the installer warning
that an existing state volume contains wallets sealed under a different
`master.key`.

The critical rule: a SQLite state database and its `master.key` are a pair.
Without the exact `master.key` that sealed the wallets in `state.db`, `fwd`
cannot decrypt them. If that key is lost, regenerate wallets and redo the
on-chain authorizations instead of trying to recover the old state.

## 0. Backup (create the bundle — regularly AND after every custody change)

The restore below only works if you have a current off-host bundle. **Take a fresh
bundle whenever custody changes** (a `wallets create`/`import`, a `master generate`/
re-seal, a `policy.yaml` change) — a bundle that predates your current wallet set
cannot restore it. Automate it (cron) so it is never just-in-time.

```sh
# 0a. Consistent SQLite snapshot (online-safe — do NOT cp a live state.db; the WAL
#     would be torn). Uses sqlite3 .backup against the state volume.
STATE_VOL=fwd_fwd-state                     # = <COMPOSE_PROJECT>_fwd-state
sudo mkdir -p /tmp/fwd-backup
sudo docker run --rm -v "$STATE_VOL":/data:ro -v /tmp/fwd-backup:/out alpine \
  sh -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /data/state.db ".backup /out/state.db"'

# 0b. Gather the custody bundle (the four Required Inputs below + clif envs).
sudo cp /opt/fwd/src/config/master.key /opt/fwd/src/config/policy.yaml /opt/fwd/src/.env /tmp/fwd-backup/
sudo cp /opt/clif/.env.songbird /opt/clif/.env.flare /tmp/fwd-backup/ 2>/dev/null || true

# 0c. Encrypt — NEVER write master.key off-host in the clear. Fail closed if you have
#     no recipient. age (preferred) or gpg:
TS=$(date +%Y%m%d-%H%M%S)
sudo tar -C /tmp/fwd-backup -czf - . | age -r <AGE_RECIPIENT_PUBKEY> -o "fwd-backup-$TS.tar.gz.age"
#   ...or: sudo tar -C /tmp/fwd-backup -czf - . | gpg -e -r <GPG_RECIPIENT> -o "fwd-backup-$TS.tar.gz.gpg"

# 0d. Shred the staging dir (it held the plaintext master.key), then copy the
#     ENCRYPTED bundle OFF-HOST (another machine / object storage) and verify it decrypts.
sudo shred -u /tmp/fwd-backup/master.key 2>/dev/null; sudo rm -rf /tmp/fwd-backup
```

Schedule it (e.g. daily) via root cron, writing to a path you replicate off-host:

```cron
17 3 * * *  /usr/local/sbin/fwd-backup.sh   # wrap 0a–0d; alert if it exits non-zero
```

## Required Inputs

Have these from your off-host backup before starting:

- `master.key` for the restored wallets.
- `policy.yaml` that authorizes those wallets and callers.
- `.env` with the `FWD_ADMIN_KEY` and image tag used by the stack.
- Any `clif` env files, for example `.env.songbird` and `.env.flare`.
- A SQLite backup: either a cold `state.db` copy or the Litestream local replica
  directory from the `backup` volume.

Do not paste private keys into this restore path. Restoring reuses already sealed
wallet ciphertext from SQLite.

## 1. Stage The Software Without Starting Custody

On the new or rebuilt host:

```sh
git clone https://github.com/africanproofs/fwd.git
sudo sh fwd/install/install.sh --no-start
```

This creates the fwd install layout under `/opt/fwd` and builds the fwd image (fwd-only;
clif is a separate deployment, restored independently). It may generate placeholder config;
the next step overwrites it with the restored files.

## 2. Restore Operator Config

Copy the restored config into the live install paths:

```sh
sudo install -m 0600 /path/to/backup/master.key /opt/fwd/src/config/master.key
sudo install -m 0600 /path/to/backup/policy.yaml /opt/fwd/src/config/policy.yaml
sudo install -m 0600 /path/to/backup/.env /opt/fwd/src/.env

sudo chown -R 1000:1000 /opt/fwd/src/config /opt/fwd/src/.env

# clif is a SEPARATE deployment — restore its per-network env to /opt/clif (or just
# re-run `fwd onboard …` to regenerate it after fwd is back up):
sudo mkdir -p /opt/clif
sudo install -m 0600 /path/to/backup/.env.songbird /opt/clif/.env.songbird
sudo install -m 0600 /path/to/backup/.env.flare /opt/clif/.env.flare
sudo chown -R 1000:1000 /opt/clif
```

Skip a network env file if that network was not onboarded.

## 3. Restore SQLite State

Stop any partial stack first:

```sh
cd /opt/fwd/src
sudo fwd stop || true
```

The default Compose project is `fwd`, so the state volume is
`fwd_fwd-state`. If you installed with a custom `FWD_CONTAINER`, use that prefix
instead.

For a cold `state.db` copy:

```sh
STATE_VOL=fwd_fwd-state
sudo docker volume create "$STATE_VOL"
sudo docker run --rm \
  -v "$STATE_VOL":/data \
  -v /path/to/backup:/restore:ro \
  alpine sh -c '
    rm -f /data/state.db /data/state.db-wal /data/state.db-shm
    cp /restore/state.db /data/state.db
    chown -R 1000:1000 /data
  '
```

For a Litestream replica, first copy the off-host replica contents into the
`fwd_backup` volume, then restore:

```sh
BACKUP_VOL=fwd_backup
STATE_VOL=fwd_fwd-state
sudo docker volume create "$BACKUP_VOL"
sudo docker volume create "$STATE_VOL"

sudo docker run --rm \
  -v "$BACKUP_VOL":/backup \
  -v /path/to/litestream-backup:/restore:ro \
  alpine sh -c 'cp -a /restore/. /backup/'

sudo docker run --rm \
  -v "$STATE_VOL":/data \
  -v "$BACKUP_VOL":/backup \
  -v /opt/fwd/src/config/litestream/litestream.yml:/etc/litestream.yml:ro \
  litestream/litestream:0.5.11 \
  restore -config /etc/litestream.yml /data/state.db

sudo docker run --rm \
  -v "$STATE_VOL":/data \
  alpine chown -R 1000:1000 /data
```

If Litestream refuses because `/data/state.db` already exists, remove
`state.db`, `state.db-wal`, and `state.db-shm` from the state volume with a
throwaway container and rerun the restore.

## 4. Start And Verify

```sh
cd /opt/fwd/src
sudo fwd start
clifwd health
clifwd wallets list
clifwd audit verify
```

If `clifwd health` reports `sealed_master` not ready, stop. The restored
`master.key` does not match the restored SQLite wallet ciphertexts, or file
permissions prevent the container from reading it.

## 5. Reconcile Nonces Before Automation

`fwd` has no chain egress, so restored nonce state may trail chain truth. For
each sender wallet and network, read the on-chain nonce through keyless `clif`
and advance `fwd` only monotonically:

```sh
clif chain nonce --network songbird --address 0xSENDER_ADDRESS
clifwd nonce get --wallet claimer-songbird --chain 19
clifwd nonce sync --wallet claimer-songbird --chain 19 --on-chain-count <CHAIN_NONCE>
```

Use chain `19` for Songbird and `14` for Flare. If a wallet has no nonce row,
use `clifwd nonce init` with the chain nonce instead of `nonce sync`.

## 6. Resume Deliberately

Run one manual rehearsal before restarting automation:

```sh
clifctl run songbird claim --type fee   # via the separate clif deployment
clifwd audit verify
sudo fwd status
```

Only after the restored host signs correctly, the expected on-chain event is
verified, and nonces are reconciled should you restart the epoch daemon — from the
SEPARATE clif deployment:

```sh
clifctl up songbird
```

Repeat the same checks before enabling Flare.

## If The Master Key Is Lost

Old sealed wallets are unrecoverable. The recovery path is:

1. Start from a clean state volume or run the installer with `--reset-state`.
2. Run `sudo fwd onboard rewards ...` again.
3. Authorize the newly generated/imported wallets on-chain from the offline
   identity key.
4. Fund gas-paying wallets.
5. Rehearse on Songbird before Flare.

## Disaster-recovery drills (Coston2 — rehearse before you need them)

Both recovery paths above are documented but cost-free to drill on Coston2. Run them
**once on Coston2** so the first real execution is not a first-time, under-pressure one.

### A. Claim-executor re-authorization (after a claimer-wallet regen)

If a claimer (executor) wallet is regenerated — master lost, or a deliberate rotation —
the on-chain executor authorization must be redone or claims silently fail. The mechanic
is `ClaimSetupManager.setClaimExecutors` (re-authorize the NEW executor; the owner stays
the identity address — this is NOT recipient rotation).

1. Coston2: regenerate a claimer wallet — `clifwd wallets create claimer-coston2-drill`
   (note its address).
2. From the identity owner, authorize the new executor on-chain:
   `ClaimSetupManager.setClaimExecutors([<new executor address>])`.
3. Verify authorization: `clifctl run coston2 preflight --identity 0x… --recipient 0x…`
   shows the executor authorized.
4. On a claimable Coston2 epoch: `clifctl run coston2 claim` — confirm it mints to the
   recipient using the regenerated executor.

**Acceptance:** the claim succeeds end to end with the regenerated executor. Once this
passes, lift the `[Flag — DR mechanic unverified]` on Core invariant #17 (`CLAUDE.md`).

### B. Master-key-lost full restore

On a throwaway host, execute the "If The Master Key Is Lost" path end to end (regenerate →
on-chain re-auth from the offline identity → fund → Songbird rehearsal) and confirm a
rehearsal claim succeeds with the regenerated wallets. This proves the unrecoverable-key
path is survivable, not just documented.
