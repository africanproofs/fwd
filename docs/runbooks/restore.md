# Restore runbook — fwd state from the local `backup` volume (Phase 6)

> This runbook documents the disaster-recovery procedure for fwd: restore
> `state.db` from the Litestream file replica, restore Vault from its Raft
> snapshot, and confirm a working signing path against the restored state.
>
> **Where this fits in Phase 6 (after v0.4.3 reversion):**
>
> - **SQLite restore (Steps 1–3, 5–8):** complete — Litestream continuously
>   replicates `state.db` into the shared `backup` Docker volume.
> - **Vault restore (Step 4):** complete — vault-snapshot sidecar writes
>   nightly Raft snapshots to the same volume. Restore preserves the
>   original `fwd-master` Transit key and the original AppRole credentials,
>   so wallet ciphertexts in SQLite remain decryptable post-restore.
>
> **Operator-driven off-host transport.** fwd produces backup artifacts at
> a known local path (`/backup` inside the sidecar containers; the `backup`
> Docker volume on the host). It does NOT transport them off-host. To
> survive host destruction the operator MUST arrange off-host copy of the
> `backup` volume contents (rsync over SSH / restic / borg / NAS / USB —
> whatever fits the deployment), run out-of-band. **This runbook assumes
> the operator has already copied the `backup` volume contents to the new
> host using their preferred tool** before starting at Step 1 below.
>
> **RTO target:** ≤ 30 minutes from "backup contents available on the new
> host" to "first successful `/v1/sign-and-send`" (per `architecture.md:598`).
> Actual wall-clock measurement happens at Phase 6 GA (drill execution).
>
> **Related runbooks:**
> - `docs/runbooks/vault-init.md` — first-run Vault initialization and unseal
> - `docs/runbooks/phase-5-verification.md` — signing path smoke test

---

## Prerequisites

Before starting:

1. **`backup` volume contents copied to the new host.** Off-host transport
   is operator-driven and out-of-band. By Step 1 below, the new host has a
   `backup` Docker volume (or bind-mounted host path) populated with the
   pre-disaster contents — at minimum:

   - `/backup/state.db.litestream/...` (Litestream WAL + snapshots)
   - `/backup/vault-snapshots/vault-<UTC-timestamp>.snap` (at least one)

   The exact mechanism — rsync over SSH, restic, borg, NAS replay, USB
   carry-out — is the operator's choice and is NOT part of this runbook.
   fwd does not transport backups off-host.

2. **`.env` populated with the FWD-relevant vars** (no cloud creds needed):

   ```
   FWD_VAULT_ROLE_ID=<from vault-init.sh>
   FWD_VAULT_SECRET_ID=<from vault-init.sh>
   FWD_VAULT_SNAPSHOT_ROLE_ID=<from vault-init.sh>
   FWD_VAULT_SNAPSHOT_SECRET_ID=<from vault-init.sh>
   FWD_ADMIN_KEY=<admin bearer>
   ```

   Plus the caller API key(s) for any callers you need to smoke-test.

3. **fwd stack is DOWN** (this is a restore — running `litestream restore`
   against a live, open SQLite WAL is unsafe).

   ```sh
   docker compose ps
   # Confirm: all services show "Exit" or are absent
   ```

4. **D6 unseal shares accessible.** You will need 3 of the 5 shares from
   the `decisions.md` D6 distribution to unseal Vault after the snapshot
   restore in Step 4. Retrieve them before starting the restore clock.

5. **Host has `docker` and `docker compose` installed.** No external CLI
   tools needed — restore runs entirely via `docker exec`.

---

## Step 1 — Confirm the `backup` volume has restorable contents

Before destroying anything, verify the local backup volume on the new
host has both halves of the restore artifact set: Litestream's file
replica AND at least one Vault Raft snapshot.

```sh
# Inspect the volume via a throwaway container.
docker run --rm -v fwd_backup:/b alpine:3.19 sh -c '
    echo "--- /b ---"
    ls -la /b
    echo "--- /b/state.db.litestream ---"
    ls -la /b/state.db.litestream 2>/dev/null | head -10
    echo "--- /b/vault-snapshots ---"
    ls -la /b/vault-snapshots 2>/dev/null
'
```

Expected:
- `/b/state.db.litestream/` contains generation directories with WAL +
  snapshot subfolders (Litestream's on-disk format).
- `/b/vault-snapshots/` contains at least one `vault-<UTC-ts>.snap` file.

**Pass criterion:**

```sh
docker run --rm -v fwd_backup:/b alpine:3.19 sh -c '
    test -d /b/state.db.litestream \
        && ls /b/vault-snapshots 2>/dev/null | grep -qE "^vault-[0-9]{8}T[0-9]{6}Z\.snap$"
'
echo $?  # 0 = pass
```

If either half is missing: the off-host transport step (operator's
responsibility, pre-runbook) was incomplete. Do NOT proceed — go back
and re-copy. There is no restorable state on this host yet.

---

## Step 2 — Spin up a fresh fwd stack with clean state volumes

Destroy the state volumes (vault-data, fwd-state) so the restore lands
into a clean state. **DO NOT** destroy the `backup` volume — that holds
the restore source you copied in.

```sh
docker volume rm fwd_vault-data fwd_fwd-state || true
# Leaves fwd_backup intact.
```

Start the stack (all four services: vault, fwd, litestream, vault-snapshot):

```sh
docker compose up -d
```

At this point:
- `fwd-vault` is running but uninitialized (its volume is empty).
- `fwd` has started (it will fail to contact Vault — that's expected; it
  restarts until unsealed).
- `fwd-litestream` is running and will idle until `state.db` exists.
- `fwd-vault-snapshot` is running and will idle/fail-login until Vault is
  restored (Step 4) and unsealed (the loop continues across failures).

```sh
docker compose ps
# Expected: vault (healthy), fwd (restarting OK), litestream (running),
#           vault-snapshot (running).
```

---

## Step 3 — Restore `state.db` from the local file replica

The Litestream replica lives at `/backup/state.db` (and its sibling
`.litestream` directory) inside the `backup` Docker volume. Restore
writes the recovered SQLite into the `fwd-state` volume mounted at
`/data` inside the fwd container.

Because Litestream's source-aware restore reads its replica from a
filesystem path it needs to traverse, the cleanest path is to run a
throwaway `litestream` container with BOTH volumes mounted, then `docker
cp` the recovered file into the fwd container:

```sh
docker run --rm \
    -v fwd_backup:/backup:ro \
    -v "$(pwd)/config/litestream/litestream.yml:/etc/litestream.yml:ro" \
    litestream/litestream:0.3.13 \
    restore -config /etc/litestream.yml -o /tmp/state.db /data/state.db
# litestream prints progress; "restore complete" on success.
```

Litestream's `-o` writes to `/tmp/state.db` inside the throwaway
container. Capture and inject into fwd's volume:

```sh
docker run --rm \
    -v fwd_backup:/backup:ro \
    -v fwd_fwd-state:/state \
    -v "$(pwd)/config/litestream/litestream.yml:/etc/litestream.yml:ro" \
    litestream/litestream:0.3.13 \
    sh -c '
        litestream restore -config /etc/litestream.yml -o /state/state.db /data/state.db
        chown 1000:1000 /state/state.db
    '
```

The `chown 1000:1000` matches fwd's non-root user inside the fwd image
(see `Dockerfile`).

**Pass criterion:**

```sh
docker run --rm -v fwd_fwd-state:/state alpine:3.19 test -s /state/state.db
echo $?  # 0 = pass
```

---

## Step 4 — Restore Vault state from the local Raft snapshot

The vault-snapshot sidecar writes a Vault Raft snapshot to
`/backup/vault-snapshots/vault-<UTC-ts>.snap` on a configurable interval
(default 24h). After off-host transport (operator's responsibility), the
restore procedure on the new host is:

**(a) Locate the latest snapshot in the `backup` volume and place it
where the vault container can read it.**

```sh
# Pick the newest snapshot from the backup volume.
LATEST=$(docker run --rm -v fwd_backup:/b alpine:3.19 sh -c '
    ls /b/vault-snapshots 2>/dev/null \
        | grep -E "^vault-[0-9]{8}T[0-9]{6}Z\.snap$" \
        | sort \
        | tail -1
')

[ -z "${LATEST}" ] && { echo "ERROR: no snapshots in /backup/vault-snapshots/"; exit 1; }

# Copy into a host-side tmp file, then docker cp into fwd-vault.
docker run --rm -v fwd_backup:/b alpine:3.19 cat "/b/vault-snapshots/${LATEST}" > /tmp/vault.snap
docker cp /tmp/vault.snap fwd-vault:/tmp/vault.snap
rm -f /tmp/vault.snap
```

**(b) Initialize the fresh Vault with throwaway Shamir.**

Vault snapshot restore requires the target Vault to be initialized AND
unsealed AND authenticated. We init with throwaway shares; the snapshot
restore overwrites the seal config with the ORIGINAL D6 shares' seal.

```sh
docker exec fwd-vault vault operator init \
    -key-shares=3 -key-threshold=2 -format=json \
    > /tmp/init-dummy.json

# Parse dummy shares + root token (these will be discarded after restore).
DUMMY_KEY_1=$(jq -r '.unseal_keys_b64[0]' /tmp/init-dummy.json)
DUMMY_KEY_2=$(jq -r '.unseal_keys_b64[1]' /tmp/init-dummy.json)
DUMMY_ROOT=$(jq -r '.root_token' /tmp/init-dummy.json)
```

**(c) Unseal with the dummy shares and authenticate.**

```sh
docker exec fwd-vault vault operator unseal "${DUMMY_KEY_1}"
docker exec fwd-vault vault operator unseal "${DUMMY_KEY_2}"
docker exec -e VAULT_TOKEN="${DUMMY_ROOT}" fwd-vault vault status
```

**(d) Restore the snapshot.**

This OVERWRITES the dummy Vault state with the snapshot's state, including
the original Shamir seal configuration.

```sh
docker exec -e VAULT_TOKEN="${DUMMY_ROOT}" fwd-vault \
    vault operator raft snapshot restore -force /tmp/vault.snap
```

The Vault becomes sealed after restore. The dummy unseal keys and the
dummy root token are now invalid — they unsealed the throwaway state, not
the restored state.

**(e) Unseal with the ORIGINAL D6 shares.**

Retrieve 3 of the 5 D6-distributed unseal shares (per `decisions.md` D6 +
Core invariant #17). Apply each:

```sh
docker exec fwd-vault vault operator unseal <D6_SHARE_1>
docker exec fwd-vault vault operator unseal <D6_SHARE_2>
docker exec fwd-vault vault operator unseal <D6_SHARE_3>
docker exec fwd-vault vault status
# Expected: Sealed: false, Initialized: true
```

**(f) Verify the restored state.**

```sh
# The Transit master key must be present — this is what makes wallet
# ciphertexts decryptable.
docker exec -e VAULT_TOKEN=<old-root-token-from-D6> fwd-vault \
    vault list transit/keys
# Expected: fwd-master

# The fwd and fwd-snapshot AppRoles must still exist.
docker exec -e VAULT_TOKEN=<old-root-token-from-D6> fwd-vault \
    vault list auth/approle/role
# Expected: fwd, fwd-snapshot
```

**Pass criterion:**

```sh
# Sealed: false AND fwd-master present
docker exec fwd-vault vault status -format=json \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if not d['sealed'] and d['initialized'] else 1)"
echo $?  # 0 = pass

docker exec -e VAULT_TOKEN=<old-root-token> fwd-vault \
    vault list -format=json transit/keys \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'fwd-master' in d else 1)"
echo $?  # 0 = pass
```

**If your `.env` AppRole `secret_id` values have been rotated since the
snapshot was taken** (rare in v1; `secret_id_ttl=0` means non-expiring): the
fwd container will fail to authenticate with the restored Vault's older
credentials. Generate fresh secret_ids:

```sh
docker exec -e VAULT_TOKEN=<old-root-token> fwd-vault \
    vault write -f auth/approle/role/fwd/secret-id
docker exec -e VAULT_TOKEN=<old-root-token> fwd-vault \
    vault write -f auth/approle/role/fwd-snapshot/secret-id
# Capture both secret_ids, update .env, then `docker compose restart fwd vault-snapshot`
```

**On the honest doctrine (v0.4.2 onwards):** The pre-v0.4.2 fallback (fresh
`vault-init.sh` run with OLD D6 shares) does NOT work — running a fresh
`vault operator init` produces a NEW seal config, which makes the OLD D6
shares useless and the existing wallet ciphertexts unreadable (the
fwd-master Transit key is regenerated under the new seal). Always restore
from snapshot.

---

## Step 5 — Restart fwd against the restored Vault

Step 4 left the Vault unsealed with the ORIGINAL AppRole credentials
intact in the restored state. The `.env` values from before the disaster
should still authenticate. Restart the fwd daemon (and the vault-snapshot
sidecar) so they pick up the restored Vault:

```sh
docker compose restart fwd vault-snapshot
```

If your pre-disaster `.env` is lost, regenerate fresh `secret_id`s per
Step 4's "If your `.env` AppRole `secret_id` values have been rotated"
block and update `.env` before this restart.

Confirm fwd comes up and authenticates against Vault:

```sh
docker logs fwd 2>&1 | grep -E 'startup|vault|lifespan' | tail -20
```

Expected: no `vault_unavailable` or `401` lines; `startup.complete` or
`lifespan.startup` log line with `vault: ok`.

---

## Step 6 — Smoke-test the restored state

Confirm fwd reports healthy and the restored SQLite rows are readable:

```sh
# Health check
clifwd health
# Expected: {"fwd": "ok", "vault": "ok", "rpc": "ok"}
```

**Pass criterion:**

```sh
clifwd health | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('vault')=='ok' and d.get('fwd')=='ok' else 1)"
echo $?  # 0 = pass
```

Confirm the wallet inventory matches the pre-disaster state:

```sh
KEY=$(grep -E '^FWD_ADMIN_KEY=' .env | cut -d= -f2-)

curl -sf -H "Authorization: Bearer $KEY" \
    http://127.0.0.1:8080/v1/admin/wallets | python3 -m json.tool
```

**Pass criterion:**

```sh
# At least one wallet in the response (adjust count to match pre-disaster inventory)
curl -sf -H "Authorization: Bearer $KEY" \
    http://127.0.0.1:8080/v1/admin/wallets \
    | python3 -c "import sys,json; ws=json.load(sys.stdin).get('wallets',[]); sys.exit(0 if len(ws) > 0 else 1)"
echo $?  # 0 = pass
```

Confirm the caller inventory matches:

```sh
curl -sf -H "Authorization: Bearer $KEY" \
    http://127.0.0.1:8080/v1/admin/callers | python3 -m json.tool
```

**Pass criterion:**

```sh
curl -sf -H "Authorization: Bearer $KEY" \
    http://127.0.0.1:8080/v1/admin/callers \
    | python3 -c "import sys,json; cs=json.load(sys.stdin).get('callers',[]); sys.exit(0 if len(cs) > 0 else 1)"
echo $?  # 0 = pass
```

If either wallet or caller check fails (empty inventory but non-empty state
was expected): Litestream replication missed those rows. Surface to the
Reviewer for triage — do NOT proceed to Steps 7–8.

---

## Step 7 — Reconcile nonces against on-chain state

fwd's lifespan startup (v0.4.0a5) automatically calls `nonce_reconcile`
and logs drift between `nonces.next_nonce` and the chain's
`eth_getTransactionCount`:

```sh
docker logs fwd 2>&1 | grep nonce_reconcile
```

Possible outcomes:

| Log line | Meaning | Action |
|---|---|---|
| `nonce_reconcile.complete` with no `drift` lines | DB and chain are in sync | None — proceed to Step 8 |
| `nonce_reconcile.drift wallet=<name> db_nonce=<N> chain_nonce=<M>` | Chain advanced past DB (lost txs) | See drift decision tree below |
| `nonce_reconcile.skipped reason=rpc_unreachable` | RPC was down at startup | Confirm `RPC_URL_COSTON2` is reachable; restart fwd |

**Drift decision tree** — for each wallet showing `db_nonce < chain_nonce`:

- **(a) Accept — let the watcher reconcile.** If the drift is ≤ 2 nonces
  (representing txs broadcast in the ~10s before the last Litestream WAL
  sync), the receipt watcher will mark those rows `dropped` and the nonce
  manager will self-correct on the next sign-and-send. Safe when the
  missing txs were low-value or idempotent operations.

- **(b) Manual fill.** Send a zero-value self-send via another client
  (e.g., `cast send` from the Foundry toolkit) using the wallet's raw
  private key to advance the on-chain nonce to match the DB state. Use
  only when you have a strong reason to preserve the DB's nonce baseline
  (e.g., outstanding replacement transactions with specific nonces).

- **(c) Reject the restored state.** If the drift is large (> 10 nonces or
  involves high-value transactions), the restored state may represent an
  unsafe baseline. Stop the restore, escalate to the Reviewer, and
  consider manual forensics before resuming signing.

**Pass criterion:**

```sh
# No unresolved drift warnings after startup
docker logs fwd 2>&1 | grep 'nonce_reconcile.drift' | wc -l | xargs -I {} test {} -eq 0
echo $?  # 0 = pass (no drift), non-zero = drift present (see decision tree)
```

Note: a non-zero result here is not a hard failure if the drift is within
acceptable bounds and option (a) applies. Record the drift magnitude in
your restore log.

---

## Step 8 — Confirm signing works against the restored state

Issue one `/v1/sign-and-send` to verify the full custody chain (SQLite
restore → Vault decrypt → sign → broadcast) is functional:

```sh
# Use an existing caller API key; or create a new one if callers were lost.
CALLER_KEY=<caller-api-key>
WALLET=<wallet-name-from-restored-state>
ADDR=<wallet-address-from-step-6-inventory>

curl -sf -X POST http://127.0.0.1:8080/v1/sign-and-send \
    -H "Authorization: Bearer $CALLER_KEY" \
    -H 'Content-Type: application/json' \
    -d "{
        \"wallet\": \"$WALLET\",
        \"chain\": 114,
        \"to\": \"$ADDR\",
        \"value_wei\": \"0\",
        \"data\": \"0x\"
    }" | python3 -m json.tool
```

Expected response: `{"tx_id": "...", "hash": "0x...", "nonce": <N>}`.

Wait ~15 seconds for mining, then verify status:

```sh
TX_ID=<tx_id-from-response>
curl -sf -H "Authorization: Bearer $CALLER_KEY" \
    "http://127.0.0.1:8080/v1/transactions/$TX_ID" | python3 -m json.tool
```

Expected: `"status": "mined"`.

**Pass criterion:**

```sh
curl -sf -H "Authorization: Bearer $CALLER_KEY" \
    "http://127.0.0.1:8080/v1/transactions/$TX_ID" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('status')=='mined' else 1)"
echo $?  # 0 = pass
```

---

## Pass / fail summary

The restore is **complete and verified** if and only if ALL of the following
hold:

| # | Check | Shell snippet | Expected |
|---|---|---|---|
| 1 | `backup` volume has Litestream replica + ≥1 vault snapshot | `docker run --rm -v fwd_backup:/b alpine:3.19 sh -c 'test -d /b/state.db.litestream && ls /b/vault-snapshots 2>/dev/null \| grep -qE "^vault-[0-9]{8}T[0-9]{6}Z\.snap$"'; echo $?` | `0` |
| 2 | `state.db` restored into the volume | `docker run --rm -v fwd_fwd-state:/state alpine:3.19 test -s /state/state.db; echo $?` | `0` |
| 3 | `clifwd health` returns vault+fwd ok | `clifwd health \| python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('vault')=='ok' else 1)"; echo $?` | `0` |
| 4 | Wallet inventory matches pre-disaster count | `curl -sf -H "Authorization: Bearer $KEY" http://127.0.0.1:8080/v1/admin/wallets \| python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin).get('wallets') else 1)"; echo $?` | `0` |
| 5 | Caller inventory matches pre-disaster count | `curl -sf -H "Authorization: Bearer $KEY" http://127.0.0.1:8080/v1/admin/callers \| python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin).get('callers') else 1)"; echo $?` | `0` |
| 6 | Nonce drift is within acceptable margin | `docker logs fwd 2>&1 \| grep 'nonce_reconcile.drift' \| wc -l \| xargs -I {} test {} -eq 0; echo $?` | `0` (or document acceptable drift) |
| 7 | `/v1/sign-and-send` returns 200 with tx_id + hash | `curl -sf ... -o /tmp/sar.json; python3 -c "import json; d=json.load(open('/tmp/sar.json')); sys.exit(0 if 'tx_id' in d else 1)"; echo $?` | `0` |
| 8 | Tx mines on Coston2 within 60 seconds | `curl -sf ... /v1/transactions/$TX_ID \| python3 -c "...status=='mined'..."; echo $?` | `0` |

**Criteria 4 or 5 failure:** Litestream missed rows — surface to Reviewer
for triage before resuming any signing.

**Criterion 6 non-zero:** document the drift count; apply the drift
decision tree in Step 7; do not block restore completion if drift is within
acceptable bounds per option (a).

**Criterion 7 or 8 failure:** signing path is broken post-restore — most
likely cause is a Vault authentication failure (AppRole role_id/secret_id
mismatch after re-init). Re-run `vault-init.sh` and update `.env`.

---

## RTO target

**Target:** ≤ 30 minutes from "host disaster" to "first successful
`/v1/sign-and-send`" (per `architecture.md:598`).

**Approximate step timings (estimates — to be measured at Phase 6 GA drill):**

| Step | Activity | Estimated time |
|---|---|---|
| Prerequisites | Off-host copy of `backup` volume to new host (operator-driven, out of band) | varies |
| Steps 1–2 | Confirm backup contents, spin up clean stack | 1–2 min |
| Step 3 | Litestream restore from local replica | 1–3 min |
| Step 4 | Vault Raft snapshot restore + dummy-init/unseal-with-D6 dance | 4–8 min |
| Step 5 | fwd + vault-snapshot restart against restored Vault | 1–2 min |
| Steps 6–8 | Smoke test + reconcile + signing verify | 3–5 min |
| **Total (post-transport)** | | **10–20 min** |

The off-host transport (prerequisite) is excluded from the RTO budget — it
varies wildly by tool and bandwidth. The 30-min target applies to the
"backup is available on the new host → signing again" window.

RTO measurement (actual wall-clock) is deferred to Phase 6 GA, when the
drill is executed end-to-end against a fresh Docker host. At GA, the
measured RTO is recorded as an addendum to this runbook.

---

## What this runbook deliberately does NOT cover

- **Off-host transport of the `backup` volume.** Operator-driven and
  out-of-band per the v0.4.3 reversion (CLAUDE.md). The operator picks
  rsync over SSH / restic / borg / NAS / USB / whatever; fwd does not
  ship a transport tool and does not script the schedule.
- **Cloud-S3 backup.** Reverted at v0.4.3. If a future deployment wants
  cloud backup, the path forward is a separate sidecar or an operator-side
  `restic`/`rclone` against the `backup` volume — NOT modifying fwd.
- **`clifwd reconcile` CLI command.** Currently only lifespan-startup
  reconcile exists. A dedicated `clifwd reconcile` command is Phase 7 or
  a Phase 6 follow-up.
- **Automated RTO measurement.** Phase 6 GA drill.
- **Multi-host restore.** Each host has its own `backup` volume and is
  restored independently using this same procedure.

## When this runbook is wrong

- Litestream's `restore` subcommand syntax changes — update Step 3.
- Vault's `operator raft snapshot restore` API changes — update Step 4(d).
- The `GET /v1/admin/wallets` response shape changes — update Step 6 pass
  criteria.
- The `backup` volume name or mount path changes in `docker-compose.yml` —
  update Steps 1, 3, 4(a) accordingly.
