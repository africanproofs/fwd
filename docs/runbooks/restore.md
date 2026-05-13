# Restore runbook — fwd state from Litestream S3 replica (Phase 6)

> This runbook documents the disaster-recovery procedure for fwd: restore
> `state.db` from the Litestream S3 replica, reseal/unseal Vault, and
> confirm a working signing path against the restored state.
>
> **Where this fits in Phase 6 (ship 2 — v0.4.2):**
>
> - **SQLite restore (Steps 1–3, 6–8):** complete — Litestream continuously
>   replicates `state.db` to Scaleway Object Storage; these steps work today.
> - **Vault restore (Step 4):** complete — vault-snapshot sidecar (v0.4.2)
>   ships nightly Raft snapshots to the same bucket. Restore preserves the
>   original `fwd-master` Transit key and the original AppRole credentials,
>   so wallet ciphertexts in SQLite remain decryptable post-restore.
>
> **RTO target:** ≤ 30 minutes from a clean host (per `architecture.md:598`).
> Actual wall-clock measurement happens at Phase 6 GA (drill execution).
>
> **Related runbooks:**
> - `docs/runbooks/vault-init.md` — first-run Vault initialization and unseal
> - `docs/runbooks/phase-5-verification.md` — signing path smoke test

---

## Prerequisites

Before starting:

1. **Scaleway bucket provisioned.** The S3 bucket referenced by
   `LITESTREAM_S3_BUCKET` in `.env` exists and has at least one Litestream
   snapshot. Confirm from the Scaleway console or via Step 1 below.

2. **Environment populated.** Your `.env` has all five required Litestream
   S3 vars set with real credentials:

   ```
   LITESTREAM_S3_ENDPOINT=https://s3.fr-par.scw.cloud
   LITESTREAM_S3_BUCKET=ap-fwd-backups
   LITESTREAM_S3_REGION=fr-par
   LITESTREAM_S3_ACCESS_KEY_ID=<real-key>
   LITESTREAM_S3_SECRET_ACCESS_KEY=<real-secret>
   ```

   Also set `FWD_VAULT_ROLE_ID`, `FWD_VAULT_SECRET_ID`, `FWD_ADMIN_KEY`,
   and the caller API key(s) for any callers you need to smoke-test.

3. **fwd stack is DOWN** (this is a restore — running `litestream restore`
   against a live, open SQLite WAL is unsafe).

   ```sh
   docker compose ps
   # Confirm: all services show "Exit" or are absent
   ```

4. **D6 unseal shares accessible.** You will need 3 of the 5 shares from
   the `decisions.md` D6 distribution to unseal Vault in Step 5. Retrieve
   them before starting the restore clock.

5. **Host has `docker`, `docker compose`, and optionally `litestream`
   installed.** The primary restore path uses `docker exec` and requires
   only Docker.

---

## Step 1 — Confirm S3 has snapshots

Before destroying volumes, verify the S3 replica has usable data:

```sh
# Source your env vars so the litestream binary can reach the bucket.
export LITESTREAM_S3_ENDPOINT LITESTREAM_S3_BUCKET LITESTREAM_S3_REGION \
       LITESTREAM_S3_ACCESS_KEY_ID LITESTREAM_S3_SECRET_ACCESS_KEY \
       LITESTREAM_S3_PATH

BUCKET=$(grep -E '^LITESTREAM_S3_BUCKET=' .env | cut -d= -f2-)
PATH_=$(grep -E '^LITESTREAM_S3_PATH=' .env | cut -d= -f2- || echo "state.db")

# If you have litestream installed locally:
litestream snapshots \
    -config ./config/litestream/litestream.yml \
    /data/state.db

# OR, start a temporary litestream container against the same config
# (no fwd-state volume needed for a read-only snapshots query):
docker run --rm \
    --env-file .env \
    -v "$(pwd)/config/litestream/litestream.yml:/etc/litestream.yml:ro" \
    litestream/litestream:0.3.13 \
    snapshots -config /etc/litestream.yml /data/state.db
```

**Pass criterion:**

```sh
# At least one snapshot line in output (column 1 = replica name, column 3 = size)
[ "$(docker run --rm \
    --env-file .env \
    -v "$(pwd)/config/litestream/litestream.yml:/etc/litestream.yml:ro" \
    litestream/litestream:0.3.13 \
    snapshots -config /etc/litestream.yml /data/state.db 2>/dev/null | wc -l)" -gt 1 ]
echo $?  # 0 = pass
```

If no snapshots are returned: the bucket is empty or credentials are wrong.
Do NOT proceed — there is no restorable state.

---

## Step 2 — Spin up a fresh fwd stack with clean volumes

Destroy existing volumes so the restore lands into a clean state:

```sh
docker compose down --volumes
# Removes: fwd_vault-data, fwd_fwd-state, fwd_litestream-replica
```

Start the stack (all three services: vault, fwd, litestream):

```sh
docker compose up -d
```

At this point:
- `fwd-vault` is running but uninitialized (its volume is empty).
- `fwd` has started (it will fail to contact Vault — that's expected; it
  restarts until unsealed).
- `fwd-litestream` is running and will begin replicating to S3 once fwd's
  `state.db` is in place. It does NOT yet restore automatically.

```sh
docker compose ps
# Expected: vault (healthy), fwd (restarting is OK), litestream (running)
```

---

## Step 3 — Restore `state.db` from S3

The SQLite restore writes directly into the `fwd-state` volume at `/data/state.db`.

**Primary method (docker exec into the running litestream container):**

```sh
BUCKET=$(grep -E '^LITESTREAM_S3_BUCKET=' .env | cut -d= -f2-)
S3PATH=$(grep -E '^LITESTREAM_S3_PATH=' .env | cut -d= -f2- || echo "state.db")

docker exec fwd-litestream litestream restore \
    -o /data/state.db \
    "s3://${BUCKET}/${S3PATH}"
```

Expected: Litestream prints progress lines ending with `restore complete`.
`/data/state.db` now exists in the `fwd-state` volume.

**Fallback method (host-side litestream binary + docker cp):**

Use this if the `fwd-litestream` container is unavailable or unhealthy:

```sh
litestream restore \
    -config ./config/litestream/litestream.yml \
    -o /tmp/fwd-state-restored.db \
    /data/state.db
docker cp /tmp/fwd-state-restored.db fwd:/data/state.db
docker exec fwd chown fwd:fwd /data/state.db
```

**Pass criterion:**

```sh
# state.db exists and is non-empty in the volume
docker exec fwd-litestream test -s /data/state.db
echo $?  # 0 = pass
```

---

## Step 4 — Restore Vault state from S3 Raft snapshot

The vault-snapshot sidecar (Phase 6 ship 2, v0.4.2) uploads a Vault Raft
snapshot to `s3://${LITESTREAM_S3_BUCKET}/${VAULT_SNAPSHOT_S3_PATH:-vault-snapshots}/vault-<ts>.snap`
on a configurable interval (default 24h). The restore procedure:

**(a) Locate and download the latest snapshot.**

```sh
BUCKET=$(grep -E '^LITESTREAM_S3_BUCKET=' .env | cut -d= -f2-)
PREFIX=$(grep -E '^VAULT_SNAPSHOT_S3_PATH=' .env | cut -d= -f2- || echo "vault-snapshots")
ENDPOINT=$(grep -E '^LITESTREAM_S3_ENDPOINT=' .env | cut -d= -f2-)

export AWS_ACCESS_KEY_ID=$(grep -E '^LITESTREAM_S3_ACCESS_KEY_ID=' .env | cut -d= -f2-)
export AWS_SECRET_ACCESS_KEY=$(grep -E '^LITESTREAM_S3_SECRET_ACCESS_KEY=' .env | cut -d= -f2-)
export AWS_DEFAULT_REGION=$(grep -E '^LITESTREAM_S3_REGION=' .env | cut -d= -f2-)

# Find the most recent snapshot (filenames are vault-<UTC-timestamp>.snap)
LATEST=$(aws --endpoint-url "${ENDPOINT}" \
    s3 ls "s3://${BUCKET}/${PREFIX}/" \
    | awk '{print $4}' \
    | grep -E '^vault-[0-9]{8}T[0-9]{6}Z\.snap$' \
    | sort | tail -1)

[ -z "${LATEST}" ] && { echo "ERROR: no snapshots in s3://${BUCKET}/${PREFIX}/"; exit 1; }

aws --endpoint-url "${ENDPOINT}" \
    s3 cp "s3://${BUCKET}/${PREFIX}/${LATEST}" /tmp/vault.snap
docker cp /tmp/vault.snap fwd-vault:/tmp/vault.snap
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

**On the v0.4.2 honest doctrine:** The pre-v0.4.2 fallback (fresh
`vault-init.sh` run with OLD D6 shares) is no longer needed and would NOT
work — running a fresh `vault operator init` produces a NEW seal config,
which makes the OLD D6 shares useless and the existing wallet ciphertexts
unreadable (the fwd-master Transit key is regenerated under the new seal).
Always restore from snapshot.

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
| 1 | S3 has at least one snapshot | `docker run --rm --env-file .env -v "$(pwd)/config/litestream/litestream.yml:/etc/litestream.yml:ro" litestream/litestream:0.3.13 snapshots -config /etc/litestream.yml /data/state.db 2>/dev/null \| wc -l \| xargs -I {} test {} -gt 1; echo $?` | `0` |
| 2 | `state.db` restored into the volume | `docker exec fwd-litestream test -s /data/state.db; echo $?` | `0` |
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
| Prerequisites | Retrieve D6 shares, confirm bucket | 3–5 min |
| Steps 1–2 | Confirm snapshots, spin up clean stack | 1–2 min |
| Step 3 | Litestream restore (depends on DB size) | 1–3 min |
| Step 4 | Vault re-init (vault-init.md steps 1–5) | 5–10 min |
| Step 5 | Unseal + fwd restart | 1–2 min |
| Steps 6–8 | Smoke test + reconcile + signing verify | 3–5 min |
| **Total** | | **14–27 min** |

RTO measurement (actual wall-clock) is deferred to Phase 6 GA, when the
drill is executed end-to-end against a fresh Docker host. At GA, the
measured RTO is recorded as an addendum to this runbook.

---

## What this runbook deliberately does NOT yet cover

- **Vault Raft snapshot restore** — next Phase 6 ship. Until that lands,
  Step 4 requires a fresh `vault-init.md` run with the OLD D6 shares.
- **`clifwd reconcile` CLI command** — currently only lifespan-startup
  reconcile exists. A dedicated `clifwd reconcile` command is Phase 7 or a
  Phase 6 follow-up.
- **Automated RTO measurement** — Phase 6 GA drill.
- **Multi-host restore** (two fwd instances sharing one bucket via
  `LITESTREAM_S3_PATH=<host>/state.db`) — same procedure, run once per host.

## When this runbook is wrong

- Litestream `snapshots` subcommand syntax changes — update Step 1.
- The restore command gains a `-config` flag variant preferred over the
  direct S3 path — update Step 3.
- Vault snapshot/restore lands (next Phase 6 ship) — amend Step 4 in-place
  with the Vault Raft snapshot restore procedure.
- The `GET /v1/admin/wallets` response shape changes — update Steps 6 pass
  criteria accordingly.
