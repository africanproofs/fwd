# Phase 5 verification — manual operator gate (v0.4.0)

> ℹ️ **Historical Phase-5 record (v0.4.0).** Predates Vault retirement (v1.0.0a1) and
> the zero-egress turn (v1.1.0a9): references to `/v1/sign-and-send`, a receipt
> watcher, and the chain-reconcile are honest history of that phase, not current
> behaviour. Kept per Core invariant #18.

> Phase 5 GA verification: 10 concurrent `/v1/sign-and-send` calls against
> the same wallet on Coston2 land in monotonically increasing nonces with
> no gaps and no duplicates. This is the operator-driven equivalent of the
> v0.2.0 spike for the concurrent-write path that v0.4.0a5's `BEGIN
> IMMEDIATE` nonce manager guarantees.
>
> Per Core invariant #14: real-RPC verification is the validation. Mocks
> lie. The unit gate at v0.4.0a5 (`test_concurrent_reservations_are_monotonic_no_gaps`)
> proves the SQLite contract; this runbook proves the chain contract.
>
> This runbook is mandatory before tagging v0.4.0 as verified (the v0.4.1
> Reviewer-only addendum records the on-chain proof).

## What this runbook does and does NOT verify

**Verified by this runbook (Scenario 1):** under concurrent submission,
fwd reserves a unique monotonic nonce per call, signs, broadcasts, and
records a `transactions` row whose nonce matches the on-chain `from`
recovery. The receipt watcher transitions each tx to `status='mined'`
after mining; `nonce_repo.last_confirmed` advances accordingly.

**Already verified by unit tests (NOT in this runbook):**

- BEGIN IMMEDIATE serialization (v0.4.0a5 `test_concurrent_reservations_are_monotonic_no_gaps`).
- Receipt-status transitions on mock receipts (v0.4.0a6 `test_process_tx_mined_when_receipt_status_ok` + `test_process_tx_failed_when_receipt_status_reverted`).
- Replacement math + bump-and-resubmit (v0.4.0a6 `test_replace_tip_bump_math` + `test_process_tx_replaces_when_stuck_under_cap`).
- Cancellation propagation (v0.4.0a6 `test_watch_receipts_cancellation_propagates_cleanly`).

**Deferred (Scenario 2 — live low-gas replacement on Coston2):** requires
configuring fwd to submit txs below the Coston2 mempool floor (achievable
by making `_DEFAULT_TIP_WEI` configurable via env). The unit-test
coverage of the replacement path at a6 is sufficient for Phase 5 GA;
live replacement verification can land in a Phase 5 follow-up patch
(v0.4.1+) or as part of Phase 7 ops runbook work.

## Prerequisites

- `docker compose ps` shows `fwd`, `fwd-vault`, `fwd-litestream` all up.
- `fwd-vault` is unsealed (`docker exec fwd-vault vault status` → `Sealed: false`).
- `.env` has populated `FWD_VAULT_ROLE_ID`, `FWD_VAULT_SECRET_ID`, `FWD_ADMIN_KEY`.
- `RPC_URL_COSTON2` in `.env` points at a reachable Coston2 RPC (default: `https://coston2-api.flare.network/ext/C/rpc`).
- `FWD_WATCHER_DISABLED` is NOT set (or is `0`) — the watcher must run.
- Host has `curl`, `jq`, and `python3` available.

## Steps

### 1. Confirm the receipt watcher started.

```sh
docker logs fwd 2>&1 | grep 'receipt_watcher.started' | tail -1
```

Expected: one line with `receipt_watcher.started` and the configured intervals/thresholds. If empty, the watcher did not start — check `FWD_WATCHER_DISABLED` env and `docker logs fwd` for errors before continuing.

### 2. Create a wallet for the gate run.

```sh
KEY=$(grep -E '^FWD_ADMIN_KEY=' .env | cut -d= -f2-)
curl -sf -X POST http://127.0.0.1:8080/v1/admin/wallets \
    -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' \
    -d '{"name":"phase5-gate","policy_path":"phase5-gate"}' | jq .
```

Capture the returned `address` — call it `ADDR`.

### 3. Fund the wallet from the Coston2 faucet.

Visit https://faucet.flare.network/coston2 and submit `ADDR`. Wait ~10 seconds for the faucet tx to confirm.

Verify funding:

```sh
curl -s -X POST https://coston2-api.flare.network/ext/C/rpc \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$ADDR\",\"latest\"],\"id\":1}" \
    | jq -r '.result'
```

Expected: a non-zero hex string (e.g., `0xde0b6b3a7640000` for 1 C2FLR).

### 4. Create a caller and capture the API key.

```sh
CALLER_KEY=$(curl -sf -X POST http://127.0.0.1:8080/v1/admin/callers \
    -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' \
    -d '{"name":"phase5-gate-caller","policy_path":"phase5-gate"}' \
    | jq -r '.api_key')
echo "CALLER_KEY=$CALLER_KEY"
```

The `CALLER_KEY` is returned ONCE — capture it now or rerun step 4 (with a different name).

### 5. Issue 10 concurrent sign-and-send requests.

Write a tiny helper script and run it. The script fires 10 self-send transactions in parallel and dumps each response to a temp file.

```sh
cat > /tmp/phase5-fire.sh <<EOF
#!/usr/bin/env bash
set -eu
mkdir -p /tmp/phase5
rm -f /tmp/phase5/tx-*.json
for i in \$(seq 1 10); do
  curl -s -X POST http://127.0.0.1:8080/v1/sign-and-send \\
    -H "Authorization: Bearer $CALLER_KEY" \\
    -H 'Content-Type: application/json' \\
    -d "{\"wallet\":\"phase5-gate\",\"chain\":114,\"to\":\"$ADDR\",\"value_wei\":\"0\",\"data\":\"0x\"}" \\
    -o "/tmp/phase5/tx-\$i.json" &
done
wait
echo "all 10 fired"
EOF
chmod +x /tmp/phase5-fire.sh
/tmp/phase5-fire.sh
```

Expected: 10 background curls complete in ~1-3 seconds. Each `/tmp/phase5/tx-N.json` contains `{"tx_id": "...", "hash": "0x...", "nonce": N}` (N = 0 through 9 — or starting from whatever nonce the wallet was at).

### 6. Verify nonces are monotonic with no gaps and no duplicates.

```sh
jq -r '"\(.nonce) \(.tx_id) \(.hash)"' /tmp/phase5/tx-*.json \
    | sort -n -k1 \
    | tee /tmp/phase5/sorted.txt
```

Expected output (10 lines, nonces sequential — actual start nonce depends on prior wallet history):

```
0 <uuid-0> 0x<hash-0>
1 <uuid-1> 0x<hash-1>
2 <uuid-2> 0x<hash-2>
3 <uuid-3> 0x<hash-3>
4 <uuid-4> 0x<hash-4>
5 <uuid-5> 0x<hash-5>
6 <uuid-6> 0x<hash-6>
7 <uuid-7> 0x<hash-7>
8 <uuid-8> 0x<hash-8>
9 <uuid-9> 0x<hash-9>
```

**Pass criteria for this step:**

```sh
# 10 distinct nonces
[ "$(awk '{print $1}' /tmp/phase5/sorted.txt | sort -u | wc -l)" -eq 10 ]
# Sequential — no gaps
awk '{print $1}' /tmp/phase5/sorted.txt | python3 -c \
    "import sys; xs = [int(l) for l in sys.stdin]; \
     sys.exit(0 if xs == list(range(min(xs), min(xs)+10)) else 1)"
# 10 distinct tx_ids
[ "$(awk '{print $2}' /tmp/phase5/sorted.txt | sort -u | wc -l)" -eq 10 ]
# 10 distinct hashes
[ "$(awk '{print $3}' /tmp/phase5/sorted.txt | sort -u | wc -l)" -eq 10 ]
```

All four checks must exit 0.

### 7. Wait for mining and verify on-chain.

```sh
sleep 30  # ~15 Coston2 blocks
```

For each tx_id in the sorted list, query its on-chain status:

```sh
for tx_id in $(awk '{print $2}' /tmp/phase5/sorted.txt); do
    curl -sf -H "Authorization: Bearer $CALLER_KEY" \
        "http://127.0.0.1:8080/v1/transactions/$tx_id" \
        | jq -r '"\(.tx_id) \(.status) \(.nonce)"'
done
```

Expected: all 10 lines show `status=mined`. If any show `submitted` after a 30-second wait, the watcher hasn't ticked yet — wait another 10 seconds and re-query. If any show `failed`, **stop** and inspect `docker logs fwd | grep tx_id=<the-failed-tx>` for the receipt status (status=`0x0` means the chain reverted the tx — a fwd code issue).

### 8. Verify the on-chain `from` matches the wallet address.

Pick the first hash from the sorted output, query the Coston2 explorer:

```sh
H1=$(awk 'NR==1{print $3}' /tmp/phase5/sorted.txt)
curl -s -X POST https://coston2-api.flare.network/ext/C/rpc \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$H1\"],\"id\":1}" \
    | jq '.result | {from, to, nonce, blockHash, blockNumber}'
```

Expected:
- `from = $ADDR` (in some case — comparisons are case-insensitive for Ethereum addresses; or use `lower()` if matching exactly).
- `to = $ADDR` (self-send).
- `nonce = "0x0"` (or whatever the start nonce was, in hex).
- `blockHash` is non-null.

### 9. Verify `nonce_repo.next_nonce` advanced correctly.

Inspect the nonces table:

```sh
docker exec fwd sqlite3 /data/state.db \
    "SELECT wallet, chain, next_nonce, last_confirmed FROM nonces WHERE wallet='phase5-gate'"
```

Expected: `phase5-gate|114|10|9` (or `next_nonce = start + 10`, `last_confirmed = start + 9`).

### 10. Browser spot-check on the Coston2 explorer.

Open https://coston2-explorer.flare.network/address/$ADDR and confirm the address page shows 10 outgoing transactions with nonces 0-9 (or your starting nonce through nonce+9) — all sent to the same `to` address (self-send), all mined within ~1 minute of step 5.

## Pass / fail summary

The Phase 5 GA verification gate is **passed** if and only if:

1. The receipt watcher started (step 1).
2. 10 concurrent `/v1/sign-and-send` calls returned 10 distinct nonces, sequential, no gaps, no duplicates (step 6).
3. All 10 transitioned to `status=mined` within 60 seconds (step 7).
4. The first on-chain hash recovers to the wallet address (step 8).
5. `nonces.next_nonce` advanced by exactly 10 and `last_confirmed` advanced by 9 (step 9).
6. The Coston2 explorer confirms 10 outgoing transactions at the address (step 10).

Any failure: do NOT mark v0.4.0 as verified. Capture `docker logs fwd 2>&1 | tail -200` and `/tmp/phase5/*` artifacts, surface to the Reviewer for triage.

## After a clean pass

The Reviewer files a v0.4.1 Reviewer-only addendum recording:
- The wallet address used (it's public — already on-chain).
- The 10 tx hashes with their on-chain block numbers.
- The runbook git-sha that was followed.
- A short note: "Phase 5 GA verification gate met live on Coston2 at <date>."

This mirrors v0.3.1's addendum to v0.3.0-phase-3c-sign-and-send.

## Scenario 2 (deferred): live low-gas replacement

The watcher's replacement-on-stuck path is unit-tested at v0.4.0a6 (`test_process_tx_replaces_when_stuck_under_cap` + `test_replace_tip_bump_math`). Live verification requires either:

(a) Making `_DEFAULT_TIP_WEI` configurable via an env var (e.g., `FWD_DEFAULT_TIP_WEI`, default 1 gwei) so the operator can submit a tx with tip far below the Coston2 mempool floor; OR

(b) A deliberate orchestration where fwd submits during a fee spike (operationally unreliable).

Path (a) is a 5-line change (new `Settings` field + replace the module-level constant in `app/sign_and_send.py` + `app/receipt_watcher.py`). The runbook step would be:

```sh
# Override to 10 wei (well below Coston2 mempool floor of ~1 gwei).
echo "FWD_DEFAULT_TIP_WEI=10" >> .env
echo "FWD_WATCHER_STUCK_THRESHOLD_SEC=10" >> .env  # impatient
docker compose up -d --build fwd  # pick up the env

# Submit one sign-and-send. Watch the watcher cycle through retries.
# Each retry's hash appears in transaction_hashes at sequence_num 1..5.
# After 5 retries, status='failed' (the bumps never reach the floor).
```

This stretch-goal verification is deferred to a Phase 5 follow-up or Phase 7 ops runbook work. Phase 5 GA is met by Scenario 1 alone.

## Operational notes

- The 10-concurrent fire is bursty — if your laptop's loopback or the Coston2 RPC is slow, increase the wait in step 7 to 60s.
- Coston2 fee market is generally low; the default `_DEFAULT_TIP_WEI` of 1 gwei mines within 1-2 blocks. If your run sees txs stuck at `submitted` indefinitely, check Coston2 network status (https://flare-explorer.flare.network/) for chain stalls.
- `clifwd wallets list` (v0.4.0a7) confirms the wallet exists post-step 2; `clifwd callers list` confirms the caller exists post-step 4.
