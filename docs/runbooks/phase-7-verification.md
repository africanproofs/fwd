# Phase 7 verification — manual operator gate (v0.5.0)

> ℹ️ **Historical Phase-7 record (v0.5.0).** Predates Vault retirement (v1.0.0a1) and
> the zero-egress turn (v1.1.0a9): references to `/v1/sign-and-send` and Vault are
> honest history of that phase's GA gate, not current behaviour. Kept per Core
> invariant #18.

> Phase 7 GA verification: against a live Coston2 RPC, fwd enforces the
> D14 default-deny policy on `/v1/sign-and-send` — every one of the 10
> D14 evaluation steps refuses with HTTP 403 and writes a `decision=
> "denied"` audit row WITHOUT broadcasting; a sanctioned ERC-20
> `transfer` is approved, signed, broadcast, and mines `status=0x1`;
> an `Idempotency-Key` replay returns the cached `tx_id` with no second
> on-chain tx; admin actions write hash-chained audit rows with no
> secret; and `clifwd audit verify` walks the whole chain clean.
>
> Per Core invariant #14: real-RPC verification is the validation.
> Mocks lie. The a6 unit suite (`tests/unit/test_sign_and_send_policy.py`)
> proves the 10-vector deny matrix against AsyncMock RPC; this runbook
> proves the same contract against live Coston2 + the real Vault
> custody path + the real D16 hash chain.
>
> Operator-gated decisions (2026-05-16): approved/mined target =
> ERC-20 `transfer` on a Coston2 test token; live matrix scope = the
> FULL 10-vector D14 deny matrix (not a representative subset).
>
> This runbook is mandatory before tagging the Phase 7 GA gate as met.
> The verification-met addendum (on-chain evidence) is recorded by a
> Reviewer-only follow-up to `docs/history/0.5.0-phase-7-ga.md`, exactly
> as v0.4.1 recorded the Phase 5 proof and v0.4.6 the Phase 6 proof.

## Drill-surfaced amendments (v0.5.1 — read FIRST)

The first live execution (2026-05-16) surfaced eight doctrine↔substrate
drifts (see `docs/history/0.5.1-phase-7-ga-substrate-and-partial-evidence.md`).
The substrate fixes shipped in v0.5.1; these amendments are now binding:

1. **Image must be Phase-7.** The deployed `fwd:dev` must be built from
   Phase-7 source (`docker compose build fwd` from a tree at ≥ v0.5.0a7).
   A pre-Phase-7 image has no policy engine and silently "works" by
   lacking `_startup_policy_load`.
2. **Substrate must be wired (v0.5.1):** Dockerfile `COPY config/`
   (ships the ABI registry) + a `/usr/local/bin/clifwd` shim;
   docker-compose.yml fwd `environment:` `FWD_POLICY_PATH=/etc/fwd/policy.yaml`
   + `FWD_ABIS_DIR=/app/config/abis` and `volumes:`
   `./config/policy.yaml:/etc/fwd/policy.yaml:ro`. If `poetry install`
   aborts on a stale lock, run `poetry lock --no-update` first.
3. **Step 0.5 — revoke pre-existing active callers.** D14 startup
   fail-fast checks **every active DB caller** against the loaded
   policy. Before restarting onto the minimal gate policy, revoke any
   active callers not in it: `GET /v1/admin/callers` →
   `DELETE /v1/admin/callers/<name>` for each `revoked_at == null`
   that the gate policy does not declare. Otherwise fwd refuses to boot.
4. **`clifwd` invocation.** As of v0.5.1 `docker exec fwd clifwd …`
   works. On an older image without the shim, use:
   `docker exec fwd python -c "from fwd.cli.main import app; app()" <args>`.
5. **No `sqlite3` in the slim image.** Inspect DB state via `clifwd`
   (`audit tail/show/verify`) or the HTTP admin/transactions API, not
   `docker exec fwd sqlite3`.
6. **EOA target is acceptable.** If `$ERC20_TOKEN` has no contract code
   (an EOA), the gate is still fully valid for its purpose: fwd decodes
   `transfer()` by selector regardless, so decode→policy→sign→broadcast
   →custody-recovery is proven. Only "a real ERC-20 ledger entry
   changed" is not asserted; scope the V10 evidence accordingly.

## What this runbook does and does NOT verify

**Verified by this runbook:**

- D14 steps 2–9 each refuse a crafted live request with HTTP 403, the
  correct `PolicyDenied` step, a `sign-and-send` audit row with
  `decision="denied"`, and **no broadcast** (the wallet's on-chain
  nonce does not advance).
- D14 step 1 (caller→binding / orphan-caller fail-fast) is enforced at
  startup: a policy.yaml missing an active caller makes fwd refuse to
  boot and leaves a `policy-load` `decision="error"` row.
- D14 step 10 (Allow): a sanctioned ERC-20 `transfer` to the pinned
  recipient is signed via the Vault custody path, broadcast, and mines
  `status=0x1`; the on-chain `from` recovers to the gate wallet.
- D14 idempotency clause: replaying the approved request with the same
  `Idempotency-Key` returns HTTP 200 + the SAME `tx_id`, writes a
  `sign-and-send-duplicate` row, and produces NO second on-chain tx.
- D16 admin-action authorship: `POST /v1/admin/{wallets,callers}`
  write `wallet-create` / `caller-create` rows with `caller=NULL` and
  NO secret (no api_key plaintext, no key_hash, no ciphertext).
- D16 tamper-evidence: `docker exec fwd clifwd audit verify` walks the
  full chain (policy-load + every denied + the approved + the
  duplicate + the admin rows) and exits 0.

**Already verified by unit tests (NOT re-proven live here):**

- The exhaustive a6 10-vector matrix with `rpc.send_raw_transaction`
  not-awaited assertions (`tests/unit/test_sign_and_send_policy.py`).
- The a7 admin-audit no-secret assertions against the real generated
  api_key / privkey-hex / ciphertext (`tests/unit/test_admin_audit.py`).
- The a7 replay path under a deny policy + the `find_sign_and_send_seq`
  round-trip (`tests/unit/test_idempotency_replay.py`).

**Out of scope (Phase 10):** `audit-verify-failure` privileged
self-write-on-break; on-chain Merkle anchor; SIGHUP hot-reload.

## Prerequisites

- `docker compose ps` shows `fwd`, `fwd-vault` up; `fwd-vault` unsealed
  (`docker exec fwd-vault vault status` → `Sealed: false`).
- `.env` has `FWD_VAULT_ROLE_ID`, `FWD_VAULT_SECRET_ID`, `FWD_ADMIN_KEY`.
- `RPC_URL_COSTON2` points at a reachable Coston2 RPC
  (`https://coston2-api.flare.network/ext/C/rpc`).
- `FWD_POLICY_PATH` and `FWD_ABIS_DIR` are set (compose default:
  `/etc/fwd/policy.yaml`, `/app/config/abis`). The lifespan policy-load
  is active when `FWD_POLICY_PATH` is set.
- `FWD_WATCHER_DISABLED` is NOT set — the receipt watcher must run so
  the approved tx transitions to `status=mined`.
- Host has `curl`, `jq`, `python3`, and `poetry` (for the calldata
  one-liners; fwd already depends on `eth-abi`/`eth-utils`).
- **ERC-20 token + balance (operator-supplied — the gated decision):**
  pick a Coston2 ERC-20 the gate wallet will hold a small balance of.
  The recommended concrete choice is Coston2 **WNat (wrapped C2FLR)**:
  resolve its address from the canonical Flare ContractRegistry
  (`0xaD67FE66660Fb8dFE9d6b1b4240d8650e30F6019`, identical on all Flare
  networks) and fund the gate wallet by wrapping (a one-off `deposit()`
  the operator sends from any funded account, then transferring some
  WNat to the gate wallet address — OR by sending the gate wallet any
  test ERC-20 they control). Set `ERC20_TOKEN` below to that address;
  the runbook treats it as an opaque parameter. The pinned transfer
  recipient is the public AP claim-recipient
  `0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294`.

## Environment variables for this run

```sh
export FWD=http://127.0.0.1:8080
ADMIN_KEY=$(grep -E '^FWD_ADMIN_KEY=' .env | cut -d= -f2-)
ERC20_TOKEN="0x...."          # operator-supplied Coston2 ERC-20 (see Prerequisites)
RECIPIENT="0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"   # pinned in policy
WRONG_RECIPIENT="0x000000000000000000000000000000000000dEaD"
NOT_A_CONTRACT="0x00000000000000000000000000000000DeaDBeef"
```

## Step 0 — write the gate policy.yaml

The policy is intentionally split across multiple callers/wallets so
the rate vectors (steps 8, 9) can be isolated from each other and from
the value/arg vectors. Write this to the host path that
`FWD_POLICY_PATH` resolves to (the compose mount of
`/etc/fwd/policy.yaml`), substituting `$ERC20_TOKEN`:

```yaml
version: 1

callers:
  phase7-gate-caller:        # steps 2-7 + approved + idempotency
    policy_path: perm/phase7-gate
  phase7-cr-caller:          # step 8 (caller rate)
    policy_path: perm/phase7-caller-rate
  phase7-wr-caller:          # step 9 (wallet rate)
    policy_path: perm/phase7-wallet-rate

wallets:
  phase7-gate:
    policy_path: wc/phase7-gate
  phase7-wr-wallet:
    policy_path: wc/phase7-wallet-rate
  phase7-offlist:            # step 7 (NOT in any wallet_allowlist)
    policy_path: wc/phase7-gate

permissions:
  perm/phase7-gate:
    contracts:
      "ERC20_TOKEN_HERE":
        abi: erc20
        methods:
          "transfer(address,uint256)":
            max_value_wei: "0"
            arg_predicates:
              to: "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"
    wallet_allowlist:
      - phase7-gate
    rate:
      per_hour: 100
      per_day: 200
  perm/phase7-caller-rate:           # tight CALLER rate
    contracts:
      "ERC20_TOKEN_HERE":
        abi: erc20
        methods:
          "transfer(address,uint256)":
            max_value_wei: "0"
            arg_predicates:
              to: "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"
    wallet_allowlist:
      - phase7-gate
    rate:
      per_hour: 1
      per_day: 2
  perm/phase7-wallet-rate:           # generous caller, tight WALLET
    contracts:
      "ERC20_TOKEN_HERE":
        abi: erc20
        methods:
          "transfer(address,uint256)":
            max_value_wei: "0"
            arg_predicates:
              to: "0x7c3579aB3E647395c96a1EfC98aF9A31C5Ecc294"
    wallet_allowlist:
      - phase7-wr-wallet
    rate:
      per_hour: 100
      per_day: 200

wallet_constraints:
  wc/phase7-gate:
    max_aggregate_value_wei_per_day: "0"
    rate:
      per_hour: 100
      per_day: 200
  wc/phase7-wallet-rate:
    max_aggregate_value_wei_per_day: "0"
    rate:
      per_hour: 1
      per_day: 2
```

Replace both `ERC20_TOKEN_HERE` occurrences with `$ERC20_TOKEN`'s value
(lowercase or checksum — D14 step 2 matches case-insensitively).

Restart fwd to load it:

```sh
docker compose restart fwd
docker logs fwd 2>&1 | grep -E 'lifespan\.(policy_loaded|abi_registry)' | tail -2
```

Expected: a `policy-load`-success log line; fwd is serving. If fwd
exits, the policy has an orphan — `docker logs fwd 2>&1 | grep
policy_consistency_error` and fix before continuing. (NOTE: the three
callers above are declared in `policy.callers` BUT do not yet exist in
the `callers` table — startup fail-fast only checks ACTIVE DB callers
against the policy, not the reverse, so this boots clean. They are
created in Step 1.)

## Step 1 — provision the gate wallets + callers

```sh
for w in phase7-gate phase7-wr-wallet phase7-offlist; do
  pp=$([ "$w" = phase7-wr-wallet ] && echo wc/phase7-wallet-rate || echo wc/phase7-gate)
  curl -sf -X POST $FWD/v1/admin/wallets -H "Authorization: Bearer $ADMIN_KEY" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$w\",\"policy_path\":\"$pp\"}" | jq -r '.address'
done
```

Capture the `phase7-gate` address → `GATE_ADDR`. Then the callers
(each returns its `api_key` ONCE):

```sh
GATE_KEY=$(curl -sf -X POST $FWD/v1/admin/callers -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"phase7-gate-caller","policy_path":"perm/phase7-gate"}' | jq -r '.api_key')
CR_KEY=$(curl -sf -X POST $FWD/v1/admin/callers -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"phase7-cr-caller","policy_path":"perm/phase7-caller-rate"}' | jq -r '.api_key')
WR_KEY=$(curl -sf -X POST $FWD/v1/admin/callers -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"phase7-wr-caller","policy_path":"perm/phase7-wallet-rate"}' | jq -r '.api_key')
echo "GATE_ADDR=$GATE_ADDR GATE_KEY=$GATE_KEY CR_KEY=$CR_KEY WR_KEY=$WR_KEY"
```

**Admin-audit sub-check (D16):** the six creates above each wrote ONE
audit row. Confirm `caller-create` / `wallet-create` rows with NO
secret:

```sh
docker exec fwd clifwd audit tail -n 12 | grep -E 'wallet-create|caller-create'
# For one caller-create row, show it in full and assert NO key/hash:
SEQ=$(docker exec fwd clifwd audit tail -n 12 | grep caller-create | head -1 | awk '{print $1}')
docker exec fwd clifwd audit show "$SEQ"
```

Expected: `decision=approved`, `caller=` (NULL/empty — admin action),
`outcome` JSON has `api_key_prefix` ONLY; the row contains NO
`fwd_live_` substring, NO `api_key_hash`, NO `privkey`, NO ciphertext.

**Policy-path validation sub-check (a7):** an admin create with a
policy_path absent from the loaded policy must be refused 400:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST $FWD/v1/admin/callers \
  -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"phase7-bad","policy_path":"perm/nope"}'
```

Expected: `400` (body `error":"unknown_policy_path"`). This create
wrote NO audit row (rejected before the use case).

## Step 2 — fund the gate wallet with C2FLR (gas) + the ERC-20

1. Faucet `GATE_ADDR` for gas: https://faucet.flare.network/coston2 .
   Verify: `eth_getBalance($GATE_ADDR)` is non-zero.
2. Give `GATE_ADDR` a small balance of `$ERC20_TOKEN` (see
   Prerequisites — wrap C2FLR to WNat and transfer some in, or send any
   test ERC-20). Verify the ERC-20 balance is ≥ the test transfer
   amount (we transfer `1` base unit):

```sh
# balanceOf(GATE_ADDR) — selector 0x70a08231
BAL=$(curl -s -X POST "$RPC_URL_COSTON2" -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{
   \"to\":\"$ERC20_TOKEN\",
   \"data\":\"0x70a08231000000000000000000000000${GATE_ADDR#0x}\"},\"latest\"]}" | jq -r .result)
python3 -c "print('ERC20 balance =', int('$BAL',16))"
```

Expected: a positive integer ≥ 1. If 0, the approved step's tx will
mine `status=0x0` (token reverts on insufficient balance) and the gate
FAILS — fund first.

## Step 3 — calldata helper

All vectors use `transfer(address,uint256)` calldata. Generate it with
the same `eth-abi` fwd itself decodes with:

```sh
calldata() {  # calldata <recipient> <amount>
  poetry run python -c "
import sys, eth_abi, eth_utils
sel = eth_utils.function_abi_to_4byte_selector({'name':'transfer','type':'function',
  'inputs':[{'name':'to','type':'address'},{'name':'amount','type':'uint256'}]})
print('0x'+sel.hex()+eth_abi.encode(['address','uint256'],[sys.argv[1],int(sys.argv[2])]).hex())
" "$1" "$2"
}
GOOD_DATA=$(calldata "$RECIPIENT" 1)            # sanctioned
WRONG_ARG_DATA=$(calldata "$WRONG_RECIPIENT" 1) # step 6
APPROVE_DATA=$(poetry run python -c "
import eth_abi, eth_utils
sel=eth_utils.function_abi_to_4byte_selector({'name':'approve','type':'function',
 'inputs':[{'name':'spender','type':'address'},{'name':'amount','type':'uint256'}]})
print('0x'+sel.hex()+eth_abi.encode(['address','uint256'],['$RECIPIENT',1]).hex())")  # step 4
TRUNCATED_DATA="0xa9059cbb00"   # transfer selector + 1 junk byte → decode fail (step 3)
GARBAGE_DATA="0xdeadbeef"       # unknown selector (step 3/registry miss)
```

A reusable POST helper that prints the HTTP code + body:

```sh
sas() {  # sas <api_key> <json-body> [idempotency-key]
  hdr=(-H "Authorization: Bearer $1" -H 'Content-Type: application/json')
  [ -n "${3:-}" ] && hdr+=(-H "Idempotency-Key: $3")
  curl -s -w '\nHTTP %{http_code}\n' -X POST $FWD/v1/sign-and-send "${hdr[@]}" -d "$2"
}
nonce_of() {  # on-chain nonce of GATE_ADDR
  curl -s -X POST "$RPC_URL_COSTON2" -H 'Content-Type: application/json' \
   -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionCount\",\"params\":[\"$GATE_ADDR\",\"latest\"]}" \
   | jq -r .result
}
```

## Step 4 — the 10-vector D14 deny matrix (live)

Record `N0=$(nonce_of)` before starting. After EVERY denied vector,
`nonce_of` MUST still equal `N0` (proof of no broadcast). Each denied
call MUST return `HTTP 403` with body `error":"policy_denied"` and a
`step=<n>` in the message.

| Vec | D14 step | Request (caller / wallet / to / data / value) | Expect |
|----|----|----|----|
| V1 | 1 caller→binding | see **Step 5** (startup fail-fast — separate) | fwd refuses to boot |
| V2 | 2 contract not permitted | GATE_KEY / phase7-gate / `$NOT_A_CONTRACT` / `$GOOD_DATA` / "0" | 403 step=2 |
| V3 | 3 decode fail | GATE_KEY / phase7-gate / `$ERC20_TOKEN` / `$TRUNCATED_DATA` / "0" | 403 step=3 |
| V3b | 3 selector miss | GATE_KEY / phase7-gate / `$ERC20_TOKEN` / `$GARBAGE_DATA` / "0" | 403 step=3 |
| V4 | 4 method not in policy | GATE_KEY / phase7-gate / `$ERC20_TOKEN` / `$APPROVE_DATA` / "0" | 403 step=4 |
| V5 | 5 value > max | GATE_KEY / phase7-gate / `$ERC20_TOKEN` / `$GOOD_DATA` / "1" | 403 step=5 |
| V6 | 6 arg predicate | GATE_KEY / phase7-gate / `$ERC20_TOKEN` / `$WRONG_ARG_DATA` / "0" | 403 step=6 |
| V7 | 7 wallet not allowlisted | GATE_KEY / **phase7-offlist** / `$ERC20_TOKEN` / `$GOOD_DATA` / "0" | 403 step=7 |
| V8 | 8 caller rate | CR_KEY / phase7-gate / `$ERC20_TOKEN` / `$GOOD_DATA` / "0" — 2nd call | 1st 201, 2nd 403 step=8 |
| V9 | 9 wallet rate | WR_KEY / phase7-wr-wallet / `$ERC20_TOKEN` / `$GOOD_DATA` / "0" — 2nd call | 1st 201, 2nd 403 step=9 |

Example invocations (V2, V6, V8 shown; V3–V7 follow the same shape):

```sh
N0=$(nonce_of); echo "start nonce=$N0"

# V2 — contract not permitted
sas "$GATE_KEY" "{\"wallet\":\"phase7-gate\",\"chain\":114,\"to\":\"$NOT_A_CONTRACT\",\"value_wei\":\"0\",\"data\":\"$GOOD_DATA\"}"
# V6 — arg predicate mismatch (sanctioned-but-modified arg)
sas "$GATE_KEY" "{\"wallet\":\"phase7-gate\",\"chain\":114,\"to\":\"$ERC20_TOKEN\",\"value_wei\":\"0\",\"data\":\"$WRONG_ARG_DATA\"}"
# V8 — caller rate: first consumes the bucket (this one BROADCASTS — see note), second denies
sas "$CR_KEY" "{\"wallet\":\"phase7-gate\",\"chain\":114,\"to\":\"$ERC20_TOKEN\",\"value_wei\":\"0\",\"data\":\"$GOOD_DATA\"}"
sas "$CR_KEY" "{\"wallet\":\"phase7-gate\",\"chain\":114,\"to\":\"$ERC20_TOKEN\",\"value_wei\":\"0\",\"data\":\"$GOOD_DATA\"}"

echo "nonce after V2/V3/V4/V5/V6/V7 = $(nonce_of)   (MUST equal $N0)"
```

**Note on V8/V9:** their FIRST call is a sanctioned transfer and
legitimately broadcasts (advancing the nonce by 1 each, mining
`status=0x1` if the wallet holds the token). It is the SECOND call that
must 403 with step=8 (V8) / step=9 (V9). For V2–V7 the nonce must be
unchanged from `N0`.

After the matrix, confirm every denied request wrote a `decision=
"denied"` `sign-and-send` row with the right step:

```sh
docker exec fwd clifwd audit tail -n 30 | grep sign-and-send
# Spot-check one — V6 should read step=6 in decision_reason:
docker exec fwd clifwd audit show <seq-of-the-V6-row>
```

Expected: one `sign-and-send` `decision=denied` row per V2–V7 + the V8
2nd + the V9 2nd, each `decision_reason` naming the matching step;
`outcome` is null (nothing signed).

## Step 5 — V1: step-1 caller→binding fail-fast (startup)

D14 step 1 is enforced at startup (not as a runtime 403): an ACTIVE
caller absent from the loaded policy makes fwd refuse to serve. Prove
it without losing the gate state:

```sh
cp /etc/fwd/policy.yaml /tmp/policy.good.yaml          # adjust to your mount path
# Remove the `phase7-gate-caller:` binding block from policy.callers, keep the rest.
$EDITOR /etc/fwd/policy.yaml
docker compose restart fwd; sleep 5
docker ps --format '{{.Names}} {{.Status}}' | grep fwd     # fwd should be Exited/Restarting
docker logs fwd 2>&1 | grep -E 'policy_consistency_error|policy-load' | tail -3
```

Expected: fwd does NOT come up; a log line names `phase7-gate-caller`
as an orphan; a `policy-load` `decision="error"` audit row was
committed (it survives the exit — D16 forensic evidence). Restore:

```sh
cp /tmp/policy.good.yaml /etc/fwd/policy.yaml
docker compose restart fwd; sleep 5
docker ps --format '{{.Names}} {{.Status}}' | grep 'fwd .*Up'   # back to serving
```

## Step 6 — V10: the sanctioned action (approved + mined)

```sh
IDEM=$(python3 -c "import uuid;print(uuid.uuid4())")
RESP=$(sas "$GATE_KEY" "{\"wallet\":\"phase7-gate\",\"chain\":114,\"to\":\"$ERC20_TOKEN\",\"value_wei\":\"0\",\"data\":\"$GOOD_DATA\"}" "$IDEM")
echo "$RESP"
TX_ID=$(echo "$RESP" | sed -n '1p' | jq -r '.tx_id')
HASH=$(echo "$RESP"  | sed -n '1p' | jq -r '.hash')
echo "TX_ID=$TX_ID HASH=$HASH IDEM=$IDEM"
```

Expected: `HTTP 201`; `tx_id`, `hash`, `nonce` returned. Wait + verify
mined:

```sh
sleep 30
curl -sf -H "Authorization: Bearer $GATE_KEY" "$FWD/v1/transactions/$TX_ID" \
  | jq -r '"\(.tx_id) \(.status) \(.nonce)"'
curl -s -X POST "$RPC_URL_COSTON2" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$HASH\"]}" \
  | jq '.result | {status, from, to, blockNumber}'
```

Expected: `/v1/transactions` → `status=mined`; receipt `status="0x1"`,
`from` = `$GATE_ADDR` (case-insensitive), `to` = `$ERC20_TOKEN`,
`blockNumber` non-null. The approved-path `sign-and-send` audit row:

```sh
docker exec fwd clifwd audit tail -n 10 | grep "$TX_ID" || \
  docker exec fwd clifwd audit tail -n 10 | grep sign-and-send
```

Expected: a `sign-and-send` `decision="approved"` row whose `outcome`
JSON contains `"tx_id":"<TX_ID>"`.

## Step 7 — D14 idempotency replay

Re-send the EXACT Step-6 request with the SAME `Idempotency-Key`:

```sh
N_BEFORE=$(nonce_of)
RESP2=$(sas "$GATE_KEY" "{\"wallet\":\"phase7-gate\",\"chain\":114,\"to\":\"$ERC20_TOKEN\",\"value_wei\":\"0\",\"data\":\"$GOOD_DATA\"}" "$IDEM")
echo "$RESP2"
TX_ID2=$(echo "$RESP2" | sed -n '1p' | jq -r '.tx_id')
N_AFTER=$(nonce_of)
```

Expected: `HTTP 200` (NOT 201); `TX_ID2 == TX_ID` (same cached id);
`N_AFTER == N_BEFORE` (NO second broadcast); a `sign-and-send-duplicate`
audit row whose `outcome` JSON has `"original_tx_id":"<TX_ID>"` and an
integer `original_audit_seq`, `decision_reason=idempotency_replay`:

```sh
docker exec fwd clifwd audit tail -n 6 | grep sign-and-send-duplicate
docker exec fwd clifwd audit show <seq-of-that-row>
```

## Step 8 — chain verify (D16 tamper-evidence)

```sh
docker exec fwd clifwd audit verify; echo "exit=$?"
docker exec fwd clifwd audit tail -n 40 | wc -l
```

Expected: `clifwd audit verify` prints chain-intact and **exits 0**,
having walked policy-load + every denied row (V2–V9) + the V1
policy-load-error + the approved row + the duplicate + the six
admin-create rows. A non-zero exit (`CHAIN BROKEN at seq=…`) is an
immediate FAIL — capture and surface.

## Pass / fail summary

The Phase 7 GA verification gate is **passed** if and only if:

| # | Criterion | Step |
|---|---|---|
| 1 | Admin creates wrote no-secret `wallet-create`/`caller-create` rows; bad policy_path → 400, no row | 1 |
| 2 | D14 steps 2–9 each return HTTP 403 with the matching `step=N`, a `decision="denied"` row, and `nonce_of` unchanged for V2–V7 | 4 |
| 3 | V1: an orphan-caller policy makes fwd refuse to boot + a `policy-load` `error` row | 5 |
| 4 | The sanctioned transfer returns 201, mines `status=0x1`, on-chain `from` = gate wallet, `decision="approved"` row | 6 |
| 5 | Idempotency replay → HTTP 200, SAME `tx_id`, nonce unchanged, `sign-and-send-duplicate` row | 7 |
| 6 | `clifwd audit verify` exits 0 over the full chain | 8 |

Any failure: do NOT mark the Phase 7 GA gate met. Capture `docker logs
fwd 2>&1 | tail -300`, the failing curl bodies, and `docker exec fwd
clifwd audit tail -n 50`; surface to the Reviewer for triage. Per the
v0.4.5 precedent, a defect the live drill surfaces is fixed + the
evidence recorded in one combined follow-up ship (v0.5.1).

## After a clean pass

The Reviewer files a Reviewer-only addendum to
`docs/history/0.5.0-phase-7-ga.md` recording:

- The gate wallet address + `$ERC20_TOKEN` (both public — already
  on-chain).
- The approved tx hash + its Coston2 block number; the duplicate's
  cached `tx_id`.
- The audit-chain length verified and the `clifwd audit verify` exit 0.
- The runbook git-sha followed.
- "Phase 7 GA verification gate met live on Coston2 at <date>."

This mirrors v0.4.1 (Phase 5 proof) and v0.4.6 (Phase 6 proof). Closes
audit deferrals F2.1 + F8.2. Phase 7 is then GA; Phase 8 (v1.0.0 —
`ftso-fee-claimer` production migration) is unblocked.

## Operational notes

- Coston2 fee market is low; the approved tx mines in 1–2 blocks. If it
  stays `submitted`, check Coston2 status before failing.
- The fixed UTC-aligned rate windows (D14) mean V8/V9 are robust within
  the hour; if you straddle a UTC hour boundary mid-run the per-hour
  buckets reset — re-run V8/V9 cleanly within one hour.
- `clifwd wallets list` / `clifwd callers list` confirm provisioning
  after Step 1.
- The same policy structure with a RewardManager `claim` contract +
  `_recipient` arg_predicate (see `docs/policy.example.yaml`) is the
  Phase 8 production shape — this gate validates that engine, exercised
  here through the cheaper, repeatable ERC-20 `transfer` surface per
  the operator's gated decision.
