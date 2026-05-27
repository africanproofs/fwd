# Zero-Egress fwd — Architecture Plan

**Status:** Proposed (operator-authorized direction, 2026-05-27). Not yet shipped.
**Ship type:** Feature ships + a constitutional-amendment ship (per the D17
ship-type framework). The new amendment gets the next free D-number — **D20**
(`docs/decisions.md` currently ends at D19).
**Decision owner:** Operator. **Author:** Reviewer (Opus).
**Revision:** Patched 2026-05-27 after first-pass review — see §11.

---

## 1. Context

`fwd` today is a sign-**and-send** service. Its only outbound network surface is
JSON-RPC to a Flare/Songbird/Coston2 node — `src/fwd/infra/rpc.py:97`
(`self._http.post(self._url, …)`) — used for chain-id verify, the one-time
on-chain nonce seed, `eth_feeHistory`, `eth_estimateGas`,
`eth_sendRawTransaction`, the background receipt watcher, startup nonce
reconcile, **and the v1.1.0a7 admin read path `GET /v1/admin/wallets/balances`
→ `eth_getBalance`** (`src/fwd/app/wallet_balances.py:149`). That balances
endpoint/CLI is part of the egress surface and must be removed, moved
client-side, or redesigned **before** `rpc.py` can be deleted (see §6).
Litestream is already local-only (v0.4.3, "no outside dependencies");
the inbound port is already `127.0.0.1`-bound. So the **entire** egress surface is
the RPC client.

**Operator decision (2026-05-27):**

1. **Egress scope** — the whole fwd stack must make **zero internet calls**. fwd
   (the key-holder) gets no internet route at all.
2. **RPC location** — the only available RPC is **public internet**; there is no
   private/LAN node to fall back to. Broadcasting therefore cannot stay inside the
   fwd stack — it moves to the **client apps**, which have internet.
3. **Standing constraint** — **multiple applications** will be clients of fwd.

**Intended outcome.** fwd becomes a **zero-egress signer + nonce-allocation
authority**: it signs ABI-decoded EVM transactions and FSP messages, allocates
nonces, enforces policy, and keeps the audit log — but **never opens a socket to
the internet**. Each client app fetches gas, broadcasts, and polls receipts over
its own internet access, then feeds chain outcomes back to fwd. This structurally
closes the threat-model **A4** "compromised fwd exfiltrates keys over the network"
channel by removing fwd's egress entirely.

---

## 2. The load-bearing insight (why this works for *multiple* clients)

The naive "fwd signs, the caller broadcasts" split normally fragments nonce
coherence: with N clients sharing one wallet, each reads `eth_getTransactionCount`
independently and collides on the same nonce — exactly what **Core invariant #4**
exists to prevent.

The escape: **nonce *reservation* is already a pure-local SQLite operation** —
`nonce_repo.reserve_next`, `BEGIN IMMEDIATE`, `src/fwd/infra/nonce_repo.py:87-123`
— and needs no network. So fwd remains the **single nonce allocator across all
clients** while having zero egress. Clients must route every transaction through
fwd to obtain a nonce; they cannot self-assign. Core #4's "concurrent signing
requests against the same wallet cannot collide" is **preserved**.

What genuinely cannot stay in fwd is **chain-truth**: the one-time on-chain nonce
seed, fee data, broadcast, and receipts. Those move to clients, who feed results
back. fwd's role sharpens to *allocate, sign, account — never observe the chain
directly*.

---

## 3. Architecture

```
┌─────────────┐   /v1/sign-transaction      ┌────────────────────────────┐
│ client app  │ ───────────────────────────▶│ fwd  (internal-only net)   │
│ (clif, …)   │   wallet,to,value,data,      │  • policy gate (default-   │
│ HAS internet│   gas,maxFee,maxPriorityFee  │    deny, ABI intent)       │
│             │ ◀─── signed raw tx + tx_id ──│  • nonce ALLOCATOR (local) │
│             │      + nonce N               │  • sign (sealed master)    │
│             │                              │  • audit (hash-chain)      │
│  eth_send-  │   /v1/transactions/{id}/     │  • tx lifecycle tracking   │
│  RawTx ────▶│   broadcast-result {hash,ok} │    via client report-back  │
│  to PUBLIC  │ ───────────────────────────▶│                            │
│  RPC        │   /v1/transactions/{id}/     │   NO httpx, NO RPC client, │
│  eth_get-   │   receipt {mined,block}      │   NO receipt watcher,      │
│  Receipt ──▶│ ───────────────────────────▶│   NO internet route        │
└─────────────┘                              └────────────────────────────┘
```

**fwd keeps (all local, zero egress):** custody/sealing, policy + ABI intent
decode, **nonce reservation**, signing, audit log, tx-lifecycle state, the
×1.125-bump replacement *logic* (now client-triggered), idempotency.

**Moves to the client (it has internet):** chain-id check, the initial on-chain
nonce seed, `eth_feeHistory`/`eth_estimateGas` (client supplies
`gas`/`maxFeePerGas`/`maxPriorityFeePerGas`), `eth_sendRawTransaction`,
`eth_getTransactionReceipt`, and feeding outcomes back to fwd.

---

## 4. Client ↔ fwd protocol

| Endpoint | Direction | Purpose |
|----------|-----------|---------|
| `POST /v1/sign-transaction` | client→fwd | Replaces `/v1/sign-and-send`. Client supplies `gas`, `maxFeePerGas`, `maxPriorityFeePerGas`. fwd reserves nonce N, builds + signs the EIP-1559 tx, records the post-sign/pre-broadcast state (reusing the existing `pending` status — see §6, no new `signed` status), returns `{tx_id, signed_raw_tx, nonce}`. **No broadcast.** |
| `POST /v1/transactions/{tx_id}/broadcast-result` | client→fwd | Client reports `{tx_hash, outcome, error_class?}`. **Outcome split (see §5):** `accepted`→`status=submitted`. `rejected_releaseable` (e.g. insufficient funds — the nonce was provably never consumed) → **`release_if_unused` only succeeds if N is the tail** (`next_nonce-1`); if N is *not* the tail (N+1.. already reserved by another client), release fails by design and the slot becomes an **unresolved hole** routed through the chosen lease/rescue/operator mechanic (§5) — it is NOT silently terminal. **`rejected_nonce_too_low` is NOT releaseable** — chain truth is *ahead* of fwd, so fwd must NOT decrement/reuse N; it forces a `nonce-sync` and advances state. |
| `POST /v1/transactions/{tx_id}/receipt` | client→fwd | Client reports `{outcome, block}` where outcome is `mined_success` or `mined_reverted` (nonce **consumed** either way — distinct from a never-broadcast `failed`; see §6 status model). fwd calls `mark_confirmed`. |
| `POST /v1/transactions/{tx_id}/sign-replacement` | client→fwd | Stuck-tx path (Core #11). **Request carries client-supplied `gas` + fee caps** (fwd can no longer estimate — §5). fwd re-signs the **same nonce** and **enforces the bump rule (≥ ×1.125 over the prior attempt, ≤5 retries)** against the recorded prior attempt; rejects a non-conforming bump. Returns new `signed_raw_tx`. |
| `POST /v1/admin/nonce-sync` | **admin only** | Replaces the egress startup reconcile. Pushes on-chain `transactionCount`. **Admin-authenticated, never a general client endpoint** — monotonic advance alone is insufficient, since a compromised client pushing `transactionCount=999999` would wedge the wallet *forward*. Advances within a small bound auto-apply; advances beyond the bound require explicit operator review (§4.1). |

`/v1/sign-fsp-message` is **unchanged** — it is already zero-egress (the precedent
this generalizes).

### 4.1 Trust boundaries on the state-mutating endpoints

With multiple clients, `broadcast-result`, `receipt`, `sign-replacement`, and
`nonce-sync` are **state-mutating trust boundaries**, not passive reports. Every
one must enforce:

- **Caller ownership.** Same `tx.caller != caller.name → 404` check the read path
  already uses (`src/fwd/api/transactions.py:49`). A client may only report on its
  own txs.
- **`tx_hash` validation.** The reported `tx_hash` must match a hash fwd recorded
  for that `tx_id` (`transaction_hashes`), or the keccak of the `signed_raw_tx` fwd
  returned — reject mismatches. A client cannot attribute an arbitrary hash to an
  fwd tx.
- **Legal status transitions only.** Guard a state machine
  (`pending → submitted → mined_success｜mined_reverted`, `pending → failed`,
  `submitted → replaced`, …). Reject illegal jumps (e.g. `mined_success → failed`).
- **`nonce-sync` authority.** **Admin-only** (uses the admin auth surface, not the
  caller bearer-token surface). Monotonic-only is *not* sufficient protection: a
  compromised client could push a huge `transactionCount` and wedge the wallet
  forward, skipping live nonces. Therefore: small advances within a configured
  bound auto-apply; any larger advance — and any rewind — requires explicit
  operator review. A client-supplied chain count is *advisory input* to the admin
  path, never a direct state write.

---

## 5. Headline residual risk — orphaned nonce reservation

The new failure mode created by the split: a client calls `/v1/sign-transaction`
(fwd reserves nonce N), then crashes *before broadcasting* and never reports back.
N is reserved-but-never-on-chain → every later nonce wedges behind the gap. This
is the sign-only analogue of the documented broadcast-rejection nonce wedge.

**Why naïve "reclaim = reissue" is unsafe (do NOT canonize it).** Once fwd has
returned the signed raw tx, it **cannot revoke it** — the client may already have
broadcast it, or may broadcast it later. Handing the *same nonce N* to the next
*arbitrary* requester therefore creates a **cross-client race between two different
intents** at one nonce: whichever the network sees first wins, and the other
client's intent is silently dropped (or, worse, the "wrong" intent mines). That is
not harmless. Two further code facts make the naïve model unworkable as written:

- `NonceRepo.reserve_next` is **monotonic** (`src/fwd/infra/nonce_repo.py:87`) — it
  only ever hands out `next_nonce` and increments. There is no allocator for a
  *gap* in the middle of the sequence.
- `release_if_unused` (`nonce_repo.py:125`) only decrements the **tail** nonce
  (`next_nonce - 1 == reserved`); it deliberately leaves non-tail gaps as
  operator-visible drift. Adding a `reserved_at` column alone does **not** give a
  safe allocator for non-tail holes.

**Required reclaim semantics (one of, to be decided in Phase-0 — not assumed):**

1. **Reservation lease.** Add `reserved_at`; a reservation with no
   `broadcast-result` inside the lease window is *flagged*, not silently reused.
2. **Same-intent replacement only.** A reclaimed nonce N may be re-signed **for the
   exact recorded intent** of the orphaned tx (fwd already stored it), never for a
   different client's new intent. This is just the `sign-replacement` path applied
   to an orphan — no cross-intent race.
3. **Gap-fill / rescue tx.** To unwedge a confirmed hole, fwd signs a deliberate
   0-value self-send at nonce N (consumes the slot with a known-benign intent),
   gated by policy + operator. This needs a real lease-aware allocation model that
   can target a specific non-tail nonce — a new repo capability, not `reserve_next`.
4. **Explicit operator action.** Unresolved holes surface to the operator
   (Core #11 spirit) rather than auto-healing.

`/v1/admin/nonce-sync` feeds chain truth so fwd can *detect* holes and advance
`last_confirmed` (monotonic — §4.1). The **idempotency key** stays mandatory in
practice, so a client retry after a timeout returns the same nonce + same intent
and never double-allocates.

This risk + the chosen reclaim mechanic is a doctrine artifact (threat-model entry
+ the Core-#11 amendment). **The D-record must not be written until the reclaim
mechanic is chosen** — otherwise it canonizes the unsafe reissue model.

---

## 6. Code changes

**Delete / gut (the egress surface) — ALL of this is one atomic ship.** `rpc.py`
cannot be deleted while any importer remains; every consumer below must be removed
in the same ship (ship 1, §8), or the tree does not import:

- `src/fwd/infra/rpc.py` — delete the RPC client entirely.
- `src/fwd/app/dependencies.py` — remove the `RpcManager` import (line 29), the
  `RpcManagerCM` class + `get_rpc_manager` (54-70), the `RequestScope.rpc_mgr`
  field (184), and the `RpcManager()` construct + `aclose()` inside
  `RequestScopeCM` (214, 229). `RequestScope` no longer carries an RPC handle.
- `src/fwd/app/receipt_watcher.py` — delete (background egress task).
- `src/fwd/app/nonce_reconcile.py` — delete; replaced by `/v1/admin/nonce-sync`.
- `src/fwd/app/wallet_balances.py` + `GET /v1/admin/wallets/balances` +
  `clifwd wallets balances` — **resolve before `rpc.py` deletion.** Options:
  (a) remove the feature; (b) move balance reads client-side (the client has
  internet and already knows the wallet address); (c) redesign as a client→fwd
  *report* (client pushes balances fwd stores read-only). Recommendation: **(b)**
  — balance is chain-truth, the same class as gas/receipts, and belongs with the
  client. Pick one in the first ship's Phase-0; `rpc.py` cannot be deleted while
  this path still calls `eth_getBalance`.
- `src/fwd/main.py::lifespan` — remove RpcManager wiring, receipt-watcher task
  start, nonce-reconcile call. **Keep `mlockall`.**
- `src/fwd/settings.py` — remove `rpc_url_flare/songbird/coston2`. Repurpose
  `ALLOWED_CHAINS` from an "RPC-routing rail" to a pure sign-allowlist
  (policy-declared chains fwd will sign for).
- `.env.example` — remove all `RPC_URL_*`.
- `pyproject.toml` — drop `httpx` from fwd's runtime deps if nothing else uses it
  (the CLI uses it for localhost calls — keep it there; verify before removing).

**Modify:**

- `src/fwd/app/sign_and_send.py` → rename to `sign_transaction.py`. Drop the `rpc`
  param and all five RPC call sites (chain-id verify, nonce seed, fee_history,
  estimate_gas, send_raw). Add required request fields `gas`, `max_fee_per_gas`,
  `max_priority_fee_per_gas`. Keep idempotency replay, policy gate, nonce
  reservation, tx build, sign, audit. **Preserve the commit-before-raise forensic
  audit discipline (Core #19) on every failure arm** — unchanged.
- `src/fwd/api/sign.py` → mount `/v1/sign-transaction` with the new request schema;
  retire `/v1/sign-and-send`.
- **Nonce initialization without RPC (ship 1 — blocks signing otherwise).** Once
  the on-chain seed is gone, a fresh `(wallet, chain)` has no `next_nonce` and
  `reserve_next` raises `NonceNotInitializedError` with no recovery path. The
  existing `init_for_wallet(wallet, chain, starting_nonce)` already takes an
  explicit seed — expose it via an **admin endpoint + `clifwd nonce init <wallet>
  <chain> <starting_nonce>`** (fresh wallet → 0; existing wallet → the operator/
  client supplies the current count). This MUST land in the same ship as the RPC
  removal, not later.
- `src/fwd/infra/nonce_repo.py` → add `reserved_at` + a **lease-aware allocator**
  capable of targeting a specific non-tail nonce (the gap-fill/rescue case in §5);
  `reserve_next`/`release_if_unused` as they stand are not sufficient. Schema
  change needs an Alembic migration.
- **Per-attempt state for replacement (`transaction_repo.py`).** Today
  `transactions.signed_raw` is a single latest value (line 32) and
  `transaction_hashes` stores only `hash_hex`/`submitted_at` (lines 40-47) — there
  is nowhere to record the *prior attempt's* gas/fee for the ≥×1.125 bump check.
  Add a `transaction_attempts` table (or per-attempt columns) recording, per
  sequence: `gas`, `max_fee_per_gas`, `max_priority_fee_per_gas`, `signed_raw`,
  `hash`, `created_at`. `sign-replacement` enforces the bump against the latest
  attempt row. Alembic migration.
- **Status model pass (`src/fwd/infra/transaction_repo.py:49`).** Do **not** invent
  a `signed` status — current `_VALID_STATUSES = {pending, submitted, mined,
  replaced, failed, dropped}`. Reuse `pending` for the post-sign/pre-broadcast
  state. Split the overloaded `failed`: a tx **never broadcast / never consumed a
  nonce** (releaseable) is a different state from a tx **mined but reverted**
  (nonce consumed) — introduce a distinct status (e.g. `reverted`) so nonce-
  consumption semantics are unambiguous. Land this as an explicit migration.
- New `src/fwd/api/` handlers + `src/fwd/app/` logic for `broadcast-result`,
  `receipt`, `sign-replacement`, `admin/nonce-sync`. Each carries a **request
  schema** (notably `sign-replacement` takes client-supplied `gas` + fee caps,
  since fwd can no longer estimate) and enforces the §4.1 trust checks
  (caller-ownership, `tx_hash` validation, legal transitions, nonce-sync
  monotonicity).

**Network topology (defense-in-depth — structural guarantee independent of code):**

- `docker-compose.yml`: mark fwd's network `internal: true` so the fwd container
  has **no gateway to the internet**. fwd attaches to this internal network only.
- **Clients are dual-homed**: the internal network (to reach `fwd:8080`) **plus** a
  normal bridge (for their own internet/RPC egress). Document in `.env.example` / a
  compose override. This is the same `internal: true` mechanism that — verified
  empirically at v0.4.2 — has no internet route; back then it broke Litestream's
  S3, which is exactly why S3 was removed. Now nothing in fwd needs egress, so
  `internal: true` is finally correct.

---

## 7. Doctrine — constitutional-amendment ship (per the D17 framework; new record = D20)

Per `CLAUDE.md` § Linear-forward versioning, this changes load-bearing invariants
and therefore ships as an operator-authorized **constitutional-amendment ship**
(bounded surface: amended sections + a `docs/decisions.md` D-record + the three
feature-ship artifacts + the two version files). Amendments:

- **Core #4** — fwd remains the single nonce *reservation* authority (still local
  SQLite, now the *only* nonce operation it performs); nonce *seeding and
  reconciliation* are client-fed chain-truth via `/v1/admin/nonce-sync`, not fwd
  RPC. Add the reservation-lease/reclaim rule.
- **Core #11** — replacement is **client-triggered** (`sign-replacement`); fwd no
  longer runs a receipt-watcher timer; the bump policy and "never silently
  abandoned / surfaces to operator" guarantee remain, now realized through
  report-back + nonce-sync.
- **Core #14** ("real-RPC verification is the validation") — fwd's own code no
  longer touches RPC; the live-drill obligation shifts to the **client↔fwd↔chain
  integration** (a client broadcasting an fwd-signed tx on real Coston2). fwd unit
  tests cover signing/nonce/policy; the integration drill is the validation.
- **§ "What FWD Deliberately IS NOT"** — add **"Not a broadcaster. fwd signs and
  allocates nonces; clients broadcast."** Upgrade "No public network exposure" →
  **"No network egress at all."**
- **`docs/threat-model.md`** — A4 network-exfil channel **eliminated** (no egress);
  add the new **orphaned-reservation operational risk** + lease/reclaim mitigation.
- **`docs/decisions.md`** — new D-record **D20** (D19 is the current tail): the
  operator decision, the rejected
  alternatives (keyless egress relay; LAN-only network lock — both moot once "only
  public internet" + "whole stack zero egress" were chosen), and the
  multiple-clients rationale for keeping nonce allocation in fwd.

---

## 8. Ship sequence (operator-gated; fwd workflow: Opus prescribes → Sonnet implements → Opus reviews)

Each is its own linear-forward version with a canonical prompt at
`~/.claude/plans/fwd-canonical-prompt-<ship>.md` and an operator gate. The order
below is dependency-correct: each ship leaves the tree importing, the test suite
green, and the daemon coherent.

1. **Zero-egress signing core.** Split into two ships for tractability — nonce-init
   is additive and lands *first* so the prerequisite exists before the excision
   needs it (the plan's "not later than the removal" is satisfied by landing it
   earlier):
   - **1a (v1.1.0a8) — nonce-init (additive, RPC untouched).** Expose
     `init_for_wallet` via an admin `POST /v1/admin/nonce-init` + `clifwd nonce init
     <wallet> <chain> <starting-nonce>` (§6). Add `nonce_repo` to `AdminScope` so the
     seed + its D16 audit row commit on one session. Suite stays green; no egress
     change. Decisions for 1b also pre-locked: remove the `wallets balances` /
     `eth_getBalance` path entirely; add global `FWD_MAX_GAS` / `FWD_MAX_FEE_PER_GAS`
     sanity caps; retire `/v1/sign-and-send` (no alias); client gets the wallet
     address from its own config; keep Model S (`pending` tx row, `signed_raw`
     stored).
   - **1b (v1.1.0a9) — atomic egress excision.** `rpc.py` and *every importer* go in
     one ship: delete `rpc.py`, `receipt_watcher.py`, `nonce_reconcile.py`,
     `wallet_balances.py`; gut the `RpcManager` wiring in `dependencies.py` (§6);
     remove the balances endpoint + CLI; drop `ALLOWED_CHAINS`/`CHAIN_LABELS` (only
     users are the deleted files; policy is sole authZ); strip RPC wiring +
     receipt-watcher from `main.py::lifespan` (keep `mlockall`); remove the `rpc`
     field from `/healthz`; remove `RPC_URL_*` + watcher settings, add the two caps.
     Rename `sign_and_send`→`sign_transaction` (client-supplied gas/fee + caps; tx
     hash computed locally from the signed bytes, no broadcast); mount
     `/v1/sign-transaction`. After 1b fwd signs sequential txs with zero egress;
     lifecycle tracking past `pending` and wedge mitigation arrive next. Verify: full
     unit suite + a "no RPC reachable → still signs" test + a **code-level egress
     proof** (no httpx/RPC client remains in the tree). The **network-level**
     structural proof (§9) lands with `internal: true` in ship 4.
2. **Tx lifecycle report-back + status model + trust boundaries.**
   `broadcast-result` + `receipt` endpoints with the §4.1 trust checks; the status
   migration (`pending` for post-sign, split `failed`/`reverted` — §6);
   `reserved_at` column + orphan *detection* (flag only, no auto-reissue);
   tail-vs-non-tail release handling (§4/§5).
3. **Replacement + reclaim mechanic + admin nonce-sync.** `transaction_attempts`
   table (§6); `sign-replacement` with client-supplied gas/fee + bump enforcement
   against the prior attempt; the chosen reclaim mechanic (§5 — same-intent
   replacement / rescue tx / operator alarm); `/v1/admin/nonce-sync` (admin-only,
   bounded — §4.1).
4. **Network lockdown.** `internal: true` compose network; dual-homed client
   documentation; `.env.example` cleanup.
5. **Client integration (sibling Opus agents).** clif and other clients gain the
   self-broadcast + report-back loop against the ships 1-3 surface. The fwd Reviewer
   authors their canonical prompt + binding-passes their integration artifact; the
   fwd Reviewer does not implement consumer code (the standing "Reviewer owns fwd,
   not consumers" rule). **This precedes the live drill** because the drill *is* a
   client broadcasting an
   fwd-signed tx. (If client work must lag, ship a temporary internal drill harness
   here instead — but the drill cannot run against nothing.)
6. **Constitutional amendment (D20) + live drill + coordinated cutover.** Amend
   Core #4/#11/#14, IS-NOT, threat-model; write D20 — *only now*, once the reclaim
   mechanic and nonce-sync authority are settled. Run the §9 live drill using the
   ship-5 client. Then the operator-gated production cutover (§8.1).

### 8.1 Migration safety — the cutover is a coordinated flag-day

Zero-egress fwd and the egress-dependent `/v1/sign-and-send` **cannot coexist**:
ship 1 removes broadcast, so the moment the new fwd runs, the old endpoint is gone
and any client still calling it breaks. Therefore ships 1-5 land on **main** (the
only delivery target) and are proven on staging/Coston2, but **production stays on
the last egress-capable fwd version until a single operator-gated cutover window**
where zero-egress fwd and the self-broadcasting clients are deployed *together*.
The ship-6 live drill is the rehearsal of exactly that flip. This honors Core #15
(operator gates every production migration) and #9 (single replica — there is no
blue/green; the cutover is atomic per host).

---

## 9. Verification (end-to-end)

- **Unit:** full suite green after each ship; new tests for sign-only (no RPC
  reachable → still signs), report-back state transitions, reclaim-after-lease,
  and a **concurrent multi-client nonce test** (M clients hammer
  `/v1/sign-transaction` for one wallet → strictly monotonic, no duplicate nonce).
- **Structural egress proof:** with fwd on `internal: true`,
  `docker exec fwd python -c "import socket; socket.create_connection(('flare-api.flare.network',443),3)"`
  must fail (no route) — the literal "fwd cannot reach the internet" assertion.
- **Live drill (Core #14 successor):** a client builds real calldata, calls
  `/v1/sign-transaction`, broadcasts the returned raw tx to **real Coston2**,
  reports `broadcast-result` + `receipt` back; fwd's audit + nonce state match the
  on-chain outcome. Use real client-generated calldata, never a hand-modeled
  shape. Verify the **effect** (the expected on-chain event), not just a mined
  status.

---

## 10. Open design questions (resolve in the first ship's Phase-0: Reviewer → operator)

1. **Tx-tracking depth:** keep fwd's full tx-content tracking (Model S — enables
   replacement + audit completeness) vs a thinner "signature + nonce only" record
   (Model T). *Recommendation: Model S* — the multiple-clients + wedge risk needs
   fwd to own lifecycle state.
2. **Reclaim mechanic:** lease-window length, and *which* mechanic — same-intent
   replacement, deliberate rescue/gap-fill tx, or operator-only alarm (§5). Never
   cross-intent auto-reissue.
3. **Gas/fee trust:** fwd can no longer estimate. Does policy bound caller-supplied
   `gas`/`maxFeePerGas` (sanity caps) or accept them verbatim? *Recommendation: add
   policy max-gas/max-fee caps* so a compromised client cannot drain a wallet via
   fee.
4. **`/v1/sign-and-send` deprecation:** keep a one-version alias vs remove outright.
   *Lean: remove* — zombie egress code is exactly what Core #18 forbids.
5. **Wallet-address discovery for clients.** A client now needs the wallet's
   on-chain address to call `eth_getTransactionCount` (initial seed feed) and
   `eth_estimateGas`. Today only fwd resolves wallet-name → address
   (`signer.address`). Decide: is the address **client config** (state so
   explicitly), or does fwd expose a **caller-gated read-only wallet-metadata
   endpoint** (name → address, scoped to the caller's policy)? The plan assumes one
   of these exists; pick it in Phase-0.

---

## 11. Revision log

**2026-05-27 — first-pass review patch.** Incorporated review findings before any
D-record was drafted (deliberately, so the D-record would not canonize unsafe
semantics):

- **Egress inventory completed** — added the v1.1.0a7 `GET /v1/admin/wallets/
  balances` → `eth_getBalance` path (§1, §6); `rpc.py` cannot be deleted until it
  is resolved (ship 1).
- **Reclaim semantics rewritten** — "reclaim = reissue" flagged as unsafe
  (irrevocable signed tx + cross-intent race; `reserve_next` monotonic +
  `release_if_unused` tail-only). Replaced with same-intent-replacement / rescue-tx
  / operator-action options + a lease-aware allocator requirement (§5).
- **nonce-too-low separated** from releaseable rejections — forces `nonce-sync` and
  state advance, never decrement/reuse (§4).
- **Report-back trust boundaries** added (§4.1): caller-ownership, `tx_hash`
  validation, legal transitions, monotonic/operator-gated `nonce-sync`.
- **`sign-replacement` schema** — now takes client-supplied `gas`/fee caps; fwd
  enforces the bump rule against the prior attempt (§4, §6).
- **Status model** — dropped the invented `signed` status (reuse `pending`); split
  the overloaded `failed` (never-broadcast vs mined-but-reverted) (§4, §6).
- **D-numbering** — clarified "per the D17 framework"; the new record is **D20**
  (header, §7).
- **Open question added** — client wallet-address discovery (§10 Q5).

**2026-05-27 — second-pass review patch (sequencing + executability).** Reworked
the ship sequence and nonce-sync authority so nothing is mechanically unexecutable:

- **Atomic egress excision (§6, §8 ship 1).** `rpc.py` deletion now removes *every*
  importer in the same ship — added the `dependencies.py` `RpcManager` gut (import,
  `RpcManagerCM`, `get_rpc_manager`, `RequestScope.rpc_mgr`, `RequestScopeCM`
  construct/close), and folded the `receipt_watcher.py` / `nonce_reconcile.py`
  deletions into ship 1 (they were stranded in ship 3 while ship 1 deleted what they
  import).
- **Nonce-init in ship 1 (§6, §8).** Without the RPC seed a fresh `(wallet, chain)`
  could not sign; exposed `init_for_wallet` via an admin endpoint + `clifwd nonce
  init` so seeding is RPC-free, landing in the same ship as the removal.
- **nonce-sync hardened (§4, §4.1).** Now **admin-only** with a bounded
  auto-advance + operator review for large jumps — monotonic-only still let a
  compromised client wedge the wallet forward.
- **Non-tail release wedge (§4).** Releaseable rejection is no longer presented as
  terminal: tail → `release_if_unused`; non-tail → unresolved hole via the §5
  mechanic.
- **Per-attempt state (§6).** Added a `transaction_attempts` table for the
  ≥×1.125 bump check — `signed_raw` is single-valued and `transaction_hashes` lacks
  fee data, so the prior-attempt comparison had nowhere to read from.
- **Drill ordering (§8).** Client integration is now **ship 5**, before the live
  drill + amendment in **ship 6** (the drill requires a client to broadcast); a
  temporary harness is the named fallback.
- **Migration safety (§8.1).** Made explicit that zero-egress fwd and
  `/v1/sign-and-send` cannot coexist, so production cuts over in one coordinated
  operator-gated window rather than incrementally.
- **§10 Q2 reworded** to drop the "auto-reissue" framing the first patch had
  otherwise removed.

The D20 stub remains deliberately undrafted: the reclaim mechanic (§5/§10 Q2),
nonce-sync bound (§4.1), and balances disposition (§6) are still open, and the
D-record must not canonize them prematurely.
