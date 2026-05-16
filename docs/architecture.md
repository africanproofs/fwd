# Architecture

This document is the canonical design for `fwd`. Decisions are recorded in `decisions.md`; threats in `threat-model.md`; the phased build-out in `implementation-plan.md`. This file describes *what `fwd` is at v1.0.0* — the steady-state design once Phase 8 lands.

## One-paragraph summary

`fwd` is an HTTP signing service. Callers (AP backend apps, Claude agents) submit a signing request; `fwd` authenticates the caller, decodes the requested transaction's calldata against a known ABI, evaluates declarative policy, reserves a nonce, retrieves the wallet's Vault-wrapped private-key ciphertext from SQLite, asks HashiCorp Vault Transit to decrypt it via `aes256-gcm96` envelope encryption, signs the EIP-1559 transaction in-process with `eth-account`, zeroizes the plaintext key buffer immediately, broadcasts the signed transaction, and writes a hash-chained audit row recording the entire decision. Private keys are generated externally (secure RNG), envelope-encrypted at rest by Vault, and exist as plaintext in `fwd`'s process memory only during the bounded signing operation. State (nonces, transactions, audit log) lives in SQLite, replicated continuously to Scaleway Object Storage by Litestream. Deployment is a single-host `docker compose up`.

## Component topology

```
                    ┌─────────────────────────────────────────┐
   caller pods ───▶ │ fwd-callers Docker bridge network       │
   (ftso-claimer,   └────────────────┬────────────────────────┘
    apregister-e2e,                  │  HTTP + bearer API key
    fics-worker,                     ▼
    Claude agents)    ┌──────────────────────────────────┐
                      │  fwd (FastAPI + asyncio)         │
                      │  - caller auth (API key lookup)  │
                      │  - intent decoder (ABI parse)    │
                      │  - policy engine (YAML)          │
                      │  - nonce manager (SQLite)        │
                      │  - signing client (Vault HTTP)   │
                      │  - envelope decrypt + eth-account│
                      │  - RPC broadcast                 │
                      │  - receipt watcher (asyncio task)│
                      │  - audit log (hash-chained)      │
                      └────┬─────────────┬───────────┬───┘
                           │             │           │
                           ▼             ▼           ▼
              ┌────────────────┐  ┌──────────────┐  ┌─────────────────┐
              │ Vault          │  │ state.db     │  │ Flare RPC       │
              │ (Raft, Transit)│  │ (SQLite, WAL)│  │ Songbird RPC    │
              │ ClusterIP only │  │              │  │ Coston2 RPC     │
              └────────────────┘  └──────┬───────┘  └─────────────────┘
                                         │
                              ┌──────────▼───────────┐
                              │ litestream sidecar   │
                              │ → Scaleway Object    │
                              │   Storage            │
                              └──────────────────────┘
```

Three Docker services, two Docker networks, two named volumes:

| Service | Image | Role |
|---|---|---|
| `fwd` | `registry.gitlab.com/proofs.africa/fwd/fwd:<tag>` | The gateway. FastAPI on port 8080, bound to `127.0.0.1`. |
| `vault` | `hashicorp/vault:<pinned>` | Custody. Raft storage, Transit engine. Reachable only on `fwd-internal` network. |
| `litestream` | `litestream/litestream:<pinned>` | SQLite continuous replication to Scaleway Object Storage. |

| Network | Purpose |
|---|---|
| `fwd-internal` | `fwd` ↔ `vault` ↔ `litestream`. Marked `internal: true`; not reachable from host or external. |
| `fwd-callers` | Bridge that caller containers attach to in order to reach `fwd` on the same host. |

| Volume | Contents |
|---|---|
| `vault-data` | Vault Raft storage (encrypted at rest with master key) |
| `fwd-state` | SQLite `state.db` + audit log + WAL files |

## Trust boundaries

| Boundary | Mechanism | Failure if breached |
|---|---|---|
| caller → `fwd` | Bearer API key over HTTP on `fwd-callers` Docker network | Attacker can submit requests within that caller's policy scope |
| `fwd` → Vault | Vault token issued via Vault's K8s-style auth or AppRole, scoped to specific transit keys | Attacker can request signatures within `fwd`'s Vault permissions; cannot extract keys |
| Vault → key material | AES-256-GCM at rest; memory-locked (`mlock`) at runtime; Raft data on encrypted volume | Attacker with host root can extract key from Vault memory while unsealed |
| `fwd` → RPC | HTTPS/JSON-RPC | Compromised RPC could censor or fork view; signed tx still safe |
| Operator → Vault unseal | Shamir 3-of-5, 2 paper + 3 GPG-encrypted, geographically distributed | Attacker with 3 shares + host access can use the keys |
| Operator → `fwd` admin CLI | SSH to host + admin API key | Attacker can issue/revoke caller keys, modify policy, view audit |

## Caller authentication

v1: bearer API keys. Each caller has a key issued by `fwd`'s admin CLI:

```
$ docker exec -it fwd clifwd callers create \
    --name ftso-fee-claimer \
    --policy ftso-claim-flare-prod
fwd_live_a8f3c9d2b1e4...
```

The key is opaque to callers; `fwd` stores a salted hash on the host, not the key itself. Callers submit it as `Authorization: Bearer fwd_live_...`. Lookup → policy → wallet permissions.

API keys are rotatable from the CLI without service restart. Compromise response: revoke + reissue + caller redeploys with new key.

mTLS / SPIFFE / workload identity is deferred to Phase 10 (or whenever a caller lives outside the host).

## Signing flow

Under the v0.1.2 architecture, Vault Transit operates as an envelope-encryption layer, not a signer — Vault holds an `aes256-gcm96` master key (`fwd-master`) that wraps each wallet's externally-generated secp256k1 private key. At signing time, `fwd` decrypts via `transit/decrypt/fwd-master`, signs in-process with `eth-account` (which returns Ethereum-shaped output directly — no DER parsing or v-recovery needed in v1), and zeroizes the plaintext buffer immediately. DER parsing and v-recovery return only when Phase 10 introduces a hardware-backed `Signer` implementation that emits raw `(r, s)` ASN.1.

The `/v1/sign-and-send` happy path:

```
1.  Caller submits POST /v1/sign-and-send
    Body: { wallet, chain, to, value, data, gas? }
    Header: Authorization: Bearer fwd_live_...

2.  fwd authenticates caller
    - Lookup API key hash in callers table
    - Resolve caller → policy_path

3.  fwd loads policy.yaml (hot-reloaded on file change)
    - Resolve (caller, wallet) → permissions

4.  fwd decodes intent
    - Parse data field against bound ABI
    - Match (contract address, function selector) to policy
    - Refuse if unparseable or unbound

5.  fwd evaluates rules
    - Caller in callers list?
    - Contract in allowlist?
    - Method in allowlist?
    - Decoded args within bounds (max_value_wei, recipient pattern)?
    - Rate within window (per_hour, per_day)?
    - Sum of pending + confirmed value below daily cap?
    Default-deny on any failure.

6.  fwd reserves nonce
    BEGIN IMMEDIATE;
    SELECT next_nonce FROM nonces
      WHERE wallet = :w AND chain = :c;
    -- returns current N
    UPDATE nonces SET next_nonce = next_nonce + 1
      WHERE wallet = :w AND chain = :c;
    COMMIT;
    -- caller uses N (the pre-update value)

    (The SELECT-then-UPDATE form is atomic under BEGIN IMMEDIATE; equivalent
    to `UPDATE ... RETURNING next_nonce` on SQLite 3.35+, but the two-step
    form ships as doctrine because the dev-host glibc-2.31 Python ships
    SQLite 3.31 which lacks RETURNING — the Docker runtime has SQLite 3.40+
    but tests run on the host. Cross-environment portability wins; the
    BEGIN IMMEDIATE wrapper provides the atomicity either way.)

    **v0.4.5 doctrine refinement (concurrency-bug fix):** BEGIN IMMEDIATE
    is issued via the `engine.sync_engine "begin"` event listener in
    `infra/db.py`. For this to work without raising "cannot start a
    transaction within a transaction", `dbapi_connection.isolation_level`
    is set to `None` in the connect-event PRAGMA handler — this disables
    sqlite3's implicit BEGIN (DEFERRED) wrap so SQLAlchemy's `begin` event
    is the sole transaction start. AND `busy_timeout` is set to 30000ms
    to absorb concurrent-writer queueing during sign-and-send bursts
    (each request holds the writer lock for the duration of its session;
    Vault decrypt + RPC fee_history + estimate_gas + broadcast + INSERT
    is ~1s; 10 concurrent at 1s/each = 10s, comfortably within 30s).
    **Critically:** signing-flow components (signer, tx_repo, nonce_repo)
    MUST share a single session per request/tick — see `RequestScopeCM`
    in `app/dependencies.py`. The pre-v0.4.5 multi-CM pattern opened 3+
    concurrent sessions per request, each grabbing the writer lock,
    causing in-request self-contention manifest as "database is locked".
    A future Phase 5 follow-up may split the writer-lock critical section
    (reserve-then-commit + work-outside-lock + insert-then-commit) to
    drop writer-lock holding time from ~1s to ~ms; until then, the
    single-session + 30s busy_timeout combo absorbs the concurrency.

7.  fwd queries fee oracle
    - eth_feeHistory for last 5 blocks
    - base_fee + tip suggestion (chain-specific tip floor)

8.  fwd builds EIP-1559 unsigned transaction
    - type 0x02
    - chain_id, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList

9.  fwd retrieves the wallet's wrapped privkey
    - SELECT privkey_ciphertext, vault_master_key FROM wallets WHERE name = :w
    - Result: vault:v1:<ciphertext> blob plus the master-key name

10. fwd asks Vault to decrypt
    POST /v1/transit/decrypt/<vault_master_key>
    Body: { "ciphertext": "vault:v1:<...>" }
    Response: { "data": { "plaintext": "<base64-32-bytes>" } }

11. fwd signs in-process
    - privkey_bytes = base64.b64decode(plaintext)   # 32 bytes
    - signed = Account.from_key(privkey_bytes).sign_transaction(tx_dict)
    - tx_hash = signed.hash
    - signed_raw = signed.raw_transaction

12. fwd zeroizes the plaintext buffer immediately
    - Overwrite privkey_bytes in memory before any further I/O
    - The cached `Account` object (if eth-account caches anything) is discarded

13. fwd broadcasts via JSON-RPC eth_sendRawTransaction

14. fwd records:
    - INSERT INTO transactions (tx_id, wallet, chain, caller, nonce,
                                contract_address, method_name, value_wei,
                                idempotency_key, request_json,
                                signed_raw, status='submitted')
    - INSERT INTO transaction_args (tx_id, arg_name, arg_type, arg_value)
        — one row per decoded argument
    - INSERT INTO transaction_hashes (tx_id, sequence_num=1, hash_hex)
    - INSERT INTO audit_log (caller, action='sign-and-send',
                             request_json, decision='approved',
                             outcome=tx_id, prev_hash, row_hash)

15. fwd returns { tx_id, hash, nonce } to caller

16. Receipt watcher (asyncio task, runs every block):
    - Poll eth_getTransactionReceipt for each pending tx
    - On confirmation: status='mined', call nonce_repo.mark_confirmed(wallet, chain, nonce)
    - On stuck (N blocks elapsed): replace with bumped tip,
      append a new row to transaction_hashes (tx_id, sequence_num=N+1, hash_hex), audit row
    - On final failure (5 retries): status='failed', surface alert
```

### Failure modes in the signing flow

The v0.1.2 envelope-encryption design introduces `transit/decrypt/fwd-master` as a new failure point in the critical path. The principle: **if the failure occurs before broadcast (steps 1–12), the reserved nonce is released back to the pool in the same SQLite transaction; if at or after broadcast (steps 13+), the nonce stays committed and the receipt watcher reconciles.**

| Step | Failure | Response | Nonce |
|---|---|---|---|
| 6 | SQLite busy / lock timeout on nonce reservation | 409 `nonce_unavailable`; caller may retry | Not committed |
| 7 | RPC timeout on `eth_feeHistory` | 502 `rpc_failed` (after one retry) | Not committed |
| 9 | Wallet not found | 404 `wallet_not_found` | Not committed |
| 10 | **Vault decrypt fails** (sealed, network failure, key version mismatch) | **503 `vault_unavailable`. Reserved nonce is RELEASED in the same SQLite transaction (`UPDATE nonces SET next_nonce = next_nonce - 1 WHERE wallet = :w AND chain = :c AND next_nonce - 1 = :reserved`).** No on-chain side effect. | Released |
| 11 | `eth-account` rejects `tx_dict` (malformed) | 422 `intent_unparseable` | Released |
| 13 | RPC `eth_sendRawTransaction` rejects (invalid signature, nonce too low, etc.) | 502 `rpc_failed` | **Stays committed** — the tx may have been seen by other nodes; receipt watcher decides whether to replace |
| 13 | RPC timeout (response unknown) | Treat as committed: status='submitted' with no on-chain hash yet; receipt watcher polls `eth_getTransactionCount` to detect on-chain landing | Stays committed |

Every failure writes an audit row recording the caller, the request, the failed step, and the response code. The structlog scrubber (see `## Implementation hazards` below) ensures no plaintext privkey reaches the audit log under any failure path.

## SQLite schema

```sql
CREATE TABLE wallets (
    name                 TEXT PRIMARY KEY,
    address              TEXT NOT NULL,
    privkey_ciphertext   TEXT NOT NULL,        -- vault:v1:<base64> envelope from transit/encrypt
    vault_master_key     TEXT NOT NULL,        -- name of the Transit key used to encrypt (e.g. "fwd-master")
    policy_path          TEXT NOT NULL,
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE wallet_chains (
    wallet TEXT NOT NULL REFERENCES wallets(name),
    chain INTEGER NOT NULL,
    PRIMARY KEY (wallet, chain)
);

CREATE TABLE callers (
    name TEXT PRIMARY KEY,
    api_key_hash TEXT NOT NULL UNIQUE,       -- argon2id of the bearer token
    api_key_prefix TEXT NOT NULL,            -- first 8 chars for ops display
    policy_path TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP
);

CREATE TABLE nonces (
    wallet TEXT NOT NULL REFERENCES wallets(name),
    chain INTEGER NOT NULL,
    next_nonce INTEGER NOT NULL,
    last_confirmed INTEGER,
    last_reconciled_at TIMESTAMP NOT NULL,
    PRIMARY KEY (wallet, chain)
);

CREATE TABLE transactions (
    tx_id            TEXT PRIMARY KEY,            -- UUIDv7
    wallet           TEXT NOT NULL REFERENCES wallets(name),
    chain            INTEGER NOT NULL,
    caller           TEXT NOT NULL REFERENCES callers(name),
    nonce            INTEGER NOT NULL,
    contract_address TEXT NOT NULL,               -- decoded from request.data
    method_name      TEXT NOT NULL,               -- decoded from request.data
    value_wei        TEXT NOT NULL,               -- decimal string; SQLite has no uint256
    idempotency_key  TEXT,                        -- caller-supplied via header; optional
    request_json     TEXT NOT NULL,               -- opaque archive of original request
    signed_raw       TEXT,                        -- hex of latest signed tx
    status           TEXT NOT NULL,               -- pending|submitted|mined|replaced|failed
    submitted_at     TIMESTAMP,
    confirmed_at     TIMESTAMP,
    receipt_json     TEXT,                        -- opaque archive of RPC receipt
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_tx_idempotency
  ON transactions (caller, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE TABLE transaction_args (
    tx_id     TEXT NOT NULL REFERENCES transactions(tx_id),
    arg_name  TEXT NOT NULL,
    arg_type  TEXT NOT NULL,                      -- "address", "uint256", "bytes32", ...
    arg_value TEXT NOT NULL,
    PRIMARY KEY (tx_id, arg_name)
);

CREATE TABLE transaction_hashes (
    tx_id        TEXT NOT NULL REFERENCES transactions(tx_id),
    sequence_num INTEGER NOT NULL,                -- 1 = first submission, 2+ = replacements
    hash_hex     TEXT NOT NULL,
    submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tx_id, sequence_num)
);

CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    caller TEXT,
    action TEXT NOT NULL,                         -- sign-and-send | sign-typed-data | admin-* | ...
    request_json TEXT,
    decision TEXT NOT NULL,                       -- approved|denied|error
    decision_reason TEXT,
    outcome TEXT,                                 -- tx_id, error code, etc.
    prev_hash TEXT NOT NULL,                      -- hash of previous row (genesis = '0' * 64)
    row_hash TEXT NOT NULL                        -- sha256(canonical_json({prev_hash,ts,caller,action,request_json,decision,decision_reason,outcome})); see D16 / § Audit log (a1 NUL-join form retired at v0.5.0a2)
);

CREATE INDEX idx_tx_status ON transactions (status);
CREATE INDEX idx_tx_wallet_chain_nonce ON transactions (wallet, chain, nonce);
CREATE INDEX idx_tx_method ON transactions (method_name, contract_address);
CREATE INDEX idx_audit_caller_ts ON audit_log (caller, ts);
```

PRAGMAs at startup: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=30000`, `foreign_keys=ON`, plus `dbapi_connection.isolation_level=None` set in the `connect` handler (disables sqlite3's implicit `BEGIN (DEFERRED)` so SQLAlchemy's `begin` event handler is the sole transaction start; v0.4.5 fix). The 30 s `busy_timeout` (bumped from 5 s at v0.4.5) absorbs concurrent-writer queueing during sign-and-send bursts.

## API surface

Frozen for v1.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/sign-and-send` | caller | Build → policy → sign → broadcast |
| `POST` | `/v1/sign-typed-data` | caller | EIP-712 signing |
| `GET` | `/v1/wallets` | caller | List wallets accessible to caller |
| `GET` | `/v1/transactions/{tx_id}` | caller | Status + hash history + receipt |
| `GET` | `/v1/audit` | admin | Hash-chained audit log (paginated) |
| `GET` | `/healthz` | none | Liveness + Vault sealed status + RPC reachability |
| `POST` | `/v1/admin/wallets` | admin | Generate privkey internally, encrypt via Vault `fwd-master`, persist ciphertext, return address. See § Wallet provisioning. |
| `POST` | `/v1/admin/callers` | admin | Issue caller API key |
| `DELETE` | `/v1/admin/callers/{name}` | admin | Revoke caller |

Admin endpoints require a separate `FWD_ADMIN_KEY` configured at boot. Admin authentication is not policy-controlled — it's the bootstrap.

## Wallet provisioning

Two paths in v1: **create** (`fwd` generates a fresh privkey) and **import** (operator provides an existing privkey via file). Neither path returns plaintext to any caller; plaintext exists in `fwd`'s process memory only during the bounded provisioning operation, then is zeroized per Core invariant #16.

### Create

Generate a fresh wallet. Available via HTTP and CLI:

```
POST /v1/admin/wallets
Headers:
  Authorization: Bearer <FWD_ADMIN_KEY>
Body:
  { "name": "register-coston2-test", "policy_path": "register-coston2-test" }
Response (201):
  { "name": "register-coston2-test", "address": "0x..." }

# Equivalent CLI:
clifwd wallets create --name register-coston2-test --policy register-coston2-test
```

Flow:

1. Validate `name` is unique; if not, 409 `wallet_exists`.
2. Generate privkey via `eth_account.Account.create()` and immediately wrap as `bytearray` for zeroization.
3. Derive the EIP-55 address from the public key.
4. Encrypt the privkey via `transit/encrypt/fwd-master` → `vault:v1:<ciphertext>`.
5. `INSERT INTO wallets (name, address, privkey_ciphertext, vault_master_key='fwd-master', policy_path, created_at)`.
6. Zeroize the plaintext bytearray.
7. Audit row: `action='wallet-create', caller=<admin>, outcome=<address>`.
8. Return `{ name, address }`.

### Import

Use `clifwd wallets import` to provision a wallet from an existing 32-byte secp256k1 private key. **CLI only — no HTTP endpoint** (see `decisions.md` D9 for rationale):

```
clifwd wallets import \
    --name <wallet_name> \
    --policy <policy_path> \
    --privkey-file <absolute_path_to_hex_file> \
    [--expected-address 0x...] \
    [--shred-source]
```

The `--privkey-file` must be a regular file, mode `0600`, owned by the user running `clifwd`, containing exactly 32 bytes hex-encoded (no `0x` prefix; an optional trailing newline is permitted).

Refusal table (CLI exits with code 2 and prints a clear error):

| Condition | Response |
|---|---|
| File does not exist | `privkey-file not found: <path>` |
| File mode is not `0600` | `privkey-file mode must be 0600 (got <octal>)` |
| File owner doesn't match current user | `privkey-file must be owned by the user running clifwd` |
| Content doesn't decode to exactly 32 bytes | `privkey-file must contain a 32-byte hex-encoded secp256k1 private key (got <n> bytes)` |
| Wallet name already exists | `wallet '<name>' already exists` |
| `--expected-address` provided AND derived doesn't match | `derived address <X> does not match --expected-address <Y>` |

Flow on success:

1. Read file content; verify mode + ownership via `os.stat`.
2. `bytes.fromhex(content.strip())` → 32-byte privkey, immediately wrapped as `bytearray`.
3. Derive the EIP-55 address; verify against `--expected-address` if provided.
4. Encrypt the privkey via `transit/encrypt/fwd-master` → `vault:v1:<ciphertext>`.
5. `INSERT INTO wallets (...)`.
6. Zeroize the plaintext bytearray.
7. Audit row: `action='wallet-import', caller=<operator-uid>, request_json={name, source_file_path, source_file_mode, source_file_owner}, outcome=<address>` — the privkey itself is NOT in the audit; only the source-file metadata.
8. If `--shred-source`: run `shred -u <path>` (overwrites then unlinks). Exit non-zero with a warning if `shred` fails — the wallet is provisioned but the source file remains on disk for the operator to handle.
9. Print `{ name, address }`.

**Why CLI-only.** A privkey traversing HTTP enters TLS termination logs, FastAPI access logs, reverse-proxy memory, and any load-balancer headers. CLI-only forces the privkey through a single operator-controlled file path with explicit mode and ownership checks. See `decisions.md` D9 for the full rationale and rejected alternatives.

### Export

Not supported in v1. See `decisions.md` D9 § "When to revisit" for the deferred reasoning. Real-world "export" use cases are handled by:

| Use case | v1 mechanism |
|---|---|
| Disaster recovery (host failure) | Litestream restore (SQLite ciphertext) + Vault Raft snapshot restore (master key) on a new host. The wallet keeps signing without any plaintext ever existing on disk. |
| Migration to a hardware wallet | Generate a new wallet on the HW device, transfer balance on-chain, retire the old `fwd`-resident wallet. |
| Forensics / non-repudiation | `GET /v1/audit` walks the hash-chained audit log; the signed transactions themselves are forensic evidence. |

## Idempotency

Callers SHOULD send an `Idempotency-Key` header on every `POST /v1/sign-and-send`. The contract:

| Field | Value |
|---|---|
| Header name | `Idempotency-Key` |
| Format | UUIDv7 (recommended) — any opaque string up to 128 chars |
| Required? | Optional in v1, recommended for all retry-tolerant callers |
| Scope | Per-caller — same key used by two different callers is two distinct requests |
| Storage | `transactions.idempotency_key` with unique index on `(caller, idempotency_key)` |
| TTL | Indefinite — keys are first-class identifiers, not cache entries |

**Behavior on duplicate:**
- If a request arrives with an `(caller, Idempotency-Key)` pair that already exists in `transactions`, `fwd` returns the original `tx_id` and current status with HTTP 200.
- The duplicate request is NOT re-signed, NOT re-broadcast, and NOT re-policy-checked.
- The duplicate is recorded in the audit log as `action='sign-and-send-duplicate'` with `outcome=<original tx_id>`.

**Behavior on missing header:** request proceeds normally; no idempotency protection applies. Recommended for one-shot ad-hoc operator calls; not recommended for automated callers.

This contract is documented in v0.1.1; the replay implementation **shipped v0.5.0a7** (`api/sign.py` reads the `Idempotency-Key` header — ≤128 chars, else 400 `bad_idempotency_key`; `app/sign_and_send.py` checks `(caller, key)` via `TransactionRepo.get_by_idempotency_key` before the policy gate and, on a hit, returns the cached `tx_id` + seq-1 hash with a `sign-and-send-duplicate` audit row, no re-sign / re-broadcast / re-policy).

## Error envelope

All `4xx` and `5xx` responses from `/v1/*` endpoints return a JSON body with this shape:

```json
{
  "code": "policy_denied",
  "message": "human-readable description, safe to log",
  "request_id": "uuid-v7"
}
```

Stable error codes:

| Code | HTTP | Meaning |
|---|---|---|
| `auth_failed` | 401 | Missing or invalid API key |
| `policy_denied` | 403 | Caller authenticated but action denied by policy |
| `rate_exceeded` | 403 | Within policy but over rate window |
| `wallet_not_found` | 404 | Named wallet does not exist or caller cannot see it |
| `intent_unparseable` | 422 | `data` field could not be ABI-decoded against the bound contract |
| `nonce_unavailable` | 409 | Nonce reservation contention; caller may retry |
| `idempotency_replay` | 200 | Duplicate request; original `tx_id` returned (not actually an error — listed for completeness) |
| `vault_unavailable` | 503 | Vault sealed, unreachable, or returned error |
| `rpc_failed` | 502 | Upstream JSON-RPC error |
| `internal_error` | 500 | Unhandled exception |

The response body MUST NOT contain: SQL state, Python tracebacks, Vault error responses, RPC error responses, internal stack frames, environment variable values, file paths, or caller API keys. Sensitive details land in the audit log and structured server logs only.

## Versioning

The HTTP API is versioned via path prefix (`/v1/*`).

- **Field additions** to existing endpoint requests/responses are non-breaking and ship without a version bump.
- **Field removals**, **semantic changes**, **error-code changes**, and **endpoint removals** are breaking and require `/v2/*`.
- When `/v2/*` ships, `/v1/*` is supported for at least 6 months and ≥1 reward epoch on every chain `fwd` serves.
- Deprecation of `/v1/*` is announced via a `Deprecation: true` header on `/v1/*` responses for at least 30 days before removal.

## Vault configuration

| Setting | Value | Why |
|---|---|---|
| Storage backend | Raft (single-node, file-based) | Simplest backend that supports Transit |
| Auto-unseal | None in v1 | Manual Shamir unseal; auto-unseal is Phase 10 |
| Shamir threshold | 3 of 5 | Survives loss of any 2 share locations |
| Engines mounted | `transit/` | Only Transit; no KV needed in v1 |
| Key type | `aes256-gcm96` | Symmetric AES-256-GCM; Vault encrypts/decrypts arbitrary 32-byte plaintext (the secp256k1 privkey) |
| Key flags | `exportable=false`, `derived=false`, `allow_plaintext_backup=false` | Keys cannot be extracted via API |
| Auth methods | `approle` (for `fwd` itself) | One AppRole per `fwd` deployment; role ID + secret ID via env |
| Listener | TCP 8200 on `fwd-internal` only | Not reachable from host |
| TLS | Internal CA, self-signed | TLS within Docker network for defense-in-depth |
| Audit device | `file` → `/vault/logs/audit.log` | Vault's own audit (separate from `fwd`'s audit) |

`fwd`'s Vault policy:

```hcl
path "transit/encrypt/fwd-master" {
  capabilities = ["update"]
}

path "transit/decrypt/fwd-master" {
  capabilities = ["update"]
}

path "transit/keys/fwd-master" {
  capabilities = ["read"]
}

# NO transit/sign/*, NO transit/keys/+/export, NO transit/keys/+/rotate, NO transit/keys/+/config
```

## Auth lifecycle

Per `decisions.md` D10, `fwd` uses a staged token-management strategy: minimum viable in v1, proactive renewal at Phase 7, periodic tokens at Phase 8 if warranted.

### v1 (Phase 3b–6)

| Event | Action |
|---|---|
| `fwd` startup | `POST /v1/auth/approle/login` with `(FWD_VAULT_ROLE_ID, FWD_VAULT_SECRET_ID)` from env. Cache `client_token`, `lease_duration`, `lease_renewable` in `mlock`-protected memory. |
| Any Vault call (`encrypt`, `decrypt`) | Send with `X-Vault-Token: <client_token>` header. |
| 403 from any Vault call | Re-auth (single fresh `auth/approle/login`). Update cached token. Retry the failed call exactly once. If retry also returns 403, surface the error to the caller. |
| `fwd` shutdown | No explicit token revocation; the token expires naturally at `token_ttl`. Cached token bytes are zeroized in `__aexit__`. |

No background task. No proactive renewal. Suitable for v1 volumes (wallet creation: rare; signing: ~once per FTSO epoch / per register tx / etc., well below the 24h TTL).

### Phase 7 hardening (v0.5.0)

Add an asyncio background task started in `VaultClient.__aenter__`:

- Sleeps `lease_duration / 3` seconds at a time.
- If renewable AND `now + (lease_duration / 3) < max_ttl_deadline`: `POST /v1/auth/token/renew-self`. Update `expires_at`.
- Else: full re-auth via `auth/approle/login`. Update cached token.
- Cancel-clean on `__aexit__`.

The 403 fallback in `_request()` stays as defense-in-depth (clock skew, vault failover, race between renewal and 403, manual revocation).

### Phase 8 production (v1.0.0)

When the first production consumer migrates, the operator evaluates switching the AppRole `fwd` role from `(token_ttl=24h, token_max_ttl=72h)` to `(token_period=24h, token_max_ttl=0)`. Periodic tokens can be renewed indefinitely within `period` seconds; the 72h `max_ttl` re-auth boundary disappears. Same client code on either side; only the role config changes.

Migration procedure (operator runbook, lands at Phase 8):

```sh
docker compose stop fwd
docker exec -e VAULT_TOKEN=<root-token> fwd-vault \
    vault write auth/approle/role/fwd \
    token_policies=fwd-app \
    token_period=24h \
    token_max_ttl=0 \
    secret_id_ttl=0 \
    secret_id_num_uses=0
docker compose start fwd
```

Trade-off: no automatic credential rotation. Operator-driven `secret_id` rotation (quarterly, or on incident) becomes the periodic hygiene task.

## Policy YAML format

Authoritative shape per `decisions.md` D13 (caller-keyed indirection) +
D14 (Phase 7 implementation refinements). Loaded once at startup from
`$FWD_POLICY_PATH` (default `/etc/fwd/policy.yaml`); operator mounts via
docker-compose volume bind. The file is **operator-controlled and
gitignored** (Core invariant #12).

```yaml
version: 1

callers:
  ftso-fee-claimer-prod:
    policy_path: ftso-claim

wallets:
  claim-recipient-flare-prod:
    policy_path: claim-recipient

permissions:
  ftso-claim:
    contracts:
      "0xRewardManager...":              # checksummed; case-insensitive at match
        abi: reward_manager              # references config/abis/registry.yaml
        methods:
          "claim(address,uint256)":      # full ABI signature, not bare name
            max_value_wei: "0"           # decimal string, parsed to int
            arg_predicates:
              recipient: "0x7c3579ab3e647395c96a1efc98af9a31c5ecc294"
              epochId: any               # sentinel; matches any decoded value
    wallet_allowlist: ["claim-recipient-flare-prod"]
    rate:                                # per (caller, wallet, contract, method)
      per_hour: 100
      per_day: 1000

wallet_constraints:
  claim-recipient:
    max_aggregate_value_wei_per_day: "0"
    rate:
      per_hour: 200
      per_day: 2000
```

**Reload.** Startup-only in v1 (D14 operator decision). Policy.yaml
changes require `docker compose restart fwd`. SIGHUP hot-reload deferred
to Phase 10.

## Policy engine

The Phase 7 policy engine evaluates each `/v1/sign-and-send` request
against the loaded `policy.yaml`. Pure-function shape (per D14):

Shipped shape (v0.5.0a4, `app/policy_engine.py` — aligned to code per
Core invariant #18; the a1 sketch's `rate_buckets_advanced` audit-reason
carrier is deferred to v0.5.0a5 where the audit log lands):

```python
@dataclass(frozen=True)
class AllowDecision:
    decoded: DecodedIntent       # the typed intent that passed
    matched_policy_path: str     # the binding's policy_path

@dataclass(frozen=True)
class DenyDecision:
    step: int                    # 0 = unexpected error; 1..9 = failing D14 step
    reason: str                  # e.g. "max_value_wei exceeded"

async def evaluate(
    *,
    caller: Caller,
    wallet: Wallet,
    request: SignAndSendRequest,
    policy: Policy,
    registry: AbiRegistry,
    rate_repo: RateRepo,
    now: datetime,
) -> AllowDecision | DenyDecision: ...
```

Evaluation order is the 10 steps in D14. The entire body is wrapped in
`try/except Exception → DenyDecision(step=0)` — `evaluate` never raises
(default-deny, Core invariant #2). Every `Deny` carries the step number
for forensics.

**Live wiring (shipped v0.5.0a6).** `app/policy_gate.py` (`gate()` →
`PolicyDenied` on Deny; `release_rate_after_failure()`) is called by
`app/sign_and_send.py` BEFORE nonce reservation: a denied request never
reserves a nonce, never signs, never broadcasts (the synthetic-attack
matrix asserts `rpc.send_raw_transaction` is not awaited for all 10
deny vectors). The v0.3.0 Coston2-only chain allowlist was **lifted** —
`policy.yaml` (via the engine) is now the sole authorization;
`infra/rpc.py::ALLOWED_CHAINS` is reduced to the RPC-routing rail
(`{14,19,114}` = chains fwd has a configured URL for). Rate
release-on-failure mirrors the nonce release (engine increments at
step 8/9; a pre-broadcast failure calls `release_rate_after_failure`
with keys re-derived from the `AllowDecision` + policy);
`add_committed_value` (wallet aggregate) is added ONLY on broadcast
success, with the same `now` the engine used.

**Rate-limit state** lives in two SQLite tables (Alembic 0005,
v0.5.0a4, `infra/rate_repo.py`): `rate_buckets` (caller × wallet ×
contract × method × window counter) and `wallet_buckets` (wallet ×
window aggregate value sum + counter). Windows are fixed UTC-aligned
(D14 operator decision: trade boundary bursts for simplicity). Buckets
older than the largest configured window are deleted at policy-load
time — `RateRepo.delete_stale()` ships at v0.5.0a4 (substrate); its
policy-load-path invocation **shipped v0.5.0a7** (`_startup_policy_load`
success branch prunes `window_start` older than 2 days — older than the
largest `hour`/`day` window — wrapped so a prune failure logs
`lifespan.delete_stale_failed` and never blocks boot). The earlier
"deferred to v0.5.0a7" marker is retired.

**Startup fail-fast** (`infra/policy_loader.py::check_consistency`)
runs after policy load: an active caller is an orphan unless it is
declared in `policy.callers` **by NAME**, its stored `policy_path`
matches the binding's `policy_path` (drift detection, mirrors
`policy_engine` step 1), and the binding resolves to a `permissions`
block; `wallet_allowlist` entries must resolve to a known wallet (DB
row or `policy.wallets` key); `policy.wallets` bindings must resolve to
`wallet_constraints`; each contract `abi` must be a registered ABI
name; AND (check 3, **shipped v0.5.0a6**) every `methods.<sig>` under
a known-abi contract must resolve against
`AbiRegistry.signatures_for(abi)` (added a6). Any failure → fwd
refuses to serve (fail-fast: `_startup_policy_load` writes a
`policy-load` `decision="error"` audit row, commits it, then
`SystemExit(1)`).

## Intent decoder

ABI-based calldata decoder. Pure function in `src/fwd/domain/intent.py`
(no I/O):

```python
def decode_intent(
    contract: str,             # lowercased 0x-hex (NOT checksummed)
    calldata: bytes,           # raw calldata incl. 4-byte selector
    abi_fn_entry: dict,        # the resolved ABI function entry
) -> DecodedIntent | None: ...
```

Returns `None` (NOT raises) on any decode **failure** — selector
mismatch, truncated/malformed bytes, codec error. It does NOT return
`None` because a non-scalar top-level arg is present (B1 projection —
see below). Caller treats `None` as default-deny. `address` is passed
through unchanged: `eth_abi` 5.x already returns it as a lowercase
`0x`-hex `str` (the older "strip 32→20 and lowercase" doctrine was
wrong for the installed library; corrected v0.5.0a3).

**ABI registry.** In-repo `config/abis/` (D15 operator decision: ABIs
are public; commit them, pin them, no runtime fetch). Loaded once at
startup; in-process index keyed by **`(abi_name, selector_hex)`** —
address-agnostic. `request.to → abi_name` is a `policy.yaml` binding
(D14); the policy engine composes address→abi_name→registry.lookup.
Only `nonpayable`/`payable` functions are indexed.

```
config/abis/
  registry.yaml              # name → file mapping
  reward_manager.json        # FTSO RewardManager (Flare + Coston2)
  participant_register.json  # apregister (Coston2 + future Flare)
  erc20.json                 # canonical ERC-20 (transfer, approve)
```

**v0.5.0 type support** (expanded at v0.5.0a2 self-review to cover
ParticipantRegister's `string` fields):

- `address` — lowercased 0x-hex
- `uint*` / `int*` — Python int (eth_abi handles two-complement)
- `bool` — Python bool
- `bytesN` (N ≤ 32) — 0x-hex string
- `bytes` (dynamic) — 0x-hex string of raw bytes
- `string` (dynamic) — Python `str` (UTF-8)

**B1 projection** (corrected v0.5.0a3): top-level args of type dynamic
array / fixed array / tuple / struct / function are **decoded by
eth_abi but omitted from `DecodedIntent.args`** — they stay visible in
`method_signature`. The decoder does NOT return `None` for these (the
a1 "returns None" framing would have blocked Phase 8's FTSO `claim`,
whose proof arg is `(bytes32[],(uint24,bytes20,uint120,uint8))[]`). The
four custody-relevant `claim` scalars are projected and predicatable;
the proof array is not (nobody predicates merkle internals). The
**signable** methods of all three v0.5.0 ABIs are decodable this way;
the prior claim that these ABIs "do not use unsupported types" was
false at the ABI level (their `view` methods + FTSO proof arrays use
tuples/arrays) — it holds only for the signable surface, via B1. Deep
dotted-path predicate projection is a Phase 10 item if a real consumer
needs it (no speculative scope).

## Audit log

Phase 7 fills v0.4.0a3's empty `audit_log` schema. Authoritative
hash-chain mechanics per `decisions.md` D16. **Substrate/integration
split (Core invariant #18):** the substrate — `infra/audit_repo.py`
(`AuditRepo`, `_canonical_json`, `_row_hash`, `_as_utc`,
`GENESIS_PREV_HASH`), `app/audit_walk.py`, the `clifwd audit` CLI, the
`AuditRepoCM` dependency — shipped at **v0.5.0a5**. **Shipped
v0.5.0a6:** the `sign-and-send` row authorship (denied/error/approved
via `app/policy_gate.py` + `app/sign_and_send.py` on the shared
`RequestScope` session), the lifespan `policy-load` row
(`_startup_policy_load`), and unifying `sign_and_send`'s `request_json`
onto `_canonical_json`. **Shipped v0.5.0a7:** the `wallet-*` /
`caller-*` admin-action rows (a keyword-only `audit_repo` threaded
through the four admin use cases — one row per call, success or
known-failure, NO secret in `request_json`/`outcome`) + `AdminScope`/
`AdminScopeCM`, plus the idempotency-replay `sign-and-send-duplicate`
row. Both deferral markers retired (Core invariant #18). The
chain-walker self-write `audit-verify-failure` row remains **Phase 10**
(gated on the on-chain anchor — see "Tamper evidence", D16).

**Row shape** (Alembic 0004 — already shipped):
- `seq INTEGER PRIMARY KEY AUTOINCREMENT`
- `ts TIMESTAMP NOT NULL`
- `caller TEXT` — NULL for admin-keyed actions
- `action TEXT NOT NULL` — enum: `sign-and-send`, `sign-and-send-duplicate`, `wallet-create`, `wallet-import`, `caller-create`, `caller-revoke`, `policy-load`, `audit-verify-failure` (the last is accepted by `AuditRepo.append` from a5 but written by NO v0.5.0 path — the chain-walker self-write-on-break is **Phase 10**, gated on the on-chain anchor that closes the tamper-evidence recursion; see D16)
- `request_json TEXT` — canonical sorted-key compact JSON of request payload
- `decision TEXT NOT NULL` — `approved` | `denied` | `error`
- `decision_reason TEXT` — human-readable, e.g. `"policy_denied step=5: max_value_wei exceeded"`
- `outcome TEXT` — canonical sorted-key compact JSON of outcome payload
- `prev_hash TEXT NOT NULL` — hex SHA-256 of preceding row's `row_hash`; genesis = `'0' * 64`
- `row_hash TEXT NOT NULL` — `sha256(canonical_json_dump({prev_hash, ts, caller, action, request_json, decision, decision_reason, outcome}).encode('utf-8')).hexdigest()` where canonical_json_dump uses `sort_keys=True, separators=(',',':'), ensure_ascii=False`. Revised at v0.5.0a2 self-review from the original NUL-joined concatenation, which was collision-fragile for fields that may contain literal NUL bytes (caller name, decision_reason).

**Concurrency (a6 target).** Once integrated, audit writes happen
INSIDE the request's RequestScope session (v0.4.5
single-session-per-request invariant). One writer-lock acquisition
covers nonce reservation + transaction INSERT + audit_log INSERT +
rate-bucket increment. Estimated additional lock-holding time from
audit + rate: ~5–10 ms on top of the existing ~1 s Vault decrypt +
RPC. Within 30 s busy_timeout headroom; no lock-split refactor in v1.
(a5 ships `AuditRepoCM` as a standalone session CM; `RequestScope` is
extended to carry `AuditRepo` at a6.)

**Walker CLI** shipped at v0.5.0a5 — `clifwd audit verify | show |
tail`, canonical invocation `docker exec fwd clifwd audit verify` (D16
walker access pattern). Layering: `cli/audit.py` → `app/audit_walk.py`
→ `infra/audit_repo.py` (cli may not import infra directly). `verify`
walks `seq` order, checking each row's stored `prev_hash` against the
expected predecessor (genesis `'0'*64` for the table-minimum row, else
the prior row's stored `row_hash`; a windowed walk anchors on
`from_seq - 1` and breaks if that anchor is absent) AND the recomputed
`row_hash` (`_as_utc(row.ts)` keeps the SQLite tz-drop round-trip
symmetric). Exits 0 on an intact range; 2 (stderr `CHAIN BROKEN at
seq=<n>`) at the first mismatch. `show` exits 1 if the seq is absent;
`tail` prints the last N (default 20) ascending.

**Backfill.** None. The audit log records forward from v0.5.0 only.
Pre-Phase-7 wallets, callers, and transactions have no audit history.

**Tamper evidence vs tamper prevention.** v0.5.0 is tamper-evident —
the chain is only as anchored as the operator's out-of-band snapshots
of `clifwd audit verify`. Phase 10 on-chain anchor (weekly Merkle root
commit to Flare via fwd itself) closes the recursion.

## Backup and restore

**Continuous:** Litestream replicates `state.db` to Scaleway Object Storage every 10s with ~1MB WAL bursts. Bucket: `s3://ap-fwd-backups/<host-name>/state.db.litestream/`.

**On-demand Vault snapshots:** `vault operator raft snapshot save vault-snapshot-<ts>.bin` — runs nightly via host cron, uploaded to the same bucket under `vault-snapshots/`. Encrypts at rest with the existing Vault master key.

**Restore drill (documented in `runbooks/restore.md`):**
1. `docker compose down`
2. `litestream restore -o state.db s3://ap-fwd-backups/<host>/state.db`
3. `vault operator raft snapshot restore vault-snapshot-<ts>.bin`
4. `docker compose up -d`
5. Unseal Vault (3 of 5 shares)
6. Verify nonce reconciliation against on-chain state via `clifwd reconcile`
7. Confirm `/healthz` reports green

Target RTO: 30 minutes from a clean host.

## Observability

| Surface | Mechanism | v1 / v2 |
|---|---|---|
| Liveness / readiness | `GET /healthz` | v1 |
| Audit log | `GET /v1/audit` + CLI walker that verifies the hash chain | v1 |
| Structured logs | `structlog` JSON to stdout, captured by Docker | v1 |
| Prometheus metrics | `/metrics` endpoint, `prometheus-client` gauges/counters | v2 (Phase 10) |
| Alerting | Out of scope for v1 | v2 |
| On-chain audit anchor | Weekly commit of audit-log Merkle root to a registry contract | v2 (Phase 10) |

Default-deny in v1 is verified by a synthetic-attack integration test (Phase 7 gate): a caller with no wallet permissions tries to sign; the audit log records the denial; the test reads the row and asserts the chain link integrity.

## Layer boundaries

`fwd` follows a four-layer separation. Each layer's responsibilities and prohibitions are pinned; the package layout enforces them; an import-graph test landed in Phase 2 catches violations.

### Domain (`src/fwd/domain/`)

Pure business logic. Policy evaluation, intent decoding, nonce reservation rules, audit-chain hashing, EIP-1559 RLP encoding, DER parsing, low-S normalization, v-recovery from a digest + (r, s) pair to a candidate address.

**Must NOT:**
- Import from `infra/`, `app/`, or `api/`
- Touch SQLite, Vault, RPC, FastAPI, environment variables, or the filesystem
- Take any I/O dependency, async or sync

### Application (`src/fwd/app/`)

Use-case orchestrators. The `sign-and-send` flow that calls `auth → policy → nonce → sign → broadcast → audit` in order, coordinating between domain and infrastructure adapters.

**Must NOT:**
- Implement signing math, RLP encoding, or hash-chain hashing (those are domain)
- Format HTTP responses or CLI output (those are interface)
- Import from `api/`

### Infrastructure (`src/fwd/infra/`)

External-system adapters. `EnvelopeSigner` (decrypts wallet ciphertexts via Vault and signs in-process with `eth-account`), SQLite repositories, JSON-RPC client, Litestream sidecar config, structlog setup, argon2id hasher, ABI-loader filesystem reader.

**Must NOT:**
- Make policy decisions
- Mutate the audit log directly (only the application layer composes audit rows; infra writes them at application's request)
- Import from `app/` or `api/`

### Interface (`src/fwd/api/` and `src/fwd/cli/`)

HTTP handlers (FastAPI routes) and CLI commands (Typer subcommands). Translates external requests into application-layer calls; formats responses; returns the error envelope shape documented above.

**Must NOT:**
- Decode calldata, manage nonces, call Vault directly, write to SQLite directly
- Contain branching policy logic
- Import from `infra/` directly — interface always goes through `app/`

### Enforcement

Phase 2's scaffold pins this layout in `pyproject.toml` and adds `tests/unit/test_layer_boundaries.py` that walks the import graph and fails if any rule above is violated. The test is a hard CI gate.

## Implementation hazards (v0.1.2 envelope encryption)

Three implementation patterns specific to the v0.1.2 envelope-encryption signing flow. Each is enforced by code or test as of v0.3.2 (Phase 3 GA + audit corrections); this section documents the invariants and points to the enforcing code/test.

### 1. No plaintext caching between requests

Core invariant #16 (decrypt-on-demand, zeroize-on-completion) forbids caching plaintext private keys in process-wide state between signing operations. Every `/v1/sign-and-send` decrypts → signs → zeroizes, even if the same wallet was used 10 milliseconds ago.

**Enforced by:** `tests/unit/test_envelope_signer.py::test_no_32byte_state_after_create_wallet` and `::test_no_32byte_state_after_sign_transaction` (added in v0.3.2). Each test runs the relevant operation, then walks `signer.__dict__` and fails on any attribute that is a `bytes`/`bytearray` of length 32.

**Why this matters:** an attacker who compromises `fwd` with a cache present can dump every cached privkey in one shot; without a cache, they must wait for and intercept a signing event per wallet — an attack that is detectable in Vault's audit log as a burst of `transit/decrypt` calls.

### 2. `bytearray`, not `bytes`, for privkey buffers

Python's `bytes` is immutable: you cannot zeroize it. The signing flow uses `bytearray` from the moment the privkey enters the process to the moment it's overwritten:

```python
# CORRECT (the pattern used in src/fwd/infra/envelope_signer.py)
privkey = bytearray(base64.b64decode(plaintext))   # mutable
... sign with bytes(privkey) ...                   # cast for the API call only
for i in range(len(privkey)):
    privkey[i] = 0                                 # in-place overwrite

# WRONG
privkey = base64.b64decode(plaintext)              # immutable bytes; cannot be zeroized
... sign with privkey ...
del privkey                                        # garbage; the underlying buffer may persist
```

The v0.2.0 spike's `zeroize()` helper (preserved verbatim in `docs/history/0.2.0-spike-coston2.md`) is the canonical pattern; `src/fwd/infra/envelope_signer.py::_zeroize` is its production form.

**Enforced by:** `tests/unit/test_envelope_signer.py::test_zeroize_overwrites_bytearray_in_place` (direct test of `_zeroize`), `::test_create_wallet_buffer_is_all_zero_after_zeroize`, and `::test_sign_transaction_buffer_is_all_zero_after_zeroize` (spy-patched `_zeroize` snapshots the buffer state after the in-place overwrite; assertion is `bytes(buf) == b"\x00" * 32` AND `isinstance(buf, bytearray)`). Added in v0.3.2.

**Caveat:** Python's GC may have already copied the bytes object internally before it was wrapped in `bytearray()`. This is a best-effort mitigation, not a hard guarantee. True zero-copy privkey handling requires a C extension or `ctypes`-based memory pinning; that complexity is acceptable in Phase 10 hardening, not v1.

### 3. Structlog scrubber redacts hex-shaped 32-byte values

The most severe disclosure path under v0.1.2 is a logged privkey — accidental `logger.exception()` inside the signing critical section, or a `repr()` on a stack frame containing the privkey buffer, leaks forever (log files get backed up, shipped to centralized stores, indexed by misconfigured log collectors).

**Enforced by:** `src/fwd/main.py::_scrub_hex_secrets` (a structlog processor inserted before `JSONRenderer` in the processor chain) plus `tests/unit/test_log_scrubber.py` (10 tests: redacts unknown fields, passes whitelisted public fields, handles uppercase/mixed case, rejects shorter/longer hex). Added in v0.3.2.

The scrubber is **field-aware**: a 32-byte hex string in a known-public field (`tx_hash`, `block_hash`, `transactionHash`, `blockHash`, `stateRoot`, `transactionsRoot`, `receiptsRoot`, `parentHash`, `mixHash`) passes through; in any other field, it is replaced with `<redacted-32-byte-hex>`. The whitelist is in `src/fwd/main.py::_PUBLIC_HEX_FIELDS`. Phase 7 may extend the whitelist for ABI-decoded values; the scrubber's contract (field-aware redaction) does not change.

**Why field-aware:** naïvely redacting every 32-byte hex string would also redact transaction hashes, breaking operational debugging (operators rely on tx hashes to follow request chains). The whitelist preserves the operational signal while still catching the catastrophic leak class.

**Why this matters:** every other anti-pattern leaves recoverable state. A logged privkey is a permanent leak.

## The signer interface (forward compatibility)

`fwd`'s code is structured around a `Signer` protocol:

```python
class Signer(Protocol):
    async def address(self, wallet_name: str) -> str: ...
    async def sign_transaction(self, wallet_name: str, tx_dict: dict) -> SignedTransaction: ...
    # SignedTransaction = NamedTuple of (raw_transaction: bytes, hash: bytes, r: int, s: int, v: int)
```

v1 ships one implementation: `EnvelopeSigner` — fetches the wallet's Vault-wrapped privkey ciphertext from SQLite, calls `transit/decrypt/fwd-master` to recover plaintext, signs the transaction in-process with `eth-account`, zeroizes the plaintext buffer, and returns the signed payload. A future `YubiHsmSigner` (Phase 10, optional) plugs in via the same protocol — `fwd`'s policy engine, audit log, and API surface are unchanged. Future signer implementations that wrap a remote signing backend (HSM, KMS) will reintroduce DER parsing and v-recovery internally; the protocol only commits to "give me a signed transaction." This is the only forward-compatibility abstraction in the codebase; everything else is concrete to v1.

## Out-of-scope for this document

- Specific `policy.yaml` values for production wallets — they live in a separate private location.
- Host hardening (firewall rules, SSH config, package set) — `runbooks/host-hardening.md`.
- Phased build-out — `implementation-plan.md`.
- Decision rationale for the choices above — `decisions.md`.
- Attack surface analysis — `threat-model.md`.
