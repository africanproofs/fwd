# Architecture

This document is the canonical design for `fwd`. Decisions are recorded in `decisions.md`; threats in `threat-model.md`; the phased build-out in `implementation-plan.md`. This file describes *what `fwd` is at v1.0.0* — the steady-state design once Phase 8 lands.

## One-paragraph summary

`fwd` is an HTTP signing service. Callers (AP backend apps, Claude agents) submit a signing request; `fwd` authenticates the caller, decodes the requested transaction's calldata against a known ABI, evaluates declarative policy, reserves a nonce, asks HashiCorp Vault Transit to sign the transaction's keccak256 digest, applies low-S normalization and v-recovery, broadcasts the signed transaction, and writes a hash-chained audit row recording the entire decision. Keys are generated inside Vault and cannot be exported via the API. State (nonces, transactions, audit log) lives in SQLite, replicated continuously to Scaleway Object Storage by Litestream. Deployment is a single-host `docker compose up`.

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
                      │  - DER → low-S → v-recovery      │
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
$ docker exec -it fwd fwd-cli callers create \
    --name ftso-fee-claimer \
    --policy ftso-claim-flare-prod
fwd_live_a8f3c9d2b1e4...
```

The key is opaque to callers; `fwd` stores a salted hash on the host, not the key itself. Callers submit it as `Authorization: Bearer fwd_live_...`. Lookup → policy → wallet permissions.

API keys are rotatable from the CLI without service restart. Compromise response: revoke + reissue + caller redeploys with new key.

mTLS / SPIFFE / workload identity is deferred to Phase 10 (or whenever a caller lives outside the host).

## Signing flow

Critical correction relative to early sketches: Vault Transit does NOT return Ethereum-shaped `(r, s, v)` signatures directly. The `ecdsa-p256k1` key type returns DER-encoded ASN.1 in a `vault:v1:<base64>` envelope. The DER → low-S → v-recovery dance is identical to the AWS-KMS pattern; only custody location and auth shape differ.

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
    UPDATE nonces SET next_nonce = next_nonce + 1
      WHERE wallet = :w AND chain = :c
      RETURNING next_nonce;
    COMMIT;

7.  fwd queries fee oracle
    - eth_feeHistory for last 5 blocks
    - base_fee + tip suggestion (chain-specific tip floor)

8.  fwd builds EIP-1559 unsigned transaction
    - type 0x02
    - RLP-encode the transaction fields
    - Compute keccak256(rlp_encoded) → 32-byte digest

9.  fwd asks Vault to sign
    POST /v1/transit/sign/<wallet-key>
    Body: {
      input: base64(digest),
      hash_algorithm: "none",
      prehashed: true,
      marshaling_algorithm: "asn1"
    }
    Response: { signature: "vault:v1:<base64-DER>" }

10. fwd parses signature
    - Strip vault:v1: prefix
    - base64-decode → DER bytes
    - Parse SEQUENCE { r INTEGER, s INTEGER }
    - If s > N/2: s = N - s   (EIP-2 low-S normalization)

11. fwd recovers v
    - Try y_parity ∈ {0, 1}
    - ecrecover(digest, r, s, y_parity) → candidate address
    - Pick whichever matches wallet.address (cached from Vault at startup)

12. fwd splices (r, s, v) into the transaction
    - Re-encode as type-0x02 signed
    - tx_hash = keccak256(signed_rlp)

13. fwd broadcasts via JSON-RPC eth_sendRawTransaction

14. fwd records:
    - INSERT INTO transactions (tx_id, wallet, chain, intent_json,
                                nonce, signed_raw, hash_history,
                                status='submitted')
    - INSERT INTO audit_log (caller, action='sign-and-send',
                             request_json, decision='approved',
                             outcome=tx_id, prev_hash, row_hash)

15. fwd returns { tx_id, hash, nonce } to caller

16. Receipt watcher (asyncio task, runs every block):
    - Poll eth_getTransactionReceipt for each pending tx
    - On confirmation: status='confirmed', release nonce
    - On stuck (N blocks elapsed): replace with bumped tip,
      append to hash_history, audit row
    - On final failure (5 retries): status='failed', surface alert
```

## SQLite schema

```sql
CREATE TABLE wallets (
    name TEXT PRIMARY KEY,
    vault_key_ref TEXT NOT NULL,
    address TEXT NOT NULL,
    chains TEXT NOT NULL,                    -- JSON array of chain_ids
    policy_path TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
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
    wallet TEXT NOT NULL,
    chain INTEGER NOT NULL,
    next_nonce INTEGER NOT NULL,
    last_confirmed INTEGER,
    last_reconciled_at TIMESTAMP NOT NULL,
    PRIMARY KEY (wallet, chain)
);

CREATE TABLE transactions (
    tx_id TEXT PRIMARY KEY,                  -- UUIDv7
    wallet TEXT NOT NULL,
    chain INTEGER NOT NULL,
    caller TEXT NOT NULL,
    nonce INTEGER NOT NULL,
    intent_json TEXT NOT NULL,               -- decoded human-readable intent
    request_json TEXT NOT NULL,              -- full original request
    signed_raw TEXT,                         -- hex of latest signed tx
    hashes_json TEXT,                        -- JSON array: [hash_v1, hash_v2, ...]
    status TEXT NOT NULL,                    -- pending|submitted|mined|replaced|failed
    submitted_at TIMESTAMP,
    confirmed_at TIMESTAMP,
    receipt_json TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    caller TEXT,
    action TEXT NOT NULL,                    -- sign-and-send | sign-typed-data | admin-* | ...
    request_json TEXT,
    decision TEXT NOT NULL,                  -- approved|denied|error
    decision_reason TEXT,
    outcome TEXT,                            -- tx_id, error code, etc.
    prev_hash TEXT NOT NULL,                 -- hash of previous row (genesis = '0' * 64)
    row_hash TEXT NOT NULL                   -- hash(prev_hash || ts || caller || action || request_json || decision || outcome)
);

CREATE INDEX idx_tx_status ON transactions (status);
CREATE INDEX idx_tx_wallet_chain_nonce ON transactions (wallet, chain, nonce);
CREATE INDEX idx_audit_caller_ts ON audit_log (caller, ts);
```

PRAGMAs at startup: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, `foreign_keys=ON`.

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
| `POST` | `/v1/admin/wallets` | admin | Provision wallet (creates Vault key, derives address) |
| `POST` | `/v1/admin/callers` | admin | Issue caller API key |
| `DELETE` | `/v1/admin/callers/{name}` | admin | Revoke caller |

Admin endpoints require a separate `FWD_ADMIN_KEY` configured at boot. Admin authentication is not policy-controlled — it's the bootstrap.

## Vault configuration

| Setting | Value | Why |
|---|---|---|
| Storage backend | Raft (single-node, file-based) | Simplest backend that supports Transit |
| Auto-unseal | None in v1 | Manual Shamir unseal; auto-unseal is Phase 10 |
| Shamir threshold | 3 of 5 | Survives loss of any 2 share locations |
| Engines mounted | `transit/` | Only Transit; no KV needed in v1 |
| Key type | `ecdsa-p256k1` | secp256k1, the Ethereum curve |
| Key flags | `exportable=false`, `derived=false`, `allow_plaintext_backup=false` | Keys cannot be extracted via API |
| Auth methods | `approle` (for `fwd` itself) | One AppRole per `fwd` deployment; role ID + secret ID via env |
| Listener | TCP 8200 on `fwd-internal` only | Not reachable from host |
| TLS | Internal CA, self-signed | TLS within Docker network for defense-in-depth |
| Audit device | `file` → `/vault/logs/audit.log` | Vault's own audit (separate from `fwd`'s audit) |

`fwd`'s Vault policy:

```hcl
path "transit/sign/+" {
  capabilities = ["update"]
}

path "transit/keys/+" {
  capabilities = ["read"]
}

# NO transit/keys/+/export, NO transit/keys/+/rotate, NO transit/keys/+/config
```

## Policy YAML format

```yaml
version: 1

wallets:
  ftso-claim-flare-prod:
    address: "0x..."   # filled in after Phase 8 generation
    chain: 14          # Flare mainnet
    permissions:
      ftso-fee-claimer:
        contracts:
          "0xRewardManager...":
            methods:
              claim:
                args_constraints:
                  beneficiary: "0x7c3579ab3e647395c96a1efc98af9a31c5ecc294"
                max_value_wei: 0
        rate:
          per_hour: 10
          per_day: 100
        require_human_approval_above_value_wei: null   # claim sends 0; null disables

  register-coston2-test:
    address: "0x..."
    chain: 114         # Coston2
    permissions:
      apregister-e2e:
        contracts:
          "0xF9fDB222FCa62B50a0d94C1F31650a4034b60B12":
            methods:
              register:
                max_value_wei: 0
              updateMetadata:
                max_value_wei: 0
        rate:
          per_hour: 50
          per_day: 200
```

Policy is hot-reloaded on file mtime change. Reload writes an audit row.

## Backup and restore

**Continuous:** Litestream replicates `state.db` to Scaleway Object Storage every 10s with ~1MB WAL bursts. Bucket: `s3://ap-fwd-backups/<host-name>/state.db.litestream/`.

**On-demand Vault snapshots:** `vault operator raft snapshot save vault-snapshot-<ts>.bin` — runs nightly via host cron, uploaded to the same bucket under `vault-snapshots/`. Encrypts at rest with the existing Vault master key.

**Restore drill (documented in `runbooks/restore.md`):**
1. `docker compose down`
2. `litestream restore -o state.db s3://ap-fwd-backups/<host>/state.db`
3. `vault operator raft snapshot restore vault-snapshot-<ts>.bin`
4. `docker compose up -d`
5. Unseal Vault (3 of 5 shares)
6. Verify nonce reconciliation against on-chain state via `fwd-cli reconcile`
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

## The signer interface (forward compatibility)

`fwd`'s code is structured around a `Signer` protocol:

```python
class Signer(Protocol):
    async def address(self, key_ref: str) -> str: ...
    async def sign_digest(self, key_ref: str, digest: bytes) -> tuple[int, int]: ...
    # returns (r, s); v-recovery is the gateway's job
```

v1 ships one implementation: `VaultTransitSigner`. A future `YubiHsmSigner` (Phase 10, optional) plugs in via the same protocol — `fwd`'s policy engine, audit log, and API surface are unchanged. This is the only forward-compatibility abstraction in the codebase; everything else is concrete to v1.

## Out-of-scope for this document

- Specific `policy.yaml` values for production wallets — they live in a separate private location.
- Host hardening (firewall rules, SSH config, package set) — `runbooks/host-hardening.md`.
- Phased build-out — `implementation-plan.md`.
- Decision rationale for the choices above — `decisions.md`.
- Attack surface analysis — `threat-model.md`.
