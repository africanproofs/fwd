# Implementation plan

This document is the phased build-out for `fwd` from v0.1.0 (this doc-only ship) to v1.0.0 (first production migration). Each phase has an explicit deliverable, a verification gate, and a recorded version. The next phase does not begin until the previous phase's gate passes.

Phases 9 and 10 are open-ended (rolling migrations and post-v1 hardening). Everything before v1.0.0 is bounded.

## Phase 0 — Documentation and project registration (v0.1.0)

**Status: Shipped 2026-04-30.**

Deliverables:
- `README.md`, `CLAUDE.md`, `LICENSE`, `.gitignore`, `.python-version` at repo root.
- `docs/architecture.md`, `docs/decisions.md`, `docs/threat-model.md`, `docs/implementation-plan.md`, `docs/dependencies.md`.
- Empty `docs/runbooks/` and `docs/history/` directories ready for content.
- Project registered in root `proofs.africa/CLAUDE.md` Project Map and Relationships diagram.
- Git repo initialized, first commit landed, pushed to `gitlab.com/proofs.africa/fwd` (operator action).

Open decisions resolved here (in `decisions.md`):
- D1 custody backend = Vault Transit self-hosted
- D2 deployment = Docker Compose, host-agnostic
- D3 state = SQLite + Litestream
- D4 Vault distribution = Vault OSS (BSL)
- D5 key migration = generate fresh + rotate (per-key)
- D6 unseal share custody = 2 paper + 3 GPG, 3-of-5 threshold
- D7 repo visibility = public
- D8 caller authentication = bearer API keys

**Verification gate:** all docs above exist and read as a coherent design. Operator approves the v0.1.0 ship and authorizes Phase 1.

---

## Phase 1 — Coston2 signing spike (v0.2.0)

**Goal: prove the Vault-Transit → Ethereum signing flow end-to-end before committing to a service shape.**

Deliverables (throwaway, not committed to main):
- A 50–100 line Python script in `scratch/spike.py` (gitignored) that:
  1. Spins up Vault in dev mode locally (`vault server -dev` in a Docker container).
  2. Creates one `aes256-gcm96` key in Transit at `transit/keys/fwd-master`.
  3. Generates a fresh secp256k1 private key externally (via `coincurve.PrivateKey()` or `eth_account.Account.create()`).
  4. Computes the Ethereum address from the public key.
  5. Encrypts the privkey via `transit/encrypt/fwd-master` → `vault:v1:<ciphertext>` blob.
  6. Pauses for the operator to fund the address with Coston2 testnet tokens (manual: faucet at https://faucet.flare.network/coston2).
  7. Decrypts the ciphertext back via `transit/decrypt/fwd-master` to recover the plaintext privkey.
  8. Builds a self-transfer EIP-1559 transaction (value = 0).
  9. Signs in-process with `eth_account.Account.from_key(plaintext).sign_transaction(tx_dict)` and zeroizes the plaintext buffer.
 10. Broadcasts to public Coston2 RPC.
 11. Polls the receipt until mined, prints the on-chain hash.

**Verification gate:** the transaction is mined on Coston2 with a recoverable signature matching the Vault-derived address. If yes, the architecture is real → proceed to Phase 2. If no, surface the failure mode and revise before proceeding.

Risks retired here:
- Vault Transit `aes256-gcm96` round-trips arbitrary 32-byte plaintext (the secp256k1 privkey) intact via encrypt/decrypt.
- `eth-account` 0.13.x produces a correctly-RLP-encoded type-0x02 (EIP-1559) signed transaction for chain_id 114 from a raw 32-byte privkey.
- Coston2 RPC accepting type-0x02 transactions broadcast via `eth_sendRawTransaction`.
- `hvac` Python client compatibility with Vault's `transit/encrypt` and `transit/decrypt` endpoints at the version we'll pin.
- DER parsing, low-S normalization, and v-recovery — **NOT retired in this spike.** These are deferred until a hardware-backed signer (Phase 10) requires them.

---

## Phase 2 — Project scaffold (v0.3.0-alpha)

**Goal: a runnable but inert `fwd` skeleton.**

Deliverables (committed to main):
- `pyproject.toml` (Poetry, Python 3.12, AP-standard deps).
- `Dockerfile` building `fwd` from source.
- `docker-compose.yml` with three services (`fwd`, `vault`, `litestream`), pinned image tags, two networks, two volumes.
- `.env.example` with documented variables and safe defaults.
- `src/fwd/` package skeleton: `__init__.py`, `version.py` (= "0.3.0"), `app.py` (FastAPI app with `/healthz` only), `cli.py` (Typer skeleton with `clifwd health` and `clifwd version`).
- `tests/` skeleton with one passing unit test.
- `.gitlab-ci.yml`: lint (ruff), type-check (mypy strict), unit test (pytest), Docker build.
- `alembic/` initialized; one empty migration as scaffold.

**Verification gate:** `docker compose up -d` brings all three containers up; `curl 127.0.0.1:8080/healthz` returns 200; `clifwd health` returns `{"vault": "sealed", "rpc": "unknown", "fwd": "ok"}`. CI green.

---

## Phase 3 — Vault deployment + signing core (v0.3.0)

**Goal: `/v1/sign-and-send` works against Coston2 for one pre-provisioned wallet.**

Deliverables:
- Vault container init scripts in `scripts/vault-init.sh`: `vault operator init -key-shares=5 -key-threshold=3` → outputs 5 unseal keys + root token. Captured securely by operator; revoked after Phase 3.5.
- Vault policies in `config/vault/policies/`:
  - `fwd-app.hcl` — `update` on `transit/encrypt/fwd-master` and `transit/decrypt/fwd-master`; `read` on `transit/keys/fwd-master`. (Per v0.1.2: Vault is an envelope-encryption layer, not a signer — there is no `transit/sign/*` capability.)
- AppRole auth method enabled; one role for `fwd`; role_id + secret_id injected via env.
- Transit engine enabled at `transit/`.
- One wallet provisioned via `clifwd wallets create register-coston2-test --policy register-coston2-test` (chain_id 114); the resulting Coston2 address is funded with testnet tokens for integration testing. Under the v0.1.2 architecture there is no per-wallet `transit/keys/<wallet>` — Vault holds one shared `transit/keys/fwd-master` (`aes256-gcm96`) and each wallet's secp256k1 privkey is generated externally and stored as a Vault-encrypted ciphertext in SQLite.
- `src/fwd/signer/envelope.py` — `EnvelopeSigner` implementation: fetches `privkey_ciphertext` + `vault_master_key` from SQLite, calls `transit/decrypt`, signs with `eth-account.Account.sign_transaction`, zeroizes plaintext, returns `SignedTransaction`. (DER parsing and v-recovery are NOT in v1 scope; they return when Phase 10 introduces a hardware signer.)
- `src/fwd/api/sign.py` — `POST /v1/sign-and-send` happy path. No nonce manager, no policy yet — uses `eth_getTransactionCount` directly, hardcoded allowlist.
- Integration test `tests/integration/test_sign_coston2.py` — runs against the deployed compose stack on a CI runner with Vault in dev mode.

**Verification gate:** Phase 1's spike, but as a real test against the deployed service: a request to `/v1/sign-and-send` produces a Coston2 transaction that lands on-chain. Vault root token is then revoked.

---

## Phase 4 — Caller authentication and admin CLI (v0.4.0-alpha)

**Goal: callers identify themselves with API keys; admin CLI manages them.**

Deliverables:
- `src/fwd/auth/api_key.py` — argon2id-hashed key storage, prefix-based lookup, constant-time comparison.
- `src/fwd/cli/admin.py` — `clifwd callers create|list|revoke` subcommands.
- `src/fwd/cli/wallets.py` — `clifwd wallets create|import|list` subcommands per `decisions.md` D9 and `architecture.md` § Wallet provisioning. The `import` subcommand enforces the refusal table (file mode 0600, file owner, 32-byte hex content, name uniqueness, optional `--expected-address` match) before accepting the file.
- Admin endpoint `POST /v1/admin/wallets` gated by `FWD_ADMIN_KEY` env var (create only — there is no HTTP import endpoint by design).
- Admin endpoint `POST /v1/admin/callers` gated by `FWD_ADMIN_KEY` env var.
- Bearer-token middleware on all `/v1/*` endpoints (except `/healthz`).
- Audit log of caller-management operations (every issue/revoke recorded, even though there's no full audit log yet — placeholder writes).

**Verification gate:** an unauthenticated request to `/v1/sign-and-send` returns 401. A request with a revoked key returns 401. A request with a valid key proceeds. CLI can create + revoke keys without service restart.

---

## Phase 5 — State, nonce manager, transaction tracking (v0.4.0)

**Goal: concurrent signing requests against the same wallet land with monotonic nonces and no collisions.**

Deliverables:
- Alembic migrations for the schema in `architecture.md` (wallets, callers, nonces, transactions, audit_log).
- `src/fwd/state/db.py` — async SQLAlchemy 2.x setup, WAL pragmas at startup.
- `src/fwd/state/nonces.py` — `BEGIN IMMEDIATE` reservation, release on confirm, reconciliation on startup (compare DB nonce to `eth_getTransactionCount(latest)` and warn on drift).
- `src/fwd/watcher/receipts.py` — asyncio task polling pending transactions every block; status transitions; replacement-on-stuck with bumped tip × 1.125, capped at 5 retries.
- `tx_id` (UUIDv7) introduced; `transaction_hashes` child table tracks hash history under replacement.
- `GET /v1/transactions/{tx_id}` endpoint.

**Verification gate:** integration test issues 10 concurrent `/v1/sign-and-send` calls against the same wallet on Coston2; all 10 land in monotonically increasing nonces with no gaps and no duplicates. Stuck-tx test (artificially low gas) confirms replacement logic.

---

## Phase 6 — Litestream backup + restore drill (v0.4.0+)

**Goal: documented restore path passes a real drill.**

Deliverables:
- `litestream` container in compose, replicating `state.db` → Scaleway Object Storage every 10s.
- `config/litestream/litestream.yml` reading credentials from `.env`.
- `runbooks/restore.md` documenting the restore procedure.
- Vault snapshot cron: `vault operator raft snapshot save` nightly, uploaded to the same bucket.

**Verification gate:** Restore drill — run on a clean Docker host:
1. `docker compose up -d` against a fresh volume set.
2. `litestream restore` from S3.
3. Vault snapshot restore.
4. Unseal Vault.
5. `clifwd reconcile` against on-chain state passes.
6. Submit a `/v1/sign-and-send` request; confirm it works against the restored state.
7. Document RTO; target ≤ 30 minutes.

---

## Phase 7 — Policy engine, intent decoder, audit log (v0.5.0)

**Goal: signing requests are gated by ABI-decoded intent against declarative policy; audit chain is verifiable.**

Deliverables:
- `src/fwd/policy/loader.py` — YAML policy loader, hot-reload on file mtime change.
- `src/fwd/policy/engine.py` — evaluates `(caller, wallet, contract, method, args, value, rate)` against rules, returns approve/deny + reason.
- `src/fwd/intent/decoder.py` — ABI parsing for the v1 contract list (FTSO RewardManager, ParticipantRegister, ERC-20 minimal).
- ABI definitions checked into `config/abi/` for the bound contracts.
- `src/fwd/audit/log.py` — hash-chained writer: `row_hash = sha256(prev_hash || ts || caller || action || request || decision || outcome)`.
- `src/fwd/cli/audit.py` — `clifwd audit verify` walks the chain and asserts integrity.
- Synthetic-attack test: a caller with no permissions tries to call a non-allowlisted method; expect 403, audit row recorded with `decision=denied`.

**Verification gate:** synthetic-attack test passes; `clifwd audit verify` reports chain integrity; policy hot-reload (modify YAML, watch reload audit row appear) works without restart.

---

## Phase 8 — First production migration: `ftso-fee-claimer` (v1.0.0)

**Goal: AP's most valuable backend `.env PRIVATE_KEY` is replaced by `fwd`. One full reward epoch claimed via `fwd` end-to-end.**

Deliverables:
- New wallet in Vault: `ftso-claim-flare-prod` (chain_id 14). Generated fresh per D5.
- New `policy.yaml` entry for `ftso-fee-claimer` × `ftso-claim-flare-prod` with `claim` method allowlisted, beneficiary constraint pinned.
- On-chain rotation: `setClaimRecipient(<new-fwd-address>)` signed by the identity hardware wallet (`0x26534aC74153E3257dDD3471f96faA33D5D3B575` Flare). Verified on Flare Explorer.
- `ftso-fee-claimer` updated to call `POST /v1/sign-and-send` instead of locally signing. The `.env` line `PRIVATE_KEY=…` deleted.
- Test on Songbird first (lower stakes, also rotated to `ftso-claim-songbird-prod`).
- One full reward epoch claim cycle on Songbird passes.
- Test on Flare next.
- One full reward epoch claim cycle on Flare passes.
- Old `.env` private keys removed from git history (force-overwrite if needed; otherwise considered burned and rotated).

**Verification gate:** one full reward epoch on Flare is claimed via `fwd`, end-to-end, with no fallback path. Audit log confirms the request, decision, and on-chain hash. Operator approves the cutover.

---

## Phase 9 — Rolling migrations of remaining backends (v1.1.x, ongoing)

**Goal: every remaining `.env PRIVATE_KEY` in AP backends is migrated to `fwd`.**

Per-migration deliverables (one per ship):
- New wallet in Vault.
- New address generated; old wallet swept to new (or rotated on-chain where applicable).
- New `policy.yaml` entry.
- Application code switched to call `fwd`.
- Old `.env PRIVATE_KEY` deleted.
- Audit log + integration test green.

Migration order (suggested):
1. `apregister/` Coston2 test wallet — lowest risk, good practice.
2. `apcli` — audit which keys it actually holds (some may be redundant with `apregister/`).
3. `fics` write paths — only if/when `fics` gains write capabilities.
4. Future Claude agent wallets — provisioned at agent creation, not retroactively.

**Out of scope:** identity addresses, delegation addresses, validator NodeID. These remain offline behind the hardware wallet. They do not migrate.

**Verification gate per migration:** that backend's primary use case works against `fwd`; old `.env` line removed from disk and from any committed `.env.example` files.

---

## Phase 10 — Hardening (v2.x, deferred)

**Goal: production-grade observability, automated unsealing, hardware-backed signing.**

Candidate deliverables (operator chooses ordering and triggers):

- **Auto-unseal.** Either a second tiny Vault as transit-seal seed, or YubiHSM 2 via PKCS#11. Eliminates the manual unseal ritual.
- **YubiHSM 2 for hardware-isolated signing.** New `Signer` implementation: `YubiHsmSigner`. Per-wallet decision: which keys move to HSM custody. Threat-model upgrade: A3 residual risk shrinks dramatically.
- **Prometheus metrics.** `/metrics` endpoint exposing: signing latency (histogram), policy decisions (counter by approved/denied), nonce gap (gauge), RPC errors (counter), audit-log size (gauge), Vault seal status (gauge).
- **Grafana board** + alerting: pages on policy denial spikes, sustained RPC errors, nonce gap > threshold, Vault seal status changes.
- **On-chain audit-log anchor.** Weekly cron computes Merkle root of audit_log; commits the root via a low-cost transaction to a registry contract on Flare. Forensic non-repudiation.
- **mTLS for cross-host callers.** cert-manager-style or `fwd`-issued client certs, depending on which callers cross the host boundary.
- **Dynamic ABI fetch.** Currently the v1 contract ABIs are checked in. A future `clifwd abi fetch` from Flare Explorer could remove the manual step, with an operator-approved cache.

Each Phase 10 item is its own ship with its own canonical prompt, gate, and version bump.

---

## Versioning anchor

Per `CLAUDE.md` Core invariant #13 (linear-forward versioning), every ship bumps the next linear patch number in BOTH `pyproject.toml` and `src/fwd/version.py`.

| Phase | Version | Status |
|---|---|---|
| 0 | 0.1.0 | Shipped 2026-04-30 |
| 0+ | 0.1.1 | Shipped 2026-04-30 (pre-Phase-1 doc fixes) |
| 0++ | 0.1.2 | Shipped 2026-05-01 (Vault Transit pivot to envelope encryption) |
| 1 | 0.2.0 | Shipped 2026-05-01 (Coston2 spike against v0.1.2 architecture) |
| 1+ | 0.2.1 | Shipped 2026-05-01 (pre-Phase-2 doc fixes: failure modes + implementation hazards) |
| 1++ | 0.2.2 | Shipped 2026-05-01 (wallet create + CLI-only import; export deferred per D9) |
| 1+++ | 0.2.3 | Shipped 2026-05-01 (CLI rename: fwd-cli → clifwd; mechanical rename across docs) |
| 2 | 0.3.0-alpha | Shipped 2026-05-01 (project scaffold: pyproject + Dockerfile + compose + src/fwd/ + tests + alembic + CI) |
| 3a | 0.3.0a1 | Shipped 2026-05-02 (Phase 3a — Vault deployment: init script + fwd-app policy + AppRole + runbook) |
| 3a-fix | 0.3.0a2 | Shipped 2026-05-02 (Reviewer-only fix-up: VAULT_ADDR in compose env so the vault CLI uses HTTP — surfaced during manual verification ritual) |
| 3a-doc | 0.3.0a3 | Shipped 2026-05-02 (Doctrine: Core invariant #17 — Vault Shamir distribution is dev-elidable, production-mandatory; wipe-and-redo procedure at Phase 8 cut) |
| 3a-doc | 0.3.0a4 | Shipped 2026-05-02 (Doctrine: D10 — staged token lifecycle: 403-fallback v1 → renew-self Phase 7 → periodic tokens Phase 8; architecture.md § Auth lifecycle) |
| 3a-doc | 0.3.0a5 | Shipped 2026-05-02 (Doctrine: enforced hand-off demarcation in canonical prompts — bold marker + fenced block, no exceptions) |
| 3b | 0.3.0a6 | Shipped 2026-05-02 (Phase 3b — wallet provisioning: VaultClient, EnvelopeSigner, WalletRepo, POST /v1/admin/wallets, clifwd wallets create, admin auth middleware, Alembic 0002) |
| 3c | 0.3.0 | Shipped 2026-05-07 (Phase 3c — sign-and-send GA: RpcClient, EnvelopeSigner.sign_transaction, POST /v1/sign-and-send, hardcoded chain allowlist) |
| 3-gate | 0.3.1 | Shipped 2026-05-07 (Reviewer-only — Phase 3 verification gate met live: Coston2 tx 0x8ab03b3d... mined block 30251692, from = 0x33191597... matches wallet — full custody chain proven on-chain) |
| 3-corrections | 0.3.2 | Shipped 2026-05-07 (Reviewer-only — v0.3.1 audit corrections: real mlockall + IPC_LOCK, field-aware structlog scrubber, zeroize/no-cache tests, settings layer-boundary, threat-model A5+summary fix, hazards #1/#2/#3 to past tense, Core invariant #18 — doctrine and code do not drift) |
| 3-pre4-doc | 0.3.3 | Shipped 2026-05-07 (Reviewer-only — pre-Phase-4 doctrine: D11 admin/caller auth bright line, D12 CLI in-process import pattern, D13 caller-keyed policy with wallet-level Phase-7 hooks; closes audit F2.4, F3.2, F7.4) |
| 4 | 0.4.0a1 | Shipped 2026-05-07 (Phase 4 — caller authentication: argon2id API keys, callers table + Alembic 0003, api/caller_auth.py D11-isolated, POST/DELETE/GET /v1/admin/callers, clifwd callers create/list/revoke, clifwd wallets import + list stub, /v1/sign-and-send → caller_required, 115 unit tests) |
| 4-corrections | 0.4.0a2 | Shipped 2026-05-07 (Reviewer-only — v0.4.0a1 audit corrections: F6.1 ruff F841 lint fix, F1.2 shred-missing fail-loud, F1.1 import_wallet hazard #1/#2 tests, F5.2 stale comments in api_key.py + admin_auth.py, F5.1 v0.4.0a1 history doc addendum; 12 findings deferred per Core invariant #18) |
| 5 | 0.4.0 | State + nonces |
| 5 | 0.4.0 | State + nonces |
| 6 | 0.4.x | Backup + restore |
| 7 | 0.5.0 | Policy + audit |
| 8 | 1.0.0 | First production migration |
| 9 | 1.1.x… | Rolling migrations |
| 10 | 2.x | Hardening (deferred) |

The version anchor lives in `src/fwd/version.py`, displayed in `/healthz` and the CLI banner. Cross-artifact drift (pyproject.toml ≠ version.py) is caught by a unit test (`tests/unit/test_version_consistency.py`) — added in Phase 2.

---

## Out of scope for this plan

- Detailed canonical prompts for each phase — those are written by the reviewer at ship time, not here.
- Specific test counts per phase — implementer determines naturally during execution; reviewer's spec asserts test *coverage* shape, not exact counts.
- Production policy values — they live outside the public repo (per D7).
- Phase-internal sequencing — implementer chooses optimal order within a phase, subject to the gate.
