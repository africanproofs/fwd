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

**Goal: documented restore path passes a real drill against a local backup volume.**

**Revised at v0.4.3** (reversion ship). Per the operator's "no outside
dependencies" directive, the cloud-backup destination shipped at v0.4.1 +
v0.4.2 was reverted; fwd now produces backup artifacts at a known local
path (`/backup` inside the sidecars, the `backup` Docker volume on the
host). Off-host transport is the operator's responsibility, run out of
band against that volume with the operator's preferred tool (rsync /
restic / borg / NAS / USB — fwd does not ship a transport tool).

Deliverables:
- `litestream` container in compose, replicating `state.db` → `/backup/state.db` continuously (~10s RPO).
- `config/litestream/litestream.yml` configured with `type: file` (no cloud credentials).
- `vault-snapshot` sidecar saving Vault Raft snapshots to `/backup/vault-snapshots/vault-<UTC-ts>.snap` on a configurable interval (default 24h) with rotation.
- `runbooks/restore.md` documenting the local-volume restore procedure.
- `runbooks/vault-init.md` extended with the `fwd-snapshot` AppRole creation (v0.4.2).

**Verification gate:** Restore drill — run on a clean Docker host, with
the `backup` volume contents pre-populated by the operator (simulating
off-host transport):
1. Confirm `backup` volume has the Litestream replica + ≥1 vault snapshot.
2. `docker compose up -d` against a fresh `vault-data` + `fwd-state` volume set; `backup` preserved.
3. `litestream restore` from `/backup/state.db` into `fwd-state`.
4. `vault operator raft snapshot restore` from `/backup/vault-snapshots/<latest>.snap`; unseal with the original D6 shares.
5. fwd authenticates against the restored Vault (existing AppRole credentials still valid).
6. Submit a `/v1/sign-and-send` request; confirm it mines against the restored state.
7. Document RTO; target ≤ 30 minutes (excluding off-host transport).

**Out of scope** (per v0.4.3 reversion): off-host transport automation,
cloud-S3 backup. Both belong to operator-side tooling outside fwd.

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
| 5a3 | 0.4.0a3 | Shipped 2026-05-11 (Phase 5 alpha 1 — state schema + transaction persistence: Alembic 0004 (wallet_chains + nonces + transactions + transaction_args + transaction_hashes + audit_log + 5 indexes), TransactionRepo, UUIDv7 helper, F8.1 caller as explicit input to sign-and-send, GET /v1/transactions/{tx_id} (caller-gated, 404 cross-caller), 18 new tests) |
| 5a4-doc | 0.4.0a4 | Shipped 2026-05-12 (Reviewer-only — doctrine: every canonical prompt MUST be accompanied by a Sonnet wrapper message; symmetric to v0.3.0a5's hand-off-demarcation doctrine) |
| 5a5 | 0.4.0a5 | Shipped 2026-05-12 (Phase 5 alpha 2 — nonce manager: infra/nonce_repo.py with BEGIN IMMEDIATE 2-step reservation per architecture.md step 6, safe-conditional release per step 10, app/nonce_reconcile.py best-effort startup drift check in lifespan, sign-and-send 5th-arg refactor with release-on-pre-broadcast-failure; concurrent gate 10/10 monotonic; architecture.md doctrine updated to specify 2-step SQL for SQLite 3.31 dev-host portability) |
| 5a6 | 0.4.0a6 | Shipped 2026-05-12 (Phase 5 alpha 3 — receipt watcher: app/receipt_watcher.py asyncio task in lifespan, submitted→mined/failed transitions, replacement-on-stuck with tip × 1.125^seq capped at 5 retries; Reviewer review fixed two bugs Sonnet's tests missed — naive submitted_at TypeError on DB round-trip, and estimate_gas `from` field using wallet name instead of address) |
| 5a7 | 0.4.0a7 | Shipped 2026-05-12 (Phase 5 alpha 4 — admin wallet inventory + F6.3 CLI test coverage: GET /v1/admin/wallets (admin-gated, public-safe response — never leaks privkey_ciphertext or vault_master_key), clifwd wallets list now real, 38 new tests including D11 bright-line on the new endpoint and triple-redundant no-secret-leak scans, F6.3 CLI test coverage closed via test_cli_main + test_cli_wallets + test_cli_callers) |
| 5 | 0.4.0 | Shipped 2026-05-12 (Phase 5 GA — runbook + close summary: docs/runbooks/phase-5-verification.md publishes the operator-runnable 10-concurrent monotonic-nonce verification gate; substrate complete; live execution by operator pending → Phase 5 verification-met addendum to follow at the next available patch) |
| 6s1 | 0.4.1 | Shipped 2026-05-13 (Phase 6 ship 1 — Litestream S3 replica + restore runbook skeleton: config/litestream/litestream.yml activated with Scaleway env-var interpolation (5 required + 2 optional vars), .env.example documents the bucket provisioning ritual, docs/runbooks/restore.md (469 lines) ships the 8-step procedure with explicit Step 4 Vault TODO including the catastrophic consequence that re-init breaks OLD ciphertexts — Vault Raft snapshot/restore is the next Phase 6 ship; no code or test changes) |
| 6s2 | 0.4.2 | Shipped 2026-05-13 (Phase 6 ship 2 — Vault Raft snapshot save + restore + network egress fix: vault-snapshot sidecar (alpine + vault CLI + aws-cli) loops AppRole-login → raft snapshot save → S3 upload → rotate with configurable interval (default 24h) + retention (default 7); new fwd-snapshot AppRole bound to minimum-capability policy (read on sys/storage/raft/snapshot, no transit/* per D11-style isolation); scripts/vault-init.sh extended with steps 9-12 to create the new role; restore.md Step 4 replaced in-place with the real `vault operator raft snapshot restore` procedure that preserves the original fwd-master Transit key and AppRole credentials; folded-in fix: fwd-egress bridge network added because fwd-internal is internal:true and could not reach S3 (Litestream moved onto fwd-egress, vault-snapshot on both fwd-internal and fwd-egress); no Python code or test changes; 213+3 unchanged) |
| 6s3 | 0.4.3 | Shipped 2026-05-13 (Phase 6 ship 3 — REVERSION of cloud-backup substrate per operator directive "no outside dependencies": aws-cli removed entirely from vault-snapshot Dockerfile (~170 MB image shrink); scripts/vault-snapshot.sh rewritten to `cp` into /backup/vault-snapshots/ inside a shared Docker volume; config/litestream/litestream.yml switched from `type: s3` to `type: file` against /backup/state.db; docker-compose.yml deletes fwd-egress network (no service needs public egress), adds `backup` named volume, drops Litestream's network membership entirely; .env.example strips LITESTREAM_S3_* + VAULT_SNAPSHOT_S3_* stanzas; docs/runbooks/restore.md Steps 1/3/4 + pass/fail table + RTO timings + "what does not cover" rewritten for local-volume restore; off-host transport explicitly declared operator's responsibility — fwd does not transport backups off-host; vault-snapshot sidecar pattern kept, fwd-snapshot AppRole + policy kept, Vault Raft snapshot save mechanism kept, restore.md 8-step structure kept; no Python code or test changes; 213+3 unchanged; v0.4.1 + v0.4.2 paragraphs preserved as honest history per Core invariant #18) |
| 6-f6.2 | 0.4.4 | Shipped 2026-05-13 (F6.2 CI integration runner — new `integration:` GitLab CI stage runs the 3 currently-skipping integration tests against a HashiCorp Vault 1.18.2 dev-mode service: scripts/ci_vault_init.py (httpx-based) initializes Transit + fwd-master + fwd-app policy + fwd AppRole and emits role_id/secret_id as shell-sourceable env exports; integration job needs: test; sources the env file via set -a; . ./vault.env; set +a; runs `pytest tests/integration/`; new docs/runbooks/ci-integration.md operator runbook documents the flow and local reproduction; bundled 4-line Reviewer correction to tests/integration/test_caller_auth_e2e.py — added caller= field to SignAndSendRequest constructor + tx_repo / nonce_repo args to sign_and_send() call + the missing TransactionRepo / NonceRepo imports and metadata.create_all calls; live verification ran all 3 integration tests PASS not skip against a local dev-mode Vault; closes audit finding F6.2) |
| 5-gate | 0.4.5 | Shipped 2026-05-13 (Phase 5 GA verification gate met live + critical concurrency-bug fix: surfaced during the live drill that sqlite3's implicit BEGIN (DEFERRED) was colliding with our BEGIN IMMEDIATE event handler, causing "cannot start a transaction within a transaction" → "database is locked" on every sign-and-send. Two-part fix in `infra/db.py`: dbapi_connection.isolation_level=None disables sqlite3's implicit transaction; busy_timeout bumped 5s→30s to absorb concurrent-writer queueing. ARCHITECTURAL FIX in app/dependencies.py: new RequestScopeCM shares ONE session across signer/tx_repo/nonce_repo per request; pre-v0.4.5 SignerCM/TransactionRepoCM/NonceRepoCM each opened their own session_scope, causing in-request self-contention on the writer lock. api/sign.py and app/receipt_watcher.py refactored to use RequestScopeCM. New tests/unit/test_db.py with 2 regression tests exercising the production engine path (the v0.4.0a5 unit test passed because it used a single session per task — missed the multi-session in-request contention). Phase 5 GA verification gate met live: wallet 0xB9aAC415..., 10 concurrent /v1/sign-and-send produced monotonic nonces 7-16, all mined within 60s, on-chain `from` recovers to wallet address, `nonces.next_nonce=17, last_confirmed=16`. 215 + 3 skipped (+2 from test_db.py). architecture.md § Signing flow step 6 doctrine updated with the SQLAlchemy + SQLite isolation-level interaction + 30s busy_timeout rationale + single-session-per-request requirement) |
| 6-gate | 0.4.6 | Shipped 2026-05-13 (Phase 6 GA verification gate met live + drill-driven drift fixes — sequel to v0.4.5's pattern. Five drifts surfaced during the live local-volume restore drill: (1) docker-compose.yml Litestream service had `:ro` on fwd-state, blocking _litestream_seq tracking table creation → /backup never populated; fix: drop the `:ro`. (2) vault-snapshot Dockerfile's `USER nobody` blocked mkdir on the root-owned /backup volume; fix: new scripts/vault-snapshot-entrypoint.sh wrapper chowns /backup/vault-snapshots as root then drops to nobody via su-exec — main loop stays unprivileged. (3) .env missing FWD_VAULT_SNAPSHOT_*_ID because vault-init.sh hadn't been re-run post-v0.4.2 (operator-host fix; re-ran script idempotently). (4) Restore runbook Step 2 ordering bug — starting all services lets fwd alembic-create empty state.db, litestream replicates it as a new generation, Step 3 restore picks the empty one and silently wipes the backup; fix: Step 2 rewritten to start ONLY vault initially. (5) Four smaller runbook drifts — /b/state.db.litestream → /b/state.db; `sh -c` → `--entrypoint /bin/sh -c`; explicit `docker compose restart vault` step after snapshot restore to refresh stale in-memory seal config; remove the nonexistent `nonce_reconcile.complete` reference (reconcile silent on happy path). Live drill RTO measured at 7m 36s (≤30m target met). Post-restore sign-and-send tx 0x9eee9a6b... mined at Coston2 block 30,476,864 with on-chain `from = 0xb9aac415...` (the phase5-gate wallet) — proves Vault Transit master restored exactly and the full custody chain works. Pre-disaster inventory of 7 wallets + 4 callers exactly matched post-restore. Nonce table continued 17/16 → 18/17 monotonically. 215 + 3 skipped unchanged. Phase 5 + Phase 6 GA gates now both met live; Phase 7 substrate is the next territory) |
| 7-a1 | 0.5.0a1 | Shipped 2026-05-13 (Phase 7 doctrine — Reviewer-only. Three new entries in `decisions.md`: D14 policy engine implementation (Pydantic schema, 10-step evaluation order refining D13, fixed UTC-aligned rate buckets, startup fail-fast on orphan callers/signatures, startup-only reload), D15 ABI intent decoder shape (eth_abi library, `DecodedIntent` dataclass, in-repo `config/abis/` registry with 3 ABIs — RewardManager + ParticipantRegister + ERC-20 — operator decision: ABIs are public, commit them; dynamic types deferred), D16 audit log hash-chain scheme (SHA-256, canonical sorted-key compact JSON, NUL-joined hash input, genesis prev_hash='0'*64, one audit_log row per request, audit writes share the RequestScope session with rate increments — ~5-10ms added writer-lock holding time, acceptable within 30s busy_timeout; `clifwd audit verify/show/tail` walker CLI; tamper-evident at v0.5.0 — Phase 10 on-chain anchor closes recursion). Architecture.md updated: § Policy YAML format rewritten to caller-keyed shape per D13/D14 (the prior wallet-keyed example was doctrine drift; "hot-reloaded on file mtime change" claim retired); new § Policy engine, § Intent decoder, § Audit log sections; § SQLite schema PRAGMAs busy_timeout drift fix (5000→30000) per Core invariant #18. config/abis/ scaffold + README placeholder explaining the registry; .gitignore adds policy.yaml (operator-controlled, like .env); .env.example adds FWD_POLICY_PATH pointer. No code, no test changes; 215+3 skipped unchanged) |
| 7-a1b | 0.5.0a2 | Shipped 2026-05-13 (Phase 7 doctrine self-review corrections — Reviewer-only. Nine gaps surfaced by Reviewer's own audit of v0.5.0a1: (1) D15 type scope expanded to include `string`, `bytes`, `int*` — original a1 scope excluded `string` but shipped ParticipantRegister ABI which uses string fields, a doctrine contradiction. (2) D16 hash construction switched from NUL-byte-joined concatenation to canonical-JSON-serialize-then-hash — NUL-join was collision-fragile for free-form fields (caller name, decision_reason) that could carry literal NULs. (3) D14 + D16 align with README on int* type support (was drifting). (4) D14 adds rate-bucket release-on-failure semantic mirroring v0.4.0a5 nonce release — original a1 left it unspecified, risking consumed rate slots on failed requests. (5) D14 adds admin-endpoint policy_path validation rule — POST /v1/admin/callers etc. must reject 400 if path is not in loaded policy; without this, admin can create entities that trap the next fwd restart in fail-fast. (6) D16 specifies audit-row authorship for every action — each use case writes one row at operation end via injected AuditRepo; admin actions get an AdminScope (lands at a6). (7) D16 specifies policy-load event content — caller=NULL, request_json=NULL, outcome={policy_yaml_sha256, callers_count, permissions_count, abis_loaded, fwd_version}; lets clifwd audit show reconstruct policy timeline across restarts. (8) D14 adds idempotency-replay-vs-policy-reeval clause — replay returns cached tx_id without re-evaluating, writes sign-and-send-duplicate audit row, does NOT increment rate buckets. (9) D16 specifies walker CLI access pattern — `docker exec fwd clifwd audit verify` is the canonical access, no host SQLite client needed; forensic fallback runs a throwaway container against the fwd_fwd-state volume. Architecture.md § Audit log and § Intent decoder mirrored. config/abis/README.md aligned. Phase 7 cadence shifted by 1 alpha (a2/a3/a4/a5 → a3/a4/a5/a6). No code, no test changes; 215+3 skipped unchanged) |
| 7-a2 | 0.5.0a3 | Shipped 2026-05-13 (ABI intent decoder substrate — first Phase 7 code ship; Sonnet-implemented via canonical prompt, Reviewer-reviewed file-by-file + gates independently re-run. `src/fwd/domain/intent.py` pure decoder `decode_intent(contract, calldata, abi_fn_entry) -> DecodedIntent | None` with B1 scalar-projection (complex args decoded but omitted from `.args`, visible in `method_signature`; `None` only on decode failure); `src/fwd/infra/abi_registry.py` `(abi_name, selector_hex)`-keyed registry, bare-array+Hardhat-wrapped, nonpayable/payable-only, fail-fast matrix; config/abis/{registry.yaml,reward_manager.json,participant_register.json,erc20.json}; `eth-abi` promoted transitive→explicit direct dep + mypy override; 34 new tests (249 passed +3 skipped). SIX D15/architecture.md drift corrections folded in per v0.4.5/v0.4.6 combined-ship precedent: B1 projection rule (was "arrays→None", would've blocked Phase 8 FTSO claim), Hazard #1 address-strip was factually wrong for eth_abi 5.x, contract checksummed→lowercased, registry (contract_address,selector)→(abi_name,selector), "ABIs scalar-only" false at ABI level→signable-only, "no new top-level dep" reconciled. Two-coauthor trailer — Sonnet implemented) |
| 7-a3 | 0.5.0a4 | Shipped 2026-05-16 (Policy engine substrate — Sonnet-implemented, Reviewer-reviewed file-by-file + gates independently re-run. `src/fwd/domain/policy.py` Pydantic v2 schema (`extra="forbid"`, `version!=1` rejected); `src/fwd/app/policy_engine.py` `evaluate(...)` implementing D14's 10 steps exactly, body wrapped `try/except → Deny(step=0)` (never raises), release-caller-bucket on Deny(9); `src/fwd/infra/rate_repo.py` rate_buckets + wallet_buckets, all-or-nothing increment, conditional release, `add_committed_value` bigint, `delete_stale`; Alembic 0005 creates/drops both tables (0001→0005 round-trip clean); `src/fwd/infra/policy_loader.py` `load_policy` fail-fast + `check_consistency` checks 1/2/4/5 + `policy_path_exists`; `app/dependencies.py` += `RateRepoCM`/`get_rate_repo`; 84 new unit tests, 333 passed +3 skipped, ruff+format+mypy(47)+layer+version green. THREE Reviewer corrections at commit (v0.4.0a5 precedent): (1) Reviewer-owned logic fix — `policy_loader` check 1 was policy_path-keyed into name-keyed `policy.callers` (would false-positive D14 fail-fast on every realistic `name!=policy_path` policy); root cause was the Reviewer's own canonical-prompt §2 check-1 spec self-contradiction (loader speced policy_path-keyed, evaluator speced name-keyed); fixed loader to mirror evaluator (name-keyed + drift + binding→permissions). (2) Fixed `test_policy_loader.py` tests that masked the bug via `name==policy_path`; added drift regression test. (3) path-c `AllowDecision.decoded: object`→`DecodedIntent` (false circular-import claim). Doctrine alignment (Core inv #18): D15 "arg_predicate parsed at policy-load time"→eval-time coercion; D14 fail-fast bullets→name-keyed-with-drift; loader check 3 (per-signature; needs `AbiRegistry.signatures_for`) DEFERRED to 7-a5/0.5.0a6; `delete_stale` policy-load wiring DEFERRED to 7-a5/0.5.0a6; D14 rate-state `(a3)`→`(a4)`; architecture.md § Policy engine code block aligned to shipped signature (`rate_buckets_advanced` audit carrier deferred to 7-a4/0.5.0a5). Admin-endpoint policy_path validation wiring DEFERRED to 7-a5 (substrate `policy_path_exists` shipped; endpoint call sites are the a6 integration ship). Two-coauthor trailer — Sonnet implemented. Committed local-only; push blocked by GitLab account block on @makhosonke (origin/main at f1ee3f1)) |
| 7-a4 | 0.5.0a5 | Shipped 2026-05-16 (Audit-log hash-chain substrate — Sonnet-implemented, Reviewer-reviewed file-by-file + gates independently re-run. `src/fwd/infra/audit_repo.py` (`_canonical_json` D16-exact, `_row_hash`, `_as_utc`, `GENESIS_PREV_HASH`, `AuditRepo.append/get/tail/verify` with genesis + windowed-anchor semantics, verify never raises on detected break); `src/fwd/app/audit_walk.py` (app-layer seam — cli may not import infra); `src/fwd/cli/audit.py` `clifwd audit verify|show|tail` in-process read-only; `dependencies.py` += `AuditRepoCM`/`get_audit_repo` (RateRepoCM mirror; RequestScope untouched); `cli/main.py` += 2-line wiring. NO Alembic migration (audit_log exists since 0004 — D16). 30 new tests, 365 passed +3 skipped, ruff+format+mypy(50)+layer+version green, 5 alembic versions. TZ hazard handled: `_as_utc` applied symmetrically append/verify so the SQLite tz-drop round-trip is byte-identical; regression test round-trips through a fresh AsyncSession. Reviewer verdict ACCEPT, no path-a/b/c (6 Sonnet deviations all legitimate: CursorResult/`_min_seq`/cli-Optional mypy-strict idioms, ruff-format, UP017, monkeypatched-walker CLI test justified by `@lru_cache` on get_engine/get_settings). Doctrine alignment (Core inv #18): D16 + architecture.md substrate(a5)/integration(a6) split; stale "lands at a5" integration refs → a6; walker "ships at"→"shipped at"; `audit-verify-failure` enum-accepted-but-not-walker-written, privileged write DEFERRED a6/P10; sign_and_send `request_json` non-compact-json.dumps drift recorded → unify at a6; architecture.md row_hash schema comment + action-enum corrected. Two-coauthor trailer — Sonnet implemented. Committed local-only; push blocked by GitLab account block on @makhosonke (origin/main at f1ee3f1). **Phase 7 substrate feature-complete; a5=7-a4 done, next is 7-a5/0.5.0a6 integration**) |
| 7-a5 | 0.5.0a6 | Shipped 2026-05-16 (Sign-and-send integration CORE — operator-gated SPLIT: a6 = core, a7 = admin-audit + idempotency. Sonnet-implemented, Reviewer-reviewed file-by-file + gates independently re-run. New `src/fwd/app/policy_gate.py` (`gate()` calls the a4 engine ONCE → `PolicyDenied` on Deny; `release_rate_after_failure()` keys re-derived from AllowDecision+policy, best-effort); `sign_and_send` gates BEFORE nonce reserve → deny→audit(denied)+raise, pre-broadcast-fail→release nonce+rate+audit(error), broadcast-success→add_committed_value+audit(approved), all on the shared RequestScope session (one BEGIN IMMEDIATE, D16 atomic); `request_json` unified onto `_canonical_json`; `api/sign.py` wallet-lookup + `app.state.policy`/`abi_registry` + `PolicyDenied`→403, no sign-without-policy fallback (fail-closed); `main.py::_startup_policy_load` loads policy.yaml+AbiRegistry, check_consistency, `policy-load` audit row, fail-fast `SystemExit(1)`, app.state stash, gated `elif FWD_POLICY_PATH` so existing integration tests unbroken; `settings.py` += `fwd_policy_path`/`fwd_abis_dir`; `AbiRegistry.signatures_for` + loader check 3 landed; RequestScope += rate_repo/audit_repo/wallet_repo; Coston2 chain-allowlist LIFTED (policy is sole authZ; ALLOWED_CHAINS reduced to RPC-routing rail {14,19,114}). 22 new tests incl. the 10-vector synthetic-attack default-deny matrix (every D14 step → PolicyDenied + audit(denied) + `send_raw_transaction` not awaited) + happy path; 387 passed +4 skipped, ruff+format+mypy(51)+layer+version green, 5 alembic (NO migration). THREE Reviewer corrections at commit: (1) path-a — `main.py` error branch dropped the spec-mandated `await session.commit()`; `SystemExit` is BaseException so session_scope's `except Exception` neither commits nor rolls back → the D16 forensic policy-load-error row was discarded (decisions.md:686); fixed by committing before `SystemExit(1)`. (2) path-c — removed the unused `canonical_json` public alias (grep-confirmed zero refs; spec permitted the private import sign_and_send/main use). (3) Reviewer-owned logic fix — the chain-lift was incomplete: `RpcClient.__init__` still hard-rejected `chain_id not in ALLOWED_CHAINS={114}`, so Flare/Songbird stayed blocked regardless of policy; the canonical-prompt §4 "don't touch rpc.py" was a Reviewer spec error (rpc.py had an active gate, not docs; unit tests missed it because they AsyncMock rpc). Fixed: `ALLOWED_CHAINS={14,19,114}`, docstring/comment/error-message corrected, `test_rpc_client.py` 2 tests realigned (v0.4.0a5 precedent). Doctrine (Core inv #18): D14/D16/architecture.md substrate-vs-integration split made explicit, sign-and-send authorship a6-shipped + admin/AdminScope/idempotency/`sign-and-send-duplicate` → a7, loader check 3 retired-deferral→shipped-a6, `delete_stale` policy-load wiring honestly re-marked a6-NOT-done→a7, `audit-verify-failure` privileged write a6→a7/P10, chain-lift documented. Two-coauthor trailer — Sonnet implemented. Committed local-only; push blocked by GitLab account block on @makhosonke (origin/main at f1ee3f1). **a6=7-a5 core done; next is 7-a6/0.5.0a7**) |
| 7-a6 | 0.5.0a7 | Shipped 2026-05-16 (Integration REST — the split's second half: admin-action audit authorship via `AdminScope`/`AdminScopeCM` threading a keyword-only `AuditRepo` through `wallet-create`/`wallet-import`/`caller-create`/`caller-revoke` — one row per call, success or known-failure, NO secret in request_json/outcome; D14 idempotency-replay at the top of `sign_and_send` — Idempotency-Key → cached tx_id + seq-1 hash, `sign-and-send-duplicate` row, NO gate/nonce/rate; admin-endpoint `policy_path` validation on POST /v1/admin/{callers,wallets} → 400 `unknown_policy_path` when a policy is loaded, skipped at bootstrap; `delete_stale` policy-load prune wired in `_startup_policy_load` success branch, cannot block boot. Sonnet-implemented across a two-subagent split — first subagent API-timed-out at ~40% with no report, a fresh continuation subagent completed it; Reviewer (Opus) did the binding file-by-file pass on the FULL submission incl. the never-reviewed prior-partial substrate + independently re-ran every gate. **414 passed + 4 skipped**; ruff/format/mypy(51)/layer/version green; 5 alembic (no migration). Verdict ACCEPT — zero path-a/b/c corrections. `audit-verify-failure` privileged self-write-on-break explicitly **deferred to Phase 10** (gated on the on-chain anchor). Doctrine reconciled: D14/D16/architecture.md a7-deferral markers retired→shipped; D16 "inline in api/callers.py" doctrine error corrected) |
| 7-gate | 0.5.0 | Runbook published 2026-05-16 (Reviewer-only — `docs/runbooks/phase-7-verification.md`; version 0.5.0a7→0.5.0; commit-attribution reconciled to the root constitution). Live execution followed in v0.5.1 |
| 7-gate-fix | 0.5.2 | Shipped 2026-05-16 (drill surfaced a D16/Core-#5 bug: denied/error sign-and-send audit rows appended on the shared session were rolled back when the exception propagated through `session_scope` — exact defect class as the v0.5.0a6 main.py SystemExit bug, recurring in sign_and_send.py; unit-invisible (mocked session), live-only. Reviewer-owned fix: `AuditRepo.commit()` + commit-then-raise on the 3 exception arms (single session — no v0.4.5 two-session deadlock; also corrects latent deny-rate / broadcast-nonce accounting). Self-validating real-`session_scope` regression in test_db.py. **Live re-verified**: deny matrix re-run → 7 `sign-and-send denied` rows persist (seq 15→23), `clifwd audit verify` chain-intact 23 rows exit 0. 415 passed +4 skipped. Phase 7 GA: all proven live EXCEPT V9 step-9 wallet-rate — pending C2FLR funding of `phase7-wr-wallet` 0xa2b394978DfAE05f8b23d50C260B3dcd8A5d2b34; verification-met addendum + F2.1/F8.2 close on V9) |
| 7-gate-substrate | 0.5.1 | Shipped 2026-05-16 (the drill ran live and surfaced 8 doctrine↔substrate drifts before any policy evaluated — v0.4.5/v0.4.6 precedent. Fixed: Dockerfile `COPY config/` + `clifwd` shim; compose `FWD_POLICY_PATH`/`FWD_ABIS_DIR` + policy bind-mount; `poetry lock` content-hash; runbook amended. **DENY SIDE PROVEN LIVE on Coston2**: Step 1 + a7 AdminScope/Vault, D16 no-secret authorship (vs real keys), a7 policy_path-400, V1 step-1 startup fail-fast + forensic error-row-survives-exit, V2–V7 deny matrix exact-step + zero broadcast, `clifwd audit verify` chain-intact. **PENDING operator gas-funding** of gate wallet `0xa1c51C9E76B0b10195EA81c0c940445Da55bb5a7`: V8/V9/V10 + idempotency. Phase 7 GA partially met; broadcast-side on-chain evidence + F2.1/F8.2 close on a Reviewer-only follow-up after funding) |
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
