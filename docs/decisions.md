# Decisions

This document records the architectural decisions made during `fwd`'s v0.1.0 design phase, with alternatives considered and the reasoning behind each. It is not a parallel canon — `architecture.md` is the canonical design — but it preserves the why so future agents can re-litigate any decision deliberately rather than by drift.

Decisions are numbered for reference. Format: **Decision** / **Alternatives considered** / **Why** / **Consequences** / **When to revisit**.

> **Two project-wide renames post-date many records below; D1 and D20 are the records of truth, and older decision bodies use the original names as honest history:** (1) **custody** — HashiCorp Vault was retired at v1.0.0a1; custody is now a sealed local master (`decisions.md` D1). Wherever an operative decision still reads "Vault / Transit / AppRole / unseal," read "sealed master." (2) **the signing endpoint** — `/v1/sign-and-send` was renamed `/v1/sign-transaction` and made sign-only (no broadcast) at v1.1.0a9 (`decisions.md` D20). Wherever a still-operative decision references `/v1/sign-and-send`, the live route is `/v1/sign-transaction`. These renames are NOT re-annotated inline on every historical record (that would churn the append-only log); D1/D20 carry the authoritative reconciliation.

---

## D1. Custody backend

**SUPERSEDED at v1.0.0a1 — current decision: sealed local master (no Vault).**
`fwd` envelope-encrypts each wallet's secp256k1 private key with
AES-256-GCM (`cryptography` AESGCM, mirroring the retired Vault
`aes256-gcm96`) under a single 32-byte master key held in a mode-0600
host file owned by the `fwd` user (`SealedMaster`,
`src/fwd/infra/sealed_master.py`; ciphertext `seal:v1:<b64(nonce||ct)>`
in SQLite). The master is loaded once at startup (fully unattended; no
unseal ceremony). Decrypt-on-demand + zeroize + `mlock` are unchanged
(Core invariants #1/#16). **Rationale:** the operator confirmed the
asset class — low-value Flare automation keys (~1000 FLR ≈ tens of USD
per key; FTSO-claim/registration/gas wallets, never treasury) on a host
never publicly exposed. Two independent audits
(`docs/reviews/v0.5.4-stack-and-overengineering-audit-report.md`,
`docs/reviews/v0.5.5-second-independent-audit-report.md`) found the full
HashiCorp Vault apparatus (Transit, 3-of-5 Shamir-across-failure-domains,
AppRole lifecycle, Raft snapshots, the vault-snapshot sidecar, the Core
#17 production wipe-and-redo) disproportionate to that asset class; its
only differentiator over a sealed master — an independent
decrypt-audit-trail against a track-covering attacker — is worthless at
this value/exposure and, per v0.5.5 audit OE-2, was never even enabled.
A sealed master gives equivalent at-rest protection (ciphertext-only on
disk theft absent the master file) and equivalent runtime blast radius
(a compromised running `fwd` decrypts everything either way), at a
fraction of the operational and dependency surface. **Disaster
recovery** is regenerate-the-wallet + on-chain re-authorization
(≈ free), not a share ceremony. **[Flag — DR mechanic, per CLAUDE.md
Core #17:** the exact on-chain step is `ClaimSetupManager.setClaimExecutors`
re-authorization of the regenerated executor, NOT recipient rotation; this
path is not yet Reviewer-verified end-to-end, so the `setClaimRecipient`
wording is retained-flagged here, not rewritten into security doctrine.] **Operator decision recorded
2026-05-17.** Alternatives weighed: keep Vault (rejected — pays the full
ops tax for a benefit that does not apply here); passphrase/Shamir-sealed
master (rejected — restart friction with no real marginal security for
this asset class on a private host); env-var master (rejected — same
boundary as the host file, less manageable). The everything below is
**honest history of the v0.1.2–v0.5.6 Vault era** (kept per Core #18 /
the v0.4.3 honest-history precedent — do not delete).

---

## D1 (historical, v0.1.2–v0.5.6). Custody: Vault Transit envelope encryption + in-process secp256k1 signing

**Decision (SUPERSEDED — see the v1.0.0a1 block above).** AP runs HashiCorp Vault on the same Docker host as `fwd`, with the Transit secrets engine providing one `aes256-gcm96` master key (`exportable=false`). Each wallet's secp256k1 private key is generated externally (secure RNG via `coincurve` or `eth-account.create()`), envelope-encrypted by Vault (`transit/encrypt/fwd-master`), and stored as a `vault:v1:<ciphertext>` blob in SQLite. At signing time, `fwd` calls `transit/decrypt/fwd-master` to recover plaintext, signs the transaction with `eth-account`, and zeroizes the plaintext buffer immediately. Plaintext private keys never persist on disk and exist in `fwd`'s process memory only during the bounded signing operation.

**Background.** v0.2.0's Phase 1 spike discovered (and the Reviewer independently verified) that Vault Transit — in OSS, OpenBao, and Vault Enterprise's native engine — supports only NIST curves (`ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`) for ECDSA signing. **secp256k1 (Ethereum's curve) is not a supported Transit key type.** The original D1 (Vault Transit signing of ECDSA secp256k1 keys) is technically impossible with the chosen substrate. This decision documents the pivot.

**Alternatives considered (revised).**
- **Path 1: AWS KMS** (or GCP/Azure KMS) — native secp256k1 support since 2021, FIPS 140-2 L2, ~$2–5/mo at AP volume. Rejected: reintroduces the cloud-jurisdiction concern that drove the original D1 toward self-hosting.
- **Path 2 (chosen): Vault Transit as envelope encryption** — preserves AP sovereignty, Shamir unseal, container topology, at the cost of plaintext privkeys briefly in `fwd`'s process memory at signing.
- **Path 3: Encrypted file keystore** (eth-account v3 format, passphrase-locked) — simpler than Path 2 but loses Shamir unseal; passphrase compromise = total loss with no equivalent recovery property.
- **Path 4: YubiHSM 2 + PKCS#11** (pull Phase 10 forward) — strongest custody, $650 hardware, 2–3 days extra engineering. Deferred to Phase 10 as originally planned.
- **Vault Enterprise** (~$30k+/yr) — not AP-realistic.

**Why Path 2.** Preserves the substantive parts of v0.1.0's design (Vault, Shamir, sovereignty) at $0 incremental cost, with a clear Phase 10 upgrade path to YubiHSM 2 for hardware-isolated signing if needed. The threat-model degradation is real (see threat-model.md A3/A4) but bounded by Core invariant #16 (decrypt-on-demand, zeroize-on-completion), which limits the in-memory exposure window to microseconds per signing operation.

**Consequences.**
- Vault is now an **encryption envelope**, not a signer. Vault's role is reduced to: wrap/unwrap arbitrary 32-byte plaintext using one `aes256-gcm96` master key.
- Plaintext private keys exist in `fwd`'s process memory only during the bounded signing operation. Mitigated by `mlock` (process-locked memory, no swap), decrypt-on-demand (no caching), and zeroize-on-completion.
- The `Signer` protocol abstraction in `architecture.md` § The signer interface is unchanged, but the v1 implementation becomes `EnvelopeSigner` (decrypts via Vault, signs with `eth-account`) instead of `VaultTransitSigner`.
- The DER → low-S → v-recovery code path is removed from v1. `eth-account` returns Ethereum-shaped output directly. The forensic surface for Phase 10 (e.g., YubiHSM PKCS#11) will reintroduce DER + v-recovery, but only when a hardware backend lands.
- The Vault policy fwd uses gains `transit/encrypt/+` and `transit/decrypt/+` (capability `update`); loses any `transit/sign/+` capability that was previously specified.

**When to revisit.** When AP is ready for Phase 10 hardening: YubiHSM 2 via PKCS#11 (`Signer` protocol implementation #2) gives keys-never-leave-hardware semantics for signing operations and is the canonical upgrade. Until then, Path 2 is the v1 substrate.

---

## D2. Deployment: Docker Compose, host-agnostic

**Decision.** `fwd` is deployed as a `docker-compose.yml` checked into the repo. The compose file makes no assumptions about the host (Scaleway, ap-ftso-02, a fresh VPS, khosi's laptop). Host-specific configuration flows through `.env`.

**Alternatives considered.**
- **K3s on ap-ftso-02** — AP's existing K8s cluster.
- **Pulumi-managed Scaleway instance** with cloud-init — declarative IaC.
- **Bare systemd units** on the host — minimal abstraction.

**Why Docker Compose.** AP's only operator (single human + agents) explicitly preferred Docker over K3s for `fwd`. K3s is operationally heavier than fwd needs, couples fwd's lifecycle to the K3s control plane (a reason to *not* run fwd there), and adds K8s-specific auth complexity (TokenReview, ServiceAccounts). Docker Compose is two commands to bring up, runs identically on any host, and the entire deployment artifact is one YAML file.

**Consequences.**
- No K8s service discovery, no NetworkPolicy, no PVC management. Volumes are Docker-managed.
- Caller authentication can't use K8s SA tokens — bearer API keys instead (see D8).
- Migration to K3s is reversible later (compose → StatefulSet is mechanical) but explicitly not the v1 path.
- Pulumi rule from root `CLAUDE.md` (Pulumi exclusively for K8s) does not apply here — there is no K8s involvement.

**When to revisit.** When `fwd` needs to scale beyond one operator's cluster (probably never), or when AP gains a multi-region / HA requirement for signing (also probably never — signers don't HA-scale cleanly).

---

## D3. State: SQLite + Litestream

**Decision.** `fwd` persists state (nonces, transactions, audit log, callers, wallets) in a single SQLite file in WAL mode, replicated continuously by a Litestream sidecar to a **local `backup` volume** (the Scaleway Object Storage destination this record originally named was reverted at v0.4.3 — "no outside dependencies"; off-host transport is operator-driven. The SQLite + Litestream decision itself stands).

**Alternatives considered.**
- **Postgres** in a sidecar container.
- **MongoDB** (AP's default datastore for FTSO).
- **Redis** + on-disk snapshots.
- **Embedded LMDB / BoltDB** (Go-style).

**Why SQLite.** A signer is correctly designed as a singleton — one nonce manager, one policy decision point, one audit log writer. Multi-writer state stores solve a problem `fwd` doesn't have. SQLite's write throughput in WAL mode is four orders of magnitude above AP's signing volume. Operating it is essentially nil — no daemon to harden, no auth model to misconfigure, no listening socket. Litestream gives continuous off-host backup with sub-second RPO at no operational cost.

**Consequences.**
- Single-pod design is enforced by SQLite's POSIX locking semantics. Cross-pod sharing is fragile and disqualified.
- API + receipt watcher collapse into one process (asyncio task). Cleaner than the K3s sketch's separate api/watcher pods.
- Schema migrations via Alembic; SQLite's lack of `ALTER COLUMN` requires `render_as_batch=True` for column changes, but that's well-supported.
- Backup discipline shifts from "Postgres pg_dump cron" to "Litestream restore drill."

**When to revisit.** If `fwd` ever needs to be multi-instance (it shouldn't — see D2), or if the audit log's growth rate makes SQLite's single-file VACUUM painful. Neither is plausible at AP's signing volumes.

---

## D4. Vault distribution: HashiCorp Vault OSS, BSL-licensed

> **MOOT at v1.0.0a1 — Vault was retired entirely (D1); there is no Vault to distribute.** Record kept as honest history of why Vault OSS was chosen when it was the custody backend (Phase 3a–7).

**Decision.** Use HashiCorp Vault OSS (Business Source License). Pin the version. Write `fwd`'s Vault client against the stable Transit API contract.

**Alternatives considered.**
- **OpenBao** — Linux Foundation fork of pre-BSL Vault, MPL-2.0, API-compatible.
- **Vault Enterprise** — commercial, ~$30k+/year.

**Why Vault OSS.** This is the box that holds AP's revenue keys. The prudent choice for that box is the option with more security audits, more years of production deployment in financial institutions, and a dedicated security team behind it. That's Vault. The BSL license forbids running Vault as a competing managed service — not relevant to AP's internal use. OpenBao is the philosophical fit for AP's open-source ethos, but is younger and has fewer audits to date.

**Consequences.**
- AP accepts the BSL license terms (functionally equivalent to MPL-2.0 for internal use).
- The Transit API surface is stable and matches what OpenBao mirrors most faithfully — swap is a one-line change in `docker-compose.yml` if needed later.
- Reviewer's earlier "lean OpenBao" position is explicitly walked back here. The reasoning: AP's open-source ethos applies to AP's *own* code, not to the choice of upstream dependencies for security-critical infrastructure.

**When to revisit.** In 12–18 months when OpenBao has more audits and production years; if it's solid by then, swap. Also revisit if HashiCorp does something user-hostile to BSL terms.

---

## D5. Key migration for `0x7c3579…c294` (FTSO claim recipient)

**Decision.** Generate a fresh secp256k1 key inside fwd, sealed under the master (HashiCorp Vault retired v1.0.0a1 — D1; "inside Vault" was the pre-v1.0.0a1 mechanic, corrected here as the named Phase-8b mechanical-mirror-tail closure) during Phase 8. Authorize that fwd executor wallet on-chain via `ClaimSetupManager.setClaimExecutors` signed by the identity hardware wallet — the operator's claim-recipient is unchanged. Do NOT import the existing `.env`-resident private key.

**Alternatives considered.**
- **Import the existing key** into Vault Transit (Vault supports `wrap`-based key import). Preserves the on-chain configuration. Avoids a rotation transaction.

**Why generate fresh.** Importing preserves convenience but inherits whatever exposure history the existing key has — `.env` files on disk, possibly in shell history, possibly in old git commits, possibly in backup tarballs. We can't audit retroactively. Importing is "stop making it worse"; rotating is "the threat model resets at epoch N, provably." The on-chain rotation cost is one transaction (~$0.10 in FLR gas) plus one hardware-wallet signature ceremony. That's a rounding error against the value protected.

**Consequences.**
- Phase 8 includes a one-time on-chain `ClaimSetupManager.setClaimExecutors` transaction (the operator's claim-recipient is unchanged).
- The hardware wallet that controls the identity address `0x26534aC74153E3257dDD3471f96faA33D5D3B575` must be available during the cutover. (Identity keys themselves do not migrate to fwd — they stay offline.)
- After rotation, every subsequent claim signed by the new Vault-resident key is cryptographically uncontaminated.
- The procedure becomes a documented runbook (not yet written) reusable for any future key rotations (compromise response, hardware-wallet upgrade, scheduled hygiene).

**When to revisit.** Per-key, at every migration. Coston2 test wallet (Phase 9) follows the same logic — generate fresh, fund the new address, retire the old. `apcli` and other backends similarly.

---

## D6. Vault unseal: 3-of-5 Shamir, distributed across 5 failure domains

> **MOOT at v1.0.0a1 — Vault was retired (D1); the sealed local master requires NO unseal ceremony** (Core invariant #8 — fully unattended on restart). No Shamir shares, no paper/GPG distribution. Record kept as honest history of the Phase 3a–7 Vault operational model.

**Decision.** Initialize Vault with 5 unseal shares, threshold 3. Distribute as: 2 paper at distinct physical locations + 3 GPG-encrypted on (laptop, private GitLab repo, USB at a third location).

**Alternatives considered.**
- **Auto-unseal via cloud KMS** — disqualified by D1 (no cloud dependency).
- **Auto-unseal via second tiny Vault** (transit auto-unseal) — viable in Phase 10 but doubles the Vault count for v1.
- **All-paper shares** — most paranoid, most operationally awkward.
- **All-digital shares** — easier to back up, but a single GPG-key compromise breaks the whole scheme.

**Why this split.**
- Routine recovery (laptop wiped, host restarted): laptop GPG share + GitLab GPG share + paper #1 = threshold met without leaving the desk.
- Catastrophic recovery (house fire, theft of laptop and home documents): paper #2 (off-site) + GPG share on GitLab + GPG share on USB at second location = threshold met from second location.
- Security against theft of GPG key alone: attacker has 3 GPG-encrypted shares but cannot decrypt them. Mitigation strengthened by GPG private key on a YubiKey hardware token with PIN.
- Security against partial physical compromise: 2 paper + 1 GPG share at any single location = below threshold. Attacker needs ≥2 distinct physical compromises plus GPG access, or ≥3 paper shares from ≥3 locations.

**Consequences.**
- Operator overhead: ~5 minutes of unseal ritual after every Vault container restart in v1. With auto-unseal in Phase 10, this approaches zero.
- Documentation overhead: `runbooks/unseal.md` enumerates the share locations (without revealing them publicly), and `runbooks/share-recovery.md` documents how to reconstruct shares if one location is lost (Vault supports re-issuing shares without rekeying).
- GPG key custody becomes a v1 operational dependency. If khosi's GPG key is lost, the digital shares become useless — paper shares alone can't meet threshold without the digital shares.

**When to revisit.** Phase 10 auto-unseal decision (HSM-backed or transit-seal). Also revisit if AP grows beyond a single human operator — multi-operator unseal would require redistributing shares across operators.

---

## D7. Repo visibility: public on GitLab

**Decision.** `gitlab.com/proofs.africa/fwd` is public. Code, architecture, decisions, threat model, dependency list — all in the open.

**Alternatives considered.**
- **Private repo** — slight obscurity advantage; operational schemas not visible.

**Why public.**
- The security model of `fwd` is policy + custody, not code secrecy. Concealing the architecture is weak protection at best.
- Public review catches bugs. `fwd`'s code path is small enough to attract scrutiny.
- Reusable by other FTSO providers — AP isn't the only operator with the `.env PRIVATE_KEY` problem. Publishing `fwd` is a small contribution to the Flare ecosystem.
- Forces discipline. Public repos can't have a "TODO: actually validate this" left in. If AP can't make `fwd`'s code public, AP shouldn't be running `fwd`.

**What does NOT live in the public repo.**
- The `master.key` sealed master (mode-0600, host-provisioned, never committed; v1.0.0a1 — replaced the retired Vault unseal shares).
- Caller API keys (issued at runtime, stored as argon2id hashes).
- `policy.yaml` *values* for production wallets — values live in a separate private location (private GitLab repo or env-injected on host).
- `FWD_ADMIN_KEY` and operator secrets (env-injected). (Litestream cloud credentials / Vault root token / AppRole secret IDs are all retired — local-only backups since v0.4.3, no Vault since v1.0.0a1.)
- The `address` field of any wallet is public anyway (visible on-chain).

**Consequences.**
- The threat model document is also public — it tells attackers what `fwd` defends against and where the residual risks are. This is acceptable; security through obscurity is not the model.
- Documentation discipline: every doc in the repo must be safe to publish.
- License: MIT (`LICENSE` at repo root).

**When to revisit.** Never, plausibly. A move to private would only follow a decision to harden by obscurity, which AP has rejected.

---

## D8. Caller authentication: bearer API keys, scoped per policy

**Decision.** Each caller authenticates to `fwd` with a bearer API key (`Authorization: Bearer fwd_live_…`). Keys are issued by `fwd`'s admin CLI, stored as argon2id hashes, rotatable at runtime, and mapped in policy to a specific set of `(wallet, contract, method, max_value, rate)` permissions.

**Alternatives considered.**
- **K8s ServiceAccount tokens** + TokenReview — disqualified by D2 (no K8s).
- **mTLS with self-signed CA** — `fwd` issues client certs at install time. Stronger but more setup.
- **SPIFFE / SPIRE workload identity** — strongest model; requires a SPIRE deployment.
- **HMAC-signed requests** — replay-safe but stateful per caller.

**Why bearer keys for v1.**
- Simplest model that meets the threat: callers live on the same host as `fwd` (Docker bridge); the API key never crosses the public internet.
- Compromise of one key cannot exceed that caller's policy (the whole point of `fwd`).
- Rotatable from the CLI without service restart. Compromise response is fast.
- Argon2id hashing means a database leak doesn't yield usable keys.

**Consequences.**
- A compromised caller container hands the attacker a usable API key. Mitigation: tight policy scope per caller, rate limits, audit-log visibility.
- API keys must be injected as env vars on caller startup. The pattern replaces `PRIVATE_KEY=…` with `FWD_API_KEY=…` — a much smaller blast radius but still a secret on disk in the caller.
- Cross-host callers (e.g., a Claude agent running off the host) need a stronger model. mTLS or SPIFFE goes in Phase 10 if any caller crosses the host boundary.

**When to revisit.** When any caller lives outside the host running `fwd`, or when AP has a SPIRE deployment available. Also revisit if API-key rotation cadence becomes a complaint (suggests rotation should be automated).

---

## D9. Wallet provisioning: HTTP + CLI create; CLI-only import; no plaintext export

**Decision.** Three wallet-provisioning paths in v1, with deliberately asymmetric ergonomics:

- **Create — HTTP + CLI.** `POST /v1/admin/wallets` (admin-scoped) and `clifwd wallets create` both call the same flow: `fwd` generates a fresh secp256k1 privkey internally via `eth_account.Account.create()`, derives the address, encrypts the privkey via `SealedMaster.encrypt` (`seal:v1:` ciphertext; v1.0.0a1 retired Vault Transit — D1), persists `(name, address, privkey_ciphertext, vault_master_key='local:v1', policy_path)` in SQLite, and zeroizes the plaintext bytearray. Plaintext privkey never leaves `fwd`'s process; no caller (not even the admin) ever sees it.

- **Import — CLI only.** `clifwd wallets import --privkey-file <path>` provisions a wallet from an existing 32-byte hex-encoded privkey supplied by the operator. **No HTTP endpoint.** The CLI enforces a refusal table (file mode, file owner, content shape, name uniqueness) before accepting the file.

- **Export — not supported in v1.** Deferred to a future ship gated on a real consumer surfacing.

**Alternatives considered.**

- HTTP `POST /v1/admin/wallets/import` with privkey in the request body — rejected. A privkey traversing HTTP enters TLS termination logs, FastAPI access logs, reverse-proxy memory, and any load-balancer header logs. The single-import-event-permanent-leak surface contradicts the "no plaintext on disk" property `fwd` is built to provide. CLI-only import forces a single, operator-controlled, file-based path with explicit mode and ownership requirements.
- Accept Geth v3 keystore JSON (passphrase-locked) for import — rejected for v1. Adds ~200 lines of decryption code and a passphrase-prompt UX. Hex format covers v1's expected use cases (`apregister/` Coston2 test wallet migration; ad-hoc operator wallets; disaster recovery from offline backup). Phase 10+ may add Geth JSON if a real consumer requires it.
- Plaintext export via API — rejected. The architectural intent is "keys never leave `fwd`'s process except during the bounded signing operation." Real export use cases are handled differently: disaster recovery via Litestream + Vault Raft snapshots; HW-wallet migration via on-chain key rotation; forensics via audit-log walks.

**Why CLI-only import.** Forces the privkey to traverse a single, operator-controlled, file-based path with explicit mode and ownership requirements. The privkey never enters `fwd`'s HTTP layer, never lands in any web log, never exists in reverse-proxy memory. The operator's act of placing the file on disk is the import authorization — the same security pattern as `~/.ssh/id_rsa` (file mode 0600 is the contract).

**Refusal table** (codified in `clifwd wallets import`; the CLI exits with code 2 and prints a clear error):

| Condition | Response |
|---|---|
| `--privkey-file` does not exist | `privkey-file not found: <path>` |
| File mode is not exactly `0600` | `privkey-file mode must be 0600 (got <octal>)` |
| File owner UID doesn't match the user running `clifwd` | `privkey-file must be owned by the user running clifwd (file_owner=<uid>, current_user=<uid>)` |
| File content (after stripping whitespace) doesn't decode to exactly 32 bytes via `bytes.fromhex(...)` | `privkey-file must contain a 32-byte hex-encoded secp256k1 private key (got <n> bytes)` |
| Wallet name already exists in the `wallets` table | `wallet '<name>' already exists` |
| Optional `--expected-address` is provided AND derived address doesn't match | `derived address <X> does not match --expected-address <Y>` |

**Consequences.**

- Phase 4's admin CLI gains `clifwd wallets create`, `clifwd wallets import`, and `clifwd wallets list` commands. Phase 4's existing scope (caller-auth + admin CLI) is naturally extended; no new phase is created.
- Phase 5 (state schema) is unchanged — the `wallets` table from `architecture.md` already accommodates both create and import paths.
- Phase 7 (audit log) must include `action='wallet-create'` and `action='wallet-import'` row types. The import audit row records `request_json={name, source_file_path, source_file_mode, source_file_owner}` — file metadata, NOT the privkey. The structlog scrubber from v0.2.1 § Implementation hazards catches any accidental privkey leak in import-path code.
- D5's "generate fresh + rotate" prescription remains unchanged for the FTSO claim recipient — that key never imports. D9 governs the OTHER wallets (e.g., `apregister/` Coston2 test wallet, ad-hoc operator wallets) where import is operationally acceptable.
- Operators MUST handle the source `privkey-file` securely BEFORE import: place on a trusted filesystem, ensure mode 0600, choose `--shred-source` if no offline backup is needed. `clifwd` cannot retroactively protect a key that was leaked before import.

**When to revisit.**

- **Geth v3 keystore JSON support** if a real consumer requires it (probably never for AP).
- **Plaintext export** if disaster recovery, HW-wallet migration, or forensics genuinely needs a path that the existing mechanisms (Litestream restore, on-chain rotation, audit log) can't serve. Re-introducing export requires explicit operator authorization tied to the use case AND would probably argue for moving custody to YubiHSM 2 first (since hardware-isolated keys are non-exportable by construction — settling the architectural question for good).
- **HTTP import endpoint** if an automation use case surfaces (e.g., a future bulk-migration tool). Re-introducing HTTP import requires explicit operator authorization AND a new threat-model section for the new exposure surface.

## D10. Token lifecycle: re-auth on 403 (v1), proactive renewal at Phase 7, periodic tokens at Phase 8

> **MOOT at v1.0.0a1 — Vault was retired (D1); the sealed local master authenticates to nothing, so there is no token, no lease, no renewal, and no AppRole.** Record kept as honest history of the Phase 3a–7 Vault auth model. (See `architecture.md` § Auth lifecycle: "There is none.")

**Decision.** `fwd` authenticates against Vault via AppRole at process startup (`POST /v1/auth/approle/login` with `(role_id, secret_id)` from env), caches the resulting client token in `mlock`-protected memory, and uses a single defensive fallback for token expiry: on any 403 response from a Vault API call, re-authenticate and retry the failed call exactly once. **No background renewal task in v1; no periodic-token configuration in v1.** AppRole role TTL stays at the v0.3.0a1 defaults: `token_ttl=24h, token_max_ttl=72h`. The strategy is staged: a proactive `auth/token/renew-self` background task lands in Phase 7 (alongside policy + audit hardening); periodic-token migration (`token_period`) lands at Phase 8 (first production migration), if and only if a real high-volume consumer materializes.

**Alternatives considered.**

- **Background `renew-self` task at v0.3.0a4 (Phase 3b).** Asyncio task runs every `ttl/3` seconds; calls `POST /v1/auth/token/renew-self` while within `max_ttl`; falls back to full re-auth at the `max_ttl` boundary. Rejected for v1: ~80 lines of code (renewal loop, expiry tracking, `lease_id` bookkeeping, integration test with shortened TTL or mocked clock) shipped without a high-volume consumer to drive the design. Phase 3b's verification gate is one wallet creation; Phase 3c is one mock-RPC sign-and-send; Phase 8's first real consumer (`ftso-fee-claimer`) signs ~once per reward epoch (3.5 days, well under the 24h TTL). The 403 fallback covers all v1 volumes. Premature optimization; ships in Phase 7.

- **Periodic tokens (`token_period=24h`) at v0.3.0a4.** AppRole role configured with `token_period` instead of `token_ttl/token_max_ttl`. Periodic tokens can be renewed indefinitely within `period` seconds; never hit a max_ttl boundary. Canonical Vault recipe for daemon services ([Vault docs: AppRole patterns](https://developer.hashicorp.com/vault/tutorials/recommended-patterns/pattern-approle)). Rejected for v1: requires re-running `vault-init.sh` with new role flags (operator-side change, not just a code change), and gives no benefit at Phase 3b's volume since renewal isn't yet implemented. Migrate when the renewal task lands AND when a real high-frequency consumer materializes — both naturally aligned with Phase 7/8.

- **Re-auth on every signing call.** Rejected: doubles round-trips, defeats the point of token caching, increases load on Vault.

- **Long-lived single token** (e.g., `token_ttl=8760h`). Rejected: increases blast radius of a leaked token; Vault's docs explicitly recommend against it for service accounts; a leaked token usable for a year is structurally indistinguishable from a static API key (a regression).

**Why this staging.**

1. **v1 volumes are low.** Wallet creation is rare (operator-driven). Phase 3c's verification gate is one Coston2 tx. Phase 8's `ftso-fee-claimer` claims ~once per reward epoch. Token won't expire mid-test or mid-claim. The 403 fallback is sufficient and exercises the re-auth path end-to-end.
2. **The 403 fallback is defense-in-depth even after Phase 7 lands.** Clock skew, vault failover, manual revocation — all surface as 403. Building it first means the renewal task adds complexity *without changing the surface contract*.
3. **Real consumers drive design.** Designing a renewal protocol against a hypothetical every-minute workload is a Karpathy violation ("simplicity first"). When a real consumer (e.g., `fics` write paths under operator-approved automation, or AI-agent signing) lands, the workload's actual shape (request bursts vs steady state, latency tolerance, max gap-without-signing) informs the renewal interval and the fallback cost.
4. **Periodic tokens are operator-side.** Switching from `token_ttl/token_max_ttl` to `token_period` is a `vault-init.sh` flag change; same Vault client code on either side. Decoupling means the migration can ride alongside Core invariant #17's production wipe-and-redo without code churn.

**Consequences.**

- **v0.3.0a4 (Phase 3b)** ships `infra/vault_client.py` with: `_login()` on init, `encrypt(plaintext) -> ciphertext` and `decrypt(ciphertext) -> plaintext` using cached `X-Vault-Token`, single-retry-on-403 inside an `_request()` helper. Approximately 50 lines of auth logic. Verifies the auth path against the live dev Vault as part of the integration test.
- **v0.3.0 (Phase 3c)** uses `decrypt()` in the signing path. No auth changes; same client.
- **Phase 7 (v0.5.0)** adds: an asyncio background task that calls `auth/token/renew-self` every `lease_duration / 3` seconds; a structlog event on each renew/re-auth; an integration test that exercises a 24h+ token cycle (mocked clock OR shortened TTL on the AppRole role). Approximately 80 lines of code + one new test.
- **Phase 8 (v1.0.0)** evaluates: if the first production consumer exhibits high-frequency signing AND the operator wants to eliminate the 72h `max_ttl` re-auth boundary, re-run `vault-init.sh` with `token_period=24h, token_max_ttl=0`. The Vault client adapts automatically. Operator runbook gains an entry documenting the migration: stop fwd → re-run script with new flags → restart fwd.
- **Token caching** continues to honor Core invariant #16 (`mlock` against swap; zeroize on logout/shutdown). The cached token is a bearer credential; same hygiene as a wallet privkey.
- **The Phase 7 renewal task** must consult `lease_renewable` and `lease_duration` from the login response, NOT hardcoded TTL values — Vault may rotate role config underneath us.

**When to revisit.**

- **High-volume consumer surfaces in Phase 4–6.** If a real workload starts pushing into the every-minute regime before Phase 7 ships, accelerate the renewal task into the same ship as the consumer's migration. Don't wait for Phase 7 to ship if the workload demands it.
- **Vault changes its renewal protocol.** Unlikely for OSS in v1.x but possible. Re-evaluate when fwd lands on Vault 1.20+ or migrates off Vault.
- **Periodic-token security audit at Phase 8.** Trade-off: no automatic credential rotation in exchange for no `max_ttl` pain. Operator must accept that `secret_id` rotation is now their hygiene task (e.g., quarterly, or on incident). Document in the production runbook before the migration ships.
- **Token-stealing attack surfaces in the threat model.** A1–A12 currently treat process-memory compromise as game-over (privkeys + token both exposed). If a more granular attacker model emerges (e.g., side-channel reading token without privkey), shorter TTLs become valuable and this decision needs refresh.

## D11. Admin auth and caller auth are distinct, never bridged

**Decision.** `fwd` has exactly two auth boundaries in v1, and they share no code path:

- **Admin auth** — single static bearer token, sourced from the `FWD_ADMIN_KEY` env var, gated by `src/fwd/api/admin_auth.py::require_admin`. Used **only** for `/v1/admin/*` endpoints (provisioning: `POST /v1/admin/wallets`, `POST /v1/admin/callers`, `DELETE /v1/admin/callers/{name}`, future admin operations). No caller endpoint accepts an admin key. Constant-time compare via `hmac.compare_digest`. 401 on missing/invalid; 503 when `FWD_ADMIN_KEY` is empty.
- **Caller auth** — argon2id-hashed bearer tokens issued by `fwd` itself (via `clifwd callers create`), persisted to the `callers` table, looked up by prefix at request time. Gated by `src/fwd/api/caller_auth.py::require_caller` (Phase 4). Used **only** for caller-facing endpoints (`/v1/sign-and-send`, `/v1/sign-typed-data`, `/v1/wallets`, `/v1/transactions/{tx_id}`). No admin endpoint accepts a caller token.

The `require_admin` and `require_caller` dependencies live in separate modules (`api/admin_auth.py` vs `api/caller_auth.py`), have separate type aliases, and surface different exceptions. A request that lands on a caller endpoint with an admin token is rejected exactly as a request with a forged token would be — there is **no fallback** to admin-key auth on caller endpoints, and no fallback to caller-token auth on admin endpoints.

**Alternatives considered.**

- **Single auth dependency that resolves either type.** Rejected. Conflating admin and caller identity removes the bright line that protects admin operations from a leaked caller key (and vice versa). The two have fundamentally different threat models: admin is a static operator credential rotated manually; callers are programmatically-issued, scoped, and revocable.
- **Caller endpoints accept admin key as a "super-user" override.** Rejected. Admin keys cannot impersonate callers — that would defeat per-caller policy enforcement and per-caller audit attribution. If an operator needs to test a caller's permissions, they issue themselves a caller token and use it.
- **Phase 4 swaps `admin_required` to a polymorphic auth dependency that gates on URL prefix.** Rejected. URL-based auth dispatch is an anti-pattern (attackers control URLs); explicit per-endpoint dependencies are cleaner and harder to misroute.

**Why this matters.** v0.3.x ships with `/v1/sign-and-send` temporarily admin-gated as a stand-in until Phase 4 lands caller auth (per `architecture.md` § Caller authentication). The risk surfaced in the v0.3.1 audit (F2.4): implementation inertia in Phase 4 might preserve the admin-gating "just for now" or build caller auth as a wrapper around admin auth. This decision pins the design before Phase 4 implementation begins.

**Consequences.**

- **v0.4.0-alpha (Phase 4)** ships `src/fwd/api/caller_auth.py::require_caller` (new module), an `app/caller_resolution.py` use case (lookup by prefix → argon2id verify → return resolved caller + policy_path), and the caller-auth path through `app/dependencies.py`. The existing `admin_required` is unchanged. `/v1/sign-and-send` swaps `dependencies=[admin_required]` to `dependencies=[caller_required]`; URL stays.
- **Tests verify the bright line:** an admin token presented to `/v1/sign-and-send` returns 401 (not 200); a caller token presented to `/v1/admin/wallets` returns 401 (not 200). These are explicit unit tests in v0.4.0-alpha, not implicit.
- **Audit-log attribution** is correct from Phase 4 day one: caller-endpoint actions log the resolved caller name, never the literal "admin"; admin-endpoint actions log the operator UID where derivable, never a caller name.

**When to revisit.**

- **A genuine super-admin operation surfaces** that the operator wants exposed via API rather than `clifwd` (e.g., emergency caller revocation). At that point, decide whether to (a) extend the admin-only API surface or (b) issue an admin user a caller token with elevated policy. Default to (b) for the principle-of-least-privilege.
- **Phase 10 mTLS** — when callers leave the host, the bearer-token model may be augmented with cert-based identity. The two-auth-boundary discipline still applies; only the credential format changes.

## D12. CLI in-process pattern for `clifwd wallets import`

**Decision.** `clifwd wallets import` (per D9: CLI-only, no HTTP endpoint) does NOT call any HTTP API. It opens an in-process composition root via `from fwd.app.dependencies import SignerCM, get_signer`, reads the privkey file, validates against the D9 refusal table (mode 0600, owner UID, 32-byte hex content, name uniqueness, optional `--expected-address` match), and calls a new `app/wallet_import.py::import_wallet` use case. The CLI module itself imports only from `fwd.app.*` and standard library; no `fwd.infra.*` imports.

The new use case `app/wallet_import.py` exposes:

```python
async def import_wallet(
    signer: EnvelopeSigner,
    *,
    name: str,
    policy_path: str,
    privkey_file: Path,
    expected_address: str | None = None,
) -> WalletImportResult: ...
```

It performs the file read, refusal-table validation, address derivation + match check, encryption + persistence (delegating to `EnvelopeSigner.import_wallet`, a new method that mirrors `create_wallet` but accepts an externally-provided privkey bytearray instead of generating one).

`clifwd wallets create` keeps its existing HTTP-client shape (it calls `POST /v1/admin/wallets`). The two flows diverge at the CLI surface, not the use-case surface. The CLI manages SQLite session and Vault client lifecycle via `SignerCM` exactly as the api layer does — same composition root, same async-context-manager idiom.

**Alternatives considered.**

- **Allow `cli/` to import from `infra/` directly** (loosen the layer-boundary test). Rejected. The CLI boundary is what stops a CLI command from accidentally bypassing the use-case layer's exception translation, audit logging (Phase 7), and policy hooks. The boundary is asymmetric for a reason: HTTP commands go through the use case; in-process commands also go through the use case.
- **Spawn a dedicated subprocess** that talks to `fwd`'s running container via a Unix socket. Rejected as Phase 10 over-engineering. The CLI runs in the same Python process tree as the daemon's deployment context (`docker exec fwd clifwd ...` on the production host); in-process is correct here.
- **Have `clifwd` proxy through a hidden admin HTTP endpoint that accepts privkey bodies**. **Strongly rejected.** Reintroduces the HTTP privkey-traversal that D9 explicitly forbids. Privkeys never enter HTTP.
- **Inline the import flow in `clifwd wallets import`** without an `app/wallet_import.py` use case (just call `EnvelopeSigner` directly from cli). Rejected. Mixes interface-layer and infra-layer responsibilities; defeats the use-case orchestration pattern that Phase 7's audit-log row will hook into.

**Why this matters.** The v0.3.1 audit (F3.2) flagged that the existing "CLI as HTTP client" pattern conflicts with D9's CLI-only import requirement. Without an explicit decision before Phase 4, Sonnet would either (a) violate the layer-boundary test and require a path-(b) rewrite, or (b) inline infra calls from the CLI and leak the use-case boundary. This decision pins the right shape.

**Consequences.**

- **v0.4.0-alpha (Phase 4)** adds `src/fwd/app/wallet_import.py` (the use case), extends `src/fwd/infra/envelope_signer.py::EnvelopeSigner` with `import_wallet(privkey_buf, ...)` (mirrors `create_wallet` but accepts the privkey externally), and adds `src/fwd/cli/wallets.py::import_` subcommand that opens `SignerCM` and calls the use case.
- **Layer-boundary test** stays as-is — `cli: {app, domain}` and `app: {domain, infra}` continue to hold.
- **Phase 7's audit row** for `action='wallet-import'` (per `architecture.md` § Wallet provisioning) hooks into `app/wallet_import.py`, not into the CLI.

**When to revisit.**

- **A second in-process CLI command lands** (e.g., a Phase 6 restore command). Same pattern: app-layer use case + thin CLI wrapper.
- **Phase 10 splits `clifwd` into a separate package distributed to operator workstations** that talks to a remote `fwd`. At that point, in-process import gets reconsidered: either keep file-on-host with the host-pinned CLI, or design a different secure-import path. Don't pre-decide.

## D13. Policy ownership: caller-keyed, with wallet-level constraints reserved for Phase 7

**Decision.** Policy is **caller-keyed** — when caller `X` requests `/v1/sign-and-send` for wallet `Y` invoking method `M` on contract `C`, `fwd` resolves the caller's `policy_path` against `policy.yaml` permissions and evaluates the (caller × wallet × contract × method × args) tuple. The wallet's `policy_path` (already on the `wallets` table since v0.3.0a6) is reserved for Phase 7 wallet-level constraints (per-wallet rate limits, per-wallet daily-spend caps); v0.4.0-alpha through v0.4.x persist it without using it for permission decisions.

The policy.yaml structure (Phase 7) lands as:

```yaml
version: 1

callers:
  ftso-fee-claimer-prod:
    policy_path: ftso-claim
  apregister-e2e:
    policy_path: apregister-e2e

wallets:
  claim-recipient-flare-prod:
    policy_path: claim-recipient        # Phase 7 wallet-level constraints
  register-coston2-test:
    policy_path: register-coston2-test

permissions:                            # PRIMARY indirection: keyed by caller.policy_path
  ftso-claim:
    contracts:
      "0x...RewardManager":
        methods:
          claim:
            max_value_wei: 0
        wallet_allowlist: ["claim-recipient-flare-prod"]
    rate:
      per_hour: 100
      per_day: 1000

  apregister-e2e:
    contracts:
      "0xF9fDB...":
        methods:
          register:
            max_value_wei: 0
        wallet_allowlist: ["register-coston2-test"]
    rate:
      per_hour: 50
      per_day: 200

wallet_constraints:                     # SECONDARY indirection: keyed by wallet.policy_path; Phase 7+
  claim-recipient:
    max_daily_aggregate_wei: 0          # claim-only wallet, never sends value
  register-coston2-test:
    max_daily_aggregate_wei: 1000000000000000000  # 1 C2FLR/day
```

Permission evaluation order (Phase 7):
1. Resolve caller's `policy_path` → permissions block.
2. Check `wallet_allowlist` includes the requested wallet.
3. Check contract address in allowlist.
4. Check method in allowlist.
5. Check decoded args within bounds (`max_value_wei`, recipient pattern).
6. Check rate limit (per-hour, per-day) on (caller, wallet, contract, method) key.
7. Check `wallet_constraints[wallet.policy_path].max_daily_aggregate_wei` against pending+confirmed value sum.
8. Default-deny on any failure.

**Alternatives considered.**

- **Wallet-keyed policy** (each wallet has a list of permitted callers/contracts/methods). Rejected for caller intuition: a caller asking "what can I sign?" is the more common operator question, not "what can be signed with this wallet?". Caller-keyed reads naturally; wallet-keyed inverts the mental model.
- **`(caller, wallet)` join key** (permissions are explicit per-pair). Rejected for cardinality: with 5 callers and 50 wallets, that's 250 explicit permission rows; the caller-keyed model with `wallet_allowlist` collapses this to 5 caller rows. Adds complexity without information-theoretic gain.
- **Drop `wallets.policy_path` entirely** (it's currently unused; Phase 4 doesn't need it). Rejected. Schema migrations are expensive; the field is already populated for existing wallets; Phase 7 has a clear use for it (per-wallet aggregate constraints). Keeping it costs zero in v0.4.x and unlocks Phase 7 cleanly.

**Why this matters.** The v0.3.1 audit (F7.4) flagged that `policy_path` is currently a free-form string with no policy semantics. Phase 4 will add the `callers` table with its own `policy_path`; without a decision on the relationship, Phase 4 might bake in the wrong indirection (e.g., wallet-keyed) that Phase 7 then has to undo.

**Consequences.**

- **v0.4.0-alpha (Phase 4)** ships the `callers` table with `policy_path TEXT NOT NULL`. The CLI `clifwd callers create --name <n> --policy <path>` accepts the path as a free-form string (Phase 7 validates it against `policy.yaml`). Phase 4 does NOT yet evaluate permissions — the temporary admin-gate on `/v1/sign-and-send` does not depend on policy_path.
- **v0.4.0 (Phase 5)** schema migration adds the full SQLite tables; `wallets.policy_path` and `callers.policy_path` are stored, no enforcement.
- **v0.5.0 (Phase 7)** introduces the policy engine that loads `policy.yaml`, resolves both `policy_path` indirections, evaluates the tuple per the order above. The Phase 7 canonical prompt will spec the engine's evaluation algorithm formally.
- **Phase 4's admin-key creation flow** continues to accept a free-form `policy_path` for both wallets and callers; consistency is verified at Phase 7 load time (unknown `policy_path` → policy.yaml load fails noisily; default-deny applies until operator fixes).

**When to revisit.**

- **A real consumer needs a policy shape outside this model** (e.g., delegated signing with caller-of-caller chains, multi-signature requirements, time-of-day constraints). Re-evaluate at Phase 7 spec time; don't extend the schema speculatively.
- **`wallet_allowlist` becomes unwieldy** (e.g., a caller permitted on >50 wallets). Phase 7 may add wildcards or pattern matching; that's an extension, not a reversal of D13.

## D14. Policy engine implementation (Phase 7)

**Decision.** Phase 7 implements the policy engine spec'd in D13. Concretely:

- **File location.** `FWD_POLICY_PATH` env var (default `/etc/fwd/policy.yaml`); operator mounts via docker-compose volume bind. The file is **operator-controlled and gitignored** (Core invariant #12 — policy values live outside the repo). The `.env.example` documents the variable; the actual `policy.yaml` is provisioned per-host.

- **Schema validation.** YAML loaded once at process startup; parsed into a Pydantic v2 `Policy` model (strict mode, `extra='forbid'`). Schema versioning is explicit: the file MUST declare `version: 1`; future schema breaks (Phase 10+) bump the version + add a migration path.

- **Schema shape** (refining D13's example with Phase 7 implementation details — D13 had method names; D14 promotes them to full ABI signatures to disambiguate overloads):

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
        "0xRewardManager...":             # checksummed; address-normalized at load
          abi: reward_manager             # references config/abis/registry.yaml
          methods:
            "claim(address,uint256)":     # full ABI signature (NOT bare name); selector computed at load
              max_value_wei: "0"          # decimal string; parsed to int at load
              arg_predicates:             # required when args constrain custody outcome
                recipient: "0x7c3579ab3e647395c96a1efc98af9a31c5ecc294"
                epochId: any              # sentinel; matches any decoded value
      wallet_allowlist: ["claim-recipient-flare-prod"]
      rate:                               # per (caller, wallet, contract, method) tuple
        per_hour: 100                     # ≤ 100 successful signings per UTC hour
        per_day: 1000                     # ≤ 1000 per UTC day

  wallet_constraints:
    claim-recipient:
      max_aggregate_value_wei_per_day: "0"   # claim-only wallet; never moves value
      rate:                                  # OPTIONAL wallet-level rate cap
        per_hour: 200
        per_day: 2000
  ```

- **Evaluation order** (refining D13's 8 steps with arg-predicate semantics):
  1. Resolve `callers.<name>.policy_path` to a `permissions.<path>` block. Missing → 403 default-deny.
  2. Look up `permissions.<path>.contracts.<request.to>` (address compared case-insensitive). Missing → 403.
  3. Decode `request.data` against `contracts.<addr>.abi` (D15). Decode failure → 403.
  4. Look up `methods.<decoded.method_signature>`. Missing → 403.
  5. Compare `request.value_wei <= method.max_value_wei` (BigInt). Exceeded → 403.
  6. For each `arg_predicates[name]`: if predicate is the string sentinel `any`, pass; else `name` must be in `decoded.args` (the projected scalars — B1 omits non-scalars) or 403. The predicate value is **coerced at evaluation time** against the decoded arg's Python type — bool checked before int (bool ⊂ int in Python), int via `int(str(pval))`, address (`0x` + 40 hex) compared case-insensitively, plain string compared exactly. Mismatch → 403.
  7. Check `wallet_allowlist` includes `request.wallet`. Missing → 403.
  8. Caller rate check (`scope_caller × scope_wallet × scope_contract × scope_method × window`): atomic increment-and-test under writer lock; cap exceeded → 403.
  9. Wallet constraints lookup (`wallets.<name>.policy_path` → `wallet_constraints.<path>`): aggregate-value-cap check and wallet-rate check (own bucket). Exceeded → 403.
  10. Allow. Audit row written by caller (sign-and-send use case), not by the policy engine.

- **Rate-limit state.** Two SQLite tables added at Alembic 0005 (a4 implementation ship — `infra/rate_repo.py`):

  ```sql
  CREATE TABLE rate_buckets (                 -- caller-keyed signing-count buckets
      caller        TEXT NOT NULL,
      wallet        TEXT NOT NULL,
      contract      TEXT NOT NULL,            -- lowercased address (policy_engine passes request.to.lower())
      method        TEXT NOT NULL,            -- full ABI signature
      window_kind   TEXT NOT NULL,            -- 'hour' | 'day'
      window_start  TIMESTAMP NOT NULL,       -- UTC-aligned bucket boundary
      counter       INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (caller, wallet, contract, method, window_kind, window_start)
  );

  CREATE TABLE wallet_buckets (               -- wallet-keyed aggregate-value buckets
      wallet               TEXT NOT NULL,
      window_kind          TEXT NOT NULL,     -- 'hour' | 'day'
      window_start         TIMESTAMP NOT NULL,
      counter              INTEGER NOT NULL DEFAULT 0,
      aggregate_value_wei  TEXT NOT NULL DEFAULT '0',  -- decimal string
      PRIMARY KEY (wallet, window_kind, window_start)
  );
  ```

  Windows are **fixed UTC-aligned buckets** (operator decision at v0.5.0a1): hour bucket `window_start = TRUNCATE(now, 'hour')`; day bucket `window_start = TRUNCATE(now, 'day')`. Trade-off: a 100/hour caller can issue 100 calls at 23:59 + 100 calls at 00:01 (effective 200 in 2 minutes around UTC midnight). Acceptable for v1; sliding windows deferred to Phase 10. Stale buckets older than the largest configured window are deleted at policy-load time (bounded growth). **Wiring status (Core invariant #18):** the `RateRepo.delete_stale(before=...)` repo method ships at v0.5.0a4 (substrate, unit-tested). v0.5.0a6 wired the lifespan policy-load + consistency-check (`main.py::_startup_policy_load`) but did NOT add the stale-bucket prune call (it was not in a6's gated scope — a6 was the sign-and-send core integration). The `delete_stale` invocation from the policy-load path **shipped v0.5.0a7**: `main.py::_startup_policy_load`'s success branch prunes buckets with `window_start` older than 2 days (safely older than the largest `hour`/`day` window), wrapped so a prune failure logs `lifespan.delete_stale_failed` and never blocks boot. The earlier "deferred to v0.5.0a7" marker is retired — it came true; rate/wallet buckets no longer accrete unbounded.

- **Concurrency.** Rate check + increment is a single round-trip under the writer lock (`BEGIN IMMEDIATE; SELECT counter; if counter < cap then UPDATE counter = counter + 1; COMMIT`). Audit log write (D16) happens in the same session — one writer-lock acquisition per request, same RequestScope pattern as v0.4.5.

- **Reload semantics.** **Startup-only in v1** (operator decision at v0.5.0a1). Policy.yaml changes require `docker compose restart fwd`. The earlier architecture.md claim "Policy is hot-reloaded on file mtime change" is retired. SIGHUP hot-reload deferred to Phase 10.

- **Startup fail-fast.** On boot, after loading policy.yaml:
  1. Every active row in `callers` (`revoked_at IS NULL`) MUST be declared in `policy.callers` **keyed by caller NAME** (per D13 — `policy.callers` is name-keyed; the loader and the evaluator MUST agree on the key space). The caller's stored `policy_path` MUST match the binding's `policy_path` (drift detection, mirrors `policy_engine` step 1), and the binding's `policy_path` MUST resolve to a `permissions` block. Any failure → fwd refuses to serve, logs the orphan/drifted caller, exits. (Refined at v0.5.0a4 — the a1 phrasing "MUST reference a policy_path that exists in policies block" was implementable two ways; `infra/policy_loader.py::check_consistency` check 1 and `app/policy_engine.py` step 1 are now both name-keyed-with-drift-check. The original canonical-prompt §2 check-1 wording speced the loader policy_path-keyed while speccing the evaluator name-keyed — a Reviewer-surfaced spec defect corrected at commit per the v0.4.0a5 precedent; see `docs/history/0.5.0a4-policy-engine.md`.)
  2. Every `policy.wallets` binding's `policy_path` MUST exist in `wallet_constraints` (check 5); every `wallet_allowlist` entry MUST resolve to a known wallet — DB `wallets` row or `policy.wallets` key (check 4). Missing → fail-fast.
  3. Every contract's `abi` in `permissions.*.contracts.*` MUST be a registered ABI name (check 2), AND every `methods.<sig>` under a known-abi contract MUST resolve to a signature the registry indexes for that ABI (check 3). **Shipped v0.5.0a6 (Core invariant #18):** the a6 integration ship added `AbiRegistry.signatures_for(abi_name) -> frozenset[str]` and wired loader check 3 in `policy_loader.check_consistency` (only when the abi IS known, to avoid double-reporting an unknown-abi contract). The earlier "deferred to a6" marker is retired — it came true.

  This is the audit-time consistency check; once it passes, runtime evaluation is dictionary lookups.

- **Default-deny.** Non-negotiable (Core invariant #2). Every code path in the evaluator returns `Deny` unless an explicit `Allow` is reached at step 10. Synthetic-attack test at v0.5.0a6 verifies this against curated malicious inputs (unknown method, value > max, wrong arg_predicate, beyond rate, etc.).

- **Rate-bucket release on failure** (added at v0.5.0a2 self-review). The step 8 caller-rate increment and step 9 wallet-rate `counter` increment reserve a rate slot OPTIMISTICALLY (before signing). If the request subsequently fails at any later step (Vault decrypt error, RPC unreachable, broadcast rejection, transaction-row INSERT failure), the cleanup path MUST decrement those buckets — same `release_if_unused` semantic as the v0.4.0a5 nonce release. The step 9 wallet-bucket `aggregate_value_wei` is asymmetric: it is incremented ONLY after broadcast success (because it tracks value committed to chain, not value reserved). Broadcast failure leaves `aggregate_value_wei` unchanged; broadcast success increments. This asymmetry is intentional: rate buckets bound "intent expressed", aggregate-value bounds "value committed".

- **Admin endpoint policy_path validation** (added at v0.5.0a2 self-review). Endpoints that take a `policy_path` on entity create — `POST /v1/admin/callers`, `POST /v1/admin/wallets`, the CLI's `clifwd wallets import` — MUST validate the supplied path against the loaded `policy.yaml` at request time. A path not present in `policies` (for callers) or `wallet_constraints` (for wallets, where applicable) returns HTTP 400 with the orphan path echoed in the response body. Without this validation, an admin can create entities the next fwd restart will fail-fast against (per the Startup fail-fast section above), trapping the operator in a refuse-to-serve loop. The validation happens against the in-process policy snapshot — `docker compose restart fwd` is the only way to refresh it (Reload semantics above).

- **Idempotency replay vs policy re-evaluation** (added at v0.5.0a2 self-review). A `/v1/sign-and-send` request bearing an `Idempotency-Key` that matches a prior request's key (per architecture.md § Idempotency) does NOT re-evaluate against policy. The cached `tx_id` is returned with HTTP 200; an audit row is written with `action='sign-and-send-duplicate'` (see D16), `request_json` containing the new request envelope, and `outcome={"original_tx_id": "<uuid>", "original_audit_seq": <int>}`. Rate buckets and aggregate-value buckets are NOT incremented (the original signing already consumed them). The cached result remains valid even if `policy.yaml` is changed between the original signing and the replay; operator policy is that rotating `policy.yaml` MUST be paired with deliberate caller-key rotation if the rotating change is policy-tightening. Phase 10 may strengthen by binding replay validity to a policy-hash field. **Replay is status-blind by design (made explicit v1.0.0 after the fourth independent audit).** A cached transaction is replayed for its `(caller, idempotency_key)` regardless of on-chain outcome — including a tx that broadcast then reverted, was dropped, or the watcher marked `failed`. This is correct for at-least-once-delivery dedup (it is precisely what prevents a double-broadcast / double-claim on a client retry) and is deliberately NOT made status-aware: re-broadcasting a tx fwd believes failed but that may still be in a mempool re-introduces the exact double-spend risk idempotency exists to remove. The consequence the **consumer** owns: an idempotency key keyed only by logical identity (e.g. network / claim-type / beneficiary / epoch) pins a *failed* claim forever — a distinct logical retry after an on-chain failure MUST use a fresh idempotency key (the original attempt consumed it). The v1.0.0 broadcast-rejection fix removes the *terminal-rejection* sub-case: a node-deterministic `RpcError` (e.g. insufficient funds) raises before the transaction row is created, so no idempotency record exists and a corrected resubmission is not pinned; the residual pin is only broadcast-succeeded-then-reverted, which is the consumer's retry-key responsibility, not an fwd code change.

- **Face-C — orphaned reserved nonce (NAMED DEFERRAL → Phase 9/10; recorded v1.0.0).** A distinct nonce-lifecycle gap, NOT the broadcast-classification fix: a tx the node *accepts* (hash returned, no error) that then never mines — after the receipt watcher exhausts retries and marks it `failed` — leaves its reserved nonce orphaned forever; `nonce_reconcile` only *logs* the drift and never heals it. fwd has no nonce-reset surface by design (building one is the scope-creep the freeze guards against). Explicitly deferred to the Phase-9/10 nonce-lifecycle work — NOT v1.0.0 code (v0.4.5 precedent: fix the drill-surfaced bug, name-and-defer the deeper follow-up; Core invariant #18 — a named, discoverable deferral, never silent drift). Full context: `docs/history/1.0.0-phase-8b-fwd-side.md`.

**Why this matters.** D13 fixed the policy SHAPE (caller-keyed indirection); D14 fixes the IMPLEMENTATION (Pydantic schema, evaluation algorithm, rate-bucket state, reload semantics, startup checks, release-on-failure semantics, admin validation, replay semantics). Without D14, the Phase 7 a3 implementation prompt has too many open questions and Sonnet adapts in ways that may drift from operator intent.

**Consequences.**

- **v0.5.0a4 (Phase 7 policy engine ship)** lands `src/fwd/domain/policy.py` (Pydantic schema), `src/fwd/app/policy_engine.py` (evaluator), `src/fwd/infra/rate_repo.py` (rate_buckets + wallet_buckets + the `delete_stale` substrate), Alembic 0005, and the release-on-failure cleanup helpers. (Admin-endpoint policy_path validation was originally slotted here but shipped at **v0.5.0a7** — see the a7 bullet.)
- **v0.5.0a6 (integration ship)** wires the engine into `app/sign_and_send.py`; existing tests that exercise sign-and-send WITHOUT a `policy.yaml` will need a test fixture. Test-fixture cost is a known one-time tax.
- **v0.5.0a7 (admin-audit + idempotency ship)** lands admin-endpoint policy_path validation (`POST /v1/admin/{callers,wallets}`), the `Idempotency-Key` replay path in `app/sign_and_send.py` (cached `tx_id`, no re-gate / no re-nonce / no re-rate, `sign-and-send-duplicate` audit row), `AdminScope`/`AdminScopeCM`, audit authorship threaded keyword-only through the four admin use cases, and the `delete_stale` policy-load prune.
- **Pre-Phase-7 callers** (the four already in the DB) MUST be reconciled before v0.5.0 GA: either revoked or paired with a `policy_path` that exists in the new `policy.yaml`. Operator-driven during Phase 7 GA. The active `phase5-gate-caller` (sole non-revoked entry at v0.5.0a1 ship time) is the only one requiring an operator decision; the three revoked entries are inert (the startup fail-fast scan is `revoked_at IS NULL` only).

**When to revisit.**

- **Sliding-window rate limit becomes necessary** (a real caller hits the UTC-boundary burst trap and it matters). Phase 10 swap; the `rate_buckets` table can be redesigned independently.
- **Hot-reload is requested by an operator** (frequent policy churn during a migration). Phase 10 SIGHUP handler; same Pydantic schema; same evaluation algorithm.

## D15. ABI intent decoder shape and ABI registry

**Decision.** Phase 7 ships a pure-function intent decoder: `decode_intent(contract: str, calldata: bytes, abi_fn_entry: dict[str, Any]) -> DecodedIntent | None` (shipped v0.5.0a3; the third parameter is the resolved ABI function entry — the policy engine performs `request.to → abi_name → registry.lookup(abi_name, selector) → abi_fn_entry` and hands the entry in, keeping the decoder pure and registry-agnostic). The decoder is foundational — without typed argument extraction, the policy engine can only check 4-byte selectors, which is far weaker than the "sign intent, never opaque bytes" promise of Core invariant #3.

- **Library.** `eth_abi` (pure Python, narrow API surface). At v0.5.0a3 it was promoted from a transitive of `eth-account`/`eth-utils` to an **explicit direct dependency** (`eth-abi = "^5.0"` in `[tool.poetry.dependencies]`): zero lockfile-graph change (5.2.0 was already installed transitively), but a direct import on a transitive-only dep on the custody path is a supply-chain-legibility defect. "No new top-level dep" (the original a1 framing) referred to the lockfile graph, which is unchanged; the explicit edge is correctness, not new surface. Used for: (a) computing the 4-byte function selector from a signature (`eth_utils.function_abi_to_4byte_selector`), (b) decoding the calldata's argument tuple against the function's argument types (`eth_abi.decode` — a complete codec that handles nested tuples/arrays).

- **`DecodedIntent` dataclass** (in `src/fwd/domain/intent.py`):

  ```python
  @dataclass(frozen=True)
  class DecodedIntent:
      contract: str               # lowercased 0x-hex address (NOT checksummed — see Hazard #1)
      method_signature: str       # canonical, e.g. "claim(address,address,uint24,bool,(bytes32[],(uint24,bytes20,uint120,uint8))[])"
      selector: str               # "0x" + 8 lowercase hex (first 4 bytes of keccak256(method_signature))
      args: dict[str, Any]        # ONLY predicatable-scalar top-level args (B1 projection — see Type handling)
  ```

  Returns `None` (NOT raises) on any decode **failure** (truncated calldata, selector mismatch, codec error). It does NOT return `None` merely because a non-scalar top-level arg is present — see the B1 projection rule under Type handling. Caller (the policy engine) treats `None` as default-deny.

- **ABI registry.** **In-repo `config/abis/`** (operator decision at v0.5.0a1: ABIs are public contract metadata, not secrets — committing matches the open-source spirit of the project and is consistent with the FTSO RewardManager and apregister contracts both being public on-chain). Layout:

  ```
  config/abis/
    registry.yaml              # name → file mapping
    reward_manager.json        # Flare FTSO RewardManager (mainnet + Coston2-equivalent)
    participant_register.json  # apregister Coston2 (0x09f15b14D16BA645661c576348E4d4C201242bF2)
    erc20.json                 # canonical ERC-20 (transfer, approve)
  ```

  ```yaml
  # config/abis/registry.yaml
  version: 1
  abis:
    reward_manager: reward_manager.json
    participant_register: participant_register.json
    erc20: erc20.json
  ```

  Loaded once at startup into an in-process index **keyed `(abi_name, selector_hex)`** (`dict[abi_name, dict[selector_hex, AbiMethod]]`). The registry is **address-agnostic** — it has no knowledge of contract addresses, because the same ERC-20 ABI serves arbitrarily many token addresses and `reward_manager` serves both Flare and Coston2 deployments at different addresses. The `request.to → abi_name` binding lives in `policy.yaml` (`permissions.<path>.contracts.<address>.abi`, D14, operator-controlled, gitignored); the policy engine composes `address → abi_name → registry.lookup(abi_name, selector)`. (Corrected at v0.5.0a3 — the a1 phrasing "keyed by (contract_address, selector)" was physically impossible.) Only state-changing functions (`stateMutability in {nonpayable, payable}`) are indexed; `view`/`pure` cannot be the target of `sign-and-send`. Reload requires fwd restart (same as policy).

- **v0.5.0 scope.** Three ABIs only: FTSO RewardManager (unblocks Phase 8 production migration), ParticipantRegister (unblocks Phase 9 apregister migration), ERC-20 (any future token-holding wallet). Adding a fourth ABI is a one-file PR — not a doctrine change.

- **Type handling at v0.5.0.** Expanded at v0.5.0a2 self-review to cover the ParticipantRegister ABI shape (which uses `string` fields for registration metadata — the original a1 scope excluded `string` and thereby contradicted shipping the participant_register ABI).
  - `address`: decoded as bytes, normalized to lowercase 0x-hex; arg_predicate comparison is case-insensitive.
  - `uint*` (uint8 through uint256): decoded as Python int; the arg_predicate value is **coerced at evaluation time** (`int(str(pval))`) against the decoded arg's Python type, NOT at policy-load time — `policy.yaml` carries no ABI types, so `MethodRule.arg_predicates` is `dict[str, Any]` of raw YAML scalars and the engine learns the target type only from the decoded arg. Python int's arbitrary precision handles uint256 cleanly. (Refined at v0.5.0a4 — the a1/a2 "parsed at policy-load time" phrasing was Core-invariant-#18 drift: `domain/policy.py` does no type parsing; `app/policy_engine.py` step 6 coerces at eval time.)
  - `int*` (int8 through int256): decoded as Python int (signed); same eval-time coercion as uint* — eth_abi handles the two's-complement decoding.
  - `bool`: decoded as bool.
  - `bytes32` (and any other fixed-size `bytesN` for N ≤ 32): decoded as 0x-hex string.
  - `bytes` (dynamic): decoded as 0x-hex string of the raw bytes; arg_predicate compares as case-insensitive hex.
  - `string` (dynamic): decoded as Python str (UTF-8 from the codec); arg_predicate compares as exact UTF-8 string equality. Empty string is a valid value (NOT a wildcard); use the `any` sentinel for "match anything".
  - **B1 projection rule (corrected at v0.5.0a3 — the a1 "decoder returns None" framing was a doctrine contradiction that would have blocked Phase 8).** Top-level arguments whose ABI type is outside the predicatable-scalar set above — dynamic arrays, fixed-size arrays, tuples, structs, function pointers — are **decoded by `eth_abi` (a complete codec) but OMITTED from `DecodedIntent.args`**. They remain fully visible in `method_signature` (the canonical type tuple, e.g. FTSO `claim`'s `(bytes32[],(uint24,bytes20,uint120,uint8))[]`). The decoder returns `None` ONLY on decode failure, never merely because such an arg is present. Consequence: a policy author cannot write an `arg_predicate` against a non-scalar arg (correct — nobody predicates merkle-proof internals); they allowlist the method by its full signature and bound it with `max_value_wei` + rate. This is exactly what the FTSO `claim`/`autoClaim` proof arrays and `autoClaim`'s `address[]` require — the four custody-relevant scalars (`_rewardOwner`, `_recipient`, `_rewardEpochId`, `_wrap`) ARE projected and predicatable; the proof array is not. The signable methods of the three v0.5.0 ABIs are therefore all decodable; the assertion that these ABIs "do not use unsupported types" was false at the ABI level (their `view` methods and FTSO proof arrays use tuples/arrays) and is replaced by: the **signable** methods are all decodable, with non-scalar args projected out per B1, not cause for `None`.

- **Selector collision handling.** Two different methods CAN share a 4-byte selector (cryptographic accident). Policy.yaml indexes by FULL signature; the decoder picks the matching signature from the ABI by argument-type compatibility. If a collision occurs WITHIN one ABI (vanishingly rare in practice), startup fail-fast logs the collision and refuses to load.

- **Hazards.** Three documented patterns:
  1. **Address representation (corrected at v0.5.0a3 — the a1 prescription was factually wrong for the installed library).** The a1 doctrine claimed `eth_abi` returns 32-byte left-padded addresses requiring a strip-to-20-and-lowercase step. **`eth_abi` 5.x returns the `address` type already as a lowercase `0x`-hex `str`** — implementing the prescribed strip would double-process a `str` and break. The decoder passes `address` through unchanged; `_normalize` only converts `bytes`/`bytesN` → `"0x"+hex`. `tests/unit/test_intent.py::test_erc20_transfer_address_already_lowercase_from_eth_abi` asserts the library invariant so a future `eth_abi` major that regresses it is caught.
  2. **Integer overflow.** Python int has arbitrary precision; uint256/int256 decode cleanly (signed via two-complement). No overflow risk at v1.
  3. **Method-name vs signature mismatch.** Policy.yaml MUST use full canonical signatures (`claim(address,address,uint24,bool,(bytes32[],(uint24,bytes20,uint120,uint8))[])`), not bare names (`claim`). Startup validation rejects bare names with a clear error.

**Alternatives considered.**

- **`web3.py`** for ABI handling. Rejected: large dep tree (~30 transitive deps), much of which `fwd` doesn't need. `eth_abi` is the focused subset.
- **Roll our own decoder** using `eth-utils` keccak + manual ABI parsing. Rejected: ABI decoding has well-known edge cases (dynamic types, structs, tuples) and reinventing the wheel is high-bug-density work for a security-critical path.
- **Operator-mounted ABIs** (env-var path or volume bind). Rejected at operator decision time: ABIs are public; bake-time pinning is an integrity gain; restore is simpler.
- **On-chain ABI fetch** at startup from a block explorer. Rejected: explorer availability becomes a fwd-startup dependency; an explorer compromise becomes a fwd compromise vector. Not a fit for default-deny custody doctrine.

**Why this matters.** A decoder that returns `None` on any failure is the simplest expression of Core invariant #3 ("Sign intent, never opaque bytes"). If we can't tell the operator-in-policy what's about to be signed in human-readable terms, we refuse. This shape is verified by the v0.5.0a5 synthetic-attack test.

**Consequences.**

- **v0.5.0a2** lands the decoder, ABI registry loader, and three ABI JSONs in `config/abis/`. No integration with sign-and-send yet (a5 wires it in).
- **The ABI files at `config/abis/*.json` are public** — committed to the repo. Anyone reading the repo learns which contracts fwd is wired to sign for; that's a custody-doctrine win, not a leak.
- **Adding a new contract to AP's signing surface** is a 4-step PR: add the ABI JSON, add the registry.yaml entry, add the permission block to operator's policy.yaml, restart fwd. No code changes.

**When to revisit.**

- **A signing target uses dynamic types** (structs, dynamic bytes). Extend the decoder type handling; add unit tests; ship as a Phase 7 follow-up.
- **A signing target's ABI is not publicly published** (rare for the Flare ecosystem). Operator-mounted ABI fallback added as a Phase 10 enhancement.

## D16. Audit log hash-chain scheme

**Decision.** Phase 7 wires the audit log writes into every `sign-and-send`, `admin/wallets/*`, and `admin/callers/*` endpoint. The `audit_log` table already exists (Alembic 0004 at v0.4.0a3); this doctrine locks down the hash-chain mechanics that the writer enforces and the walker verifies.

- **Hash function.** **SHA-256** (`hashlib.sha256`) — NIST standard, no new dependencies, deterministic across platforms. BLAKE3 considered for speed but rejected at v0.5.0a1: adds a binary-wheel dependency, doesn't materially change the workload (audit chain verify on 1M rows is seconds with SHA-256).

- **Row schema** (already in place; no migration needed):

  ```sql
  CREATE TABLE audit_log (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      caller TEXT,                          -- NULL for admin (FWD_ADMIN_KEY) actions
      action TEXT NOT NULL,                 -- enum below
      request_json TEXT,                    -- canonical sorted-key compact JSON
      decision TEXT NOT NULL,               -- 'approved' | 'denied' | 'error'
      decision_reason TEXT,                 -- human-readable, e.g. "policy_denied: max_value_wei exceeded"
      outcome TEXT,                         -- canonical sorted-key compact JSON (tx_id, error code, etc.)
      prev_hash TEXT NOT NULL,              -- hex SHA-256 of preceding row's row_hash; genesis = '0' * 64
      row_hash TEXT NOT NULL                -- hex SHA-256 of canonical concatenation (below)
  );
  ```

- **`action` enum** (locked at v0.5.0a1; extensions add new values, never repurpose existing):
  - `sign-and-send` — `/v1/sign-and-send` calls (one row per call; the decoded intent + policy decision details land in `request_json` + `decision_reason`)
  - `sign-and-send-duplicate` — idempotency replay returning prior tx_id (per D14 idempotency replay clause; outcome carries `{"original_tx_id", "original_audit_seq"}`)
  - `wallet-create`, `wallet-import` — admin wallet provisioning
  - `caller-create`, `caller-revoke` — admin caller management
  - `policy-load` — fwd lifespan startup (content spec below)
  - `audit-verify-failure` (reserved; emitted by the chain-walker CLI when it discovers a break, written via a privileged code path). **Status (Core invariant #18):** the enum value is accepted by `AuditRepo.append` as of v0.5.0a5, but the v0.5.0a5 walker does NOT write it — `clifwd audit verify` returns a `VerifyResult` and exits 2 on a break, it does not mutate the chain. The privileged self-writing-on-detected-break path is **deferred to v0.5.0a7 (or Phase 10)** — v0.5.0a6 was scoped to the sign-and-send core integration only (the split) and did not touch it; writing a row into a chain that is already known-broken needs its own anchoring design and is not required for v1 tamper-evidence.

- **`request_json` canonicalization.** Before insert: `json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`. Deterministic — same input always produces same bytes — which is what makes the hash-chain meaningful across observers. Same canonicalization applies to `outcome`.

- **Hash input** (revised at v0.5.0a2 self-review). The original a1 doctrine used a NUL-byte-joined concatenation, which is collision-resistant only when none of the contributing fields contain a literal NUL — a property NOT guaranteed for free-form fields like `caller` (caller name, set by admin) or `decision_reason` (human-readable). The fix is to canonical-JSON-serialize the row's logical fields and hash the serialization, eliminating the NUL ambiguity by construction (the JSON encoder escapes embedded NUL bytes as `\u0000`):

  ```python
  row_dict = {
      "prev_hash": prev_hash,                 # 64-char hex string
      "ts": ts.isoformat(timespec="microseconds"),
      "caller": caller,                        # str or None
      "action": action,                        # str (enum value)
      "request_json": request_json,            # str (already canonical) or None
      "decision": decision,                    # 'approved' | 'denied' | 'error'
      "decision_reason": decision_reason,      # str or None
      "outcome": outcome,                      # str (already canonical) or None
  }
  canonical = json.dumps(row_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
  row_hash = sha256(canonical.encode('utf-8')).hexdigest()
  ```

  Same canonicalization rule as `request_json` and `outcome` themselves — one rule, applied uniformly. `row_hash` is always 64 hex chars.

- **Genesis row.** First row's `prev_hash = '0' * 64`. The first audit-log write of any fwd instance's lifetime uses this sentinel. Subsequent rows reference the prior row's `row_hash`.

- **Concurrency.** Writes happen INSIDE the request's RequestScope session (v0.4.5 pattern). One writer-lock acquisition per request covers: nonce reservation + transaction INSERT + audit_log INSERT + rate-bucket increment. Estimated lock-holding-time delta per request from audit + rate writes: ~5–10 ms on top of the existing ~1 s (Vault decrypt + RPC). Within the 30 s busy_timeout headroom; no lock-split refactor needed for v1. Phase 10 may revisit if production contention surfaces.

- **Forensic-row durability (added v0.5.4; Core invariant #19).** A `denied`/`error`/aborted audit row MUST be committed independently of the transaction the failure rolls back. Forbidden anti-pattern: append on the shared `RequestScope`/`AdminScope` session, then `raise`, so the exception unwinds `fwd.infra.db.session_scope` (`except Exception: rollback`) and discards the row. `fwd` commits-before-raise on the **single shared session** — `AuditRepo.commit()` in `app/sign_and_send.py`'s three exception arms; `session.commit()` before `SystemExit(1)` in `main.py::_startup_policy_load` — NOT a second `session_scope` (that re-introduces the v0.4.5 two-session `BEGIN IMMEDIATE` deadlock). The approved/duplicate paths are unaffected (no exception → `session_scope` commits once → D16 atomicity of the approved row with nonce+tx+rate preserved). The commit also yields the doctrinally-correct *operational* end-state per failure path: a step-8/9 deny keeps its D14 rate increment (the attempt is counted; deny does not call `release_rate_after_failure`); a pre-broadcast failure's explicit `release_if_unused` + `release_rate_after_failure` run before the commit so the net is zero; a broadcast failure keeps the reserved nonce (the tx may be in mempools — the receipt watcher decides). **Mandatory enforcement:** a regression test driving the *real* `session_scope` rollback with a self-validating without-commit control. A mocked session is structurally blind to this — which is exactly why the defect shipped at v0.5.0a6 (`main.py`), was point-fixed during the a7 Reviewer pass, **recurred at v0.5.2 (`sign_and_send.py`)**, and was caught only by the Phase 7 GA live drill (Core invariant #14). Loss of these rows is a silent, total Core-invariant-#5 failure for precisely the events — refusals and failures — that most need a forensic record.

- **Substrate vs integration split (Core invariant #18; cadence settled).** The audit-log **substrate** — `infra/audit_repo.py` (`AuditRepo.append/get/tail/verify`, `_canonical_json`, `_row_hash`, `GENESIS_PREV_HASH`, `_as_utc`), `app/audit_walk.py`, the `clifwd audit` CLI, the `AuditRepoCM` dependency — shipped at **v0.5.0a5**. The **integration** — threading `AuditRepo` into each use case so rows are actually written — is split (operator-gated at the a6 Phase-0): **sign-and-send authorship shipped v0.5.0a6** (`app/sign_and_send.py` writes `sign-and-send` rows for denied/error/approved via the shared `RequestScope` session — atomic with nonce+tx+rate; `app/policy_gate.py` is the gate seam; the Coston2 authZ allowlist was lifted, policy.yaml is now the sole authorization, default-deny enforced live). **Admin-action authorship + `AdminScope` + idempotency-replay + `sign-and-send-duplicate` shipped v0.5.0a7** (`AdminScope`/`AdminScopeCM` in `app/dependencies.py`; a keyword-only `audit_repo` threaded through `wallet_create`/`wallet_import`/`caller_create`/`caller_revoke` — exactly one row per call, success OR known-failure, on the shared admin session so it commits atomically with the mutation; the replay branch at the top of `sign_and_send` returns the cached `tx_id`/seq-1 hash and writes a `sign-and-send-duplicate` row WITHOUT re-gating, reserving a nonce, or touching rate buckets). The bullets below: the `sign-and-send` row is a6-shipped; the `wallet-*`/`caller-*` rows + `AdminScope` are a7-shipped — both markers retired. The chain-walker **self-write-on-break (`audit-verify-failure`) remains Phase 10** (it depends on the on-chain anchor that closes the tamper-evidence recursion — see "Tamper evidence" below); v0.5.0's tamper-evidence is the operator-run `clifwd audit verify` (a5).

- **Audit-row authorship** (added at v0.5.0a2 self-review; integration lands v0.5.0a6). One audit row per request/operation, written by the use case at the end of the operation (success or failure):
  - `app/sign_and_send.py` writes the `sign-and-send` row (`decision` ∈ `approved`/`denied`/`error`) — **shipped v0.5.0a6**. `sign-and-send-duplicate` (idempotency replay) **shipped v0.5.0a7**. v0.5.0a6 also **unified** `sign_and_send.py`'s `request_json` builder onto `audit_repo._canonical_json` (it previously used `json.dumps({...}, sort_keys=True)` WITHOUT D16's `separators=(",", ":")` / `ensure_ascii=False`, since v0.4.0a3 — not a chain-break risk since the chain hashes the stored string verbatim, but a D16-conformance drift now resolved: the tx-row `request_json` and the audit-row `request_json` share the one canonical serializer).
  - `app/wallet_create.py` writes `wallet-create`; `app/wallet_import.py` writes `wallet-import`
  - `app/caller_create.py` writes `caller-create`; `app/caller_revoke.py` writes `caller-revoke` (**shipped v0.5.0a7** — these were already app-layer use cases since Phase 4, NOT inline in `api/callers.py`; the earlier parenthetical was a doctrine error corrected here per Core invariant #18. a7 threaded a keyword-only `audit_repo` through both; the api handlers now invoke them inside `AdminScopeCM`)
  - `src/fwd/main.py::_startup_policy_load` writes the `policy-load` row at lifespan startup, before the first request handler binds

  The sign-and-send use case receives the `AuditRepo` via `RequestScope` (shipped a6 — `RequestScopeCM` builds `audit_repo` + `rate_repo` + `wallet_repo` on the one shared session); admin actions get a dedicated `AdminScope` context manager (**shipped v0.5.0a7** — `AdminScopeCM` opens Vault + one `session_scope`, builds signer + caller_repo + audit_repo on that shared session; no RpcManager, since admin actions never touch chain). The audit write happens INSIDE the same writer-lock acquisition as the operation's other DB mutations — atomicity: nonce + tx row + rate buckets + audit row all commit together or all roll back (verified a6: `RequestScopeCM` shares one `session_scope`, one `BEGIN IMMEDIATE`).

- **`policy-load` event content** (added at v0.5.0a2 self-review). The fwd-startup policy-load row uses:
  - `caller = NULL` (no caller; lifespan event)
  - `request_json = NULL` (no request)
  - `decision = "approved"` on successful load; `"error"` on validation failure (after which fwd exits non-zero, the row remains as evidence)
  - `decision_reason` carries a short summary (`"policy loaded: N callers, M permissions, K wallet_constraints, L abis"`) or the error message
  - `outcome` is canonical JSON of: `{"policy_yaml_path": "<path>", "policy_yaml_sha256": "<64-char-hex>", "callers_count": <int>, "permissions_count": <int>, "wallet_constraints_count": <int>, "abis_loaded": ["reward_manager", ...], "fwd_version": "<version>"}`
  - One row per lifespan startup; `clifwd audit show <seq>` against the policy-load rows reconstructs the policy-hash timeline across restarts (useful for forensics: "which policy was in effect when tx X was signed?")

- **Walker CLI.** New `clifwd audit` subcommand group, **shipped at v0.5.0a5** (`cli/audit.py` → `app/audit_walk.py` → `infra/audit_repo.py`; the CLI is cli-layer and reaches the repo through the app-layer walker, since `cli → {app, domain}` forbids a direct infra import):
  - `clifwd audit verify [--from <seq>] [--to <seq>]` — walks the chain in `seq` order. For each row it (a) checks the stored `prev_hash` equals the expected predecessor hash (genesis `'0'*64` for the table-minimum row, else the prior row's stored `row_hash`; a windowed walk anchors on the row at `from_seq - 1` and reports a break if that anchor row is absent) and (b) recomputes `row_hash` (using `_as_utc(row.ts)` so the SQLite tz-drop round-trip is symmetric) and compares to the stored value. Exits 0 if the walked range is intact; exits 2 (stderr `CHAIN BROKEN at seq=<n>`) at the first linkage- or recompute-mismatch.
  - `clifwd audit show <seq>` — pretty-prints one row, decoding `request_json`/`outcome` JSON when parseable; exits 1 if no row at `seq`.
  - `clifwd audit tail [-n N]` — last N rows (default 20), one tab-separated line per row, ascending `seq`.

- **Walker CLI access pattern** (added at v0.5.0a2 self-review). The canonical invocation runs INSIDE the fwd container via `docker exec`, accessing `/data/state.db` through SQLite's read-only mode. No admin auth, no HTTP path:

  ```sh
  docker exec fwd clifwd audit verify
  docker exec fwd clifwd audit show 42
  docker exec fwd clifwd audit tail -n 20
  ```

  Forensic-scenario fallback (fwd is unhealthy or stopped): mount `fwd_fwd-state` in a throwaway container and read state.db directly:

  ```sh
  docker run --rm -v fwd_fwd-state:/data registry.gitlab.com/proofs.africa/fwd/fwd:dev \
      clifwd audit verify
  ```

  Matches the operator's existing access patterns (`docker exec fwd-vault ...` for Vault, `docker run -v fwd_backup:/b ...` for backup inspection). No host-side SQLite client required.

- **Backfill.** **No backfill** of pre-Phase-7 entities. The audit_log table contains zero rows pre-v0.5.0; the first write is `action=policy-load` on fwd's first v0.5.0a6+ startup; subsequent rows are post-startup events only. Pre-existing wallets, callers, and transactions have no audit history; that's an honest limitation, not a bug.

- **Tamper evidence vs tamper prevention.** The hash-chain is tamper-EVIDENT — an attacker with write access to SQLite CAN modify any row and recompute hashes forward, but they cannot do so without leaving evidence in the row_hash of any prior row anchored elsewhere (Phase 10 on-chain anchor closes this). At v0.5.0, the only anchor is `clifwd audit verify` snapshots captured by the operator out-of-band. Phase 10 deliverable: weekly Merkle root commit to Flare via fwd itself, breaking the recursion.

**Why this matters.** Audit is the visible accountability layer. fwd's whole value proposition rests on "every signature is recorded, every record is hashed, every chain is walkable." Without this doctrine, the audit log is just a log file — slightly worse than what `.env PRIVATE_KEY=` already provided (which had its own structured logging at least). Hash-chained audit is the differentiator.

**Consequences.**

- **v0.5.0a5** lands `src/fwd/infra/audit_repo.py` + `src/fwd/cli/audit.py`. Pure-substrate; no integration.
- **v0.5.0a6** wires the `/v1/sign-and-send` audit write — exactly one audit_log row per call (denied/error/approved).
- **v0.5.0a7** wires the admin-endpoint audit writes — one row per `wallet-create` / `wallet-import` / `caller-create` / `caller-revoke`, plus `sign-and-send-duplicate` for idempotency replay.
- **A `docker exec fwd clifwd audit verify` invocation against the live SQLite** is part of the v0.5.0 GA verification gate.

**When to revisit.**

- **A real consumer demands tamper-PROOF audit** (e.g., regulatory). Phase 10 on-chain anchor lands.
- **Audit log writes become a measurable contention point** (production migration hits a workload mix that surfaces it). Lock-split the audit write out of the request's writer-lock critical section. Phase 10.

## D17. Doctrine ship-types: feature, constitutional-amendment, bounded post-verification reconciliation

**Decision.** The per-ship doctrine-surface rule (CLAUDE.md § Linear-forward versioning, instituted v1.0.0) caps a ship at three doctrine artifacts and obligates the Reviewer to reject more. That cap is correct for **feature ships** and is the corpus-bloat remedy the fourth audit demanded. It is structurally unable to govern two legitimate non-feature acts: (a) amending the constitution itself, and (b) reconciling invariant *text* to code a prior byte-verified ship already made true. Forcing either through the 3-artifact cap either blocks it or fragments it across feature ships — and a fragmented reconciliation leaves Core-#18 partially-true doctrine states on `main`. Operator-authorized 2026-05-19 (the single constitutional item gated by the v3 FSP plan), this decision adds two named, bounded non-feature ship-types:

- **Constitutional-amendment ship** — amends CLAUDE.md process/invariant doctrine. Bounded surface: amended CLAUDE.md section(s) + a D-record + the three feature-ship artifacts + the two version files. Self-ratifying (governed by the definition it introduces; the self-reference recorded honestly here per Core invariant #18). Never a Reviewer self-grant — explicit operator authorization is constitutive. **v1.1.0a3 is the genesis instance** (it enacts this very D-record).
- **Bounded post-verification reconciliation ship** — reconciles invariant text to a *prior, already-shipped, byte/GATE-verified* ship's code. Binding constraints: (i) only text the just-shipped verified code makes true, nothing GATE-pending; (ii) every reconciled edit annotated inline `(code in ship vX.Y.ZaN makes this true)`; (iii) NO § Scope narrative paragraph; (iv) ONE coherent ship, never fragmented. Bounded surface: reconciled invariant lines (CLAUDE.md / decisions.md / architecture.md / threat-model.md) + a D-record + the three feature-ship artifacts + the two version files. Cannot ship until the reconciled code's verification gate has passed. Reusable for 9a-iii, 9b, 9c, 10x.

Neither type relaxes Core invariant #18 — each *narrows* it by forcing reconciliation into one annotated, operator-visible, gate-anchored ship instead of leaking partial truth across feature ships.

**Why this matters.** Without this, the FSP doctrine reconciliation (Core #3 EIP-191 reframe, #7 honest hot-`.env` carve-out, #17 honest hot-key text, CLAUDE.md:49 clarifying note) had no compliant home: it exceeds three artifacts by construction, and a per-ship operator "checkbox" does not amend a rule — only a recorded constitutional act does. The rule that exists to prevent doctrine bloat must not, by its own rigidity, force doctrine *dishonesty* (partial-truth fragments on main). Naming the ship-types makes the seam explicit and reusable for every future Step-0/GATE-verified phase.

**Consequences.**

- **v1.1.0a3** (this ship) enacts the amendment: CLAUDE.md § Linear-forward versioning gains the two ship-type definitions; the Reviewer-obligations bullet is scoped to feature ships; this D17 lands; § Scope Current line advances; version bumped. Doctrine-only — zero code change; v1.1.0a1/a2 behaviour unaffected; full suite stays 458 passed / 1 skipped.
- **v1.1.0a4** re-sequences the former "9a-iii" reconciliation (the v3 plan named it v1.1.0a3). It is a bounded post-verification reconciliation ship and is **hard-gated on GATE-1 live-Coston2** — it cannot honestly reword Core #3 until the fwd-reconstructed EIP-191 digest is proven real on-chain against the real `FlareSystemsManager` + a real-`signing-tool`-binary signature diff.
- 9b / 9c / 10x reuse both ship-types without re-authorization (the constitutional act is generic; only a *new* constitutional change needs a new operator authorization + D-record).

**When to revisit.** If a future audit finds either bounded surface is itself a bloat vector (e.g. reconciliation ships growing speculative text despite constraint (i)), tighten the constraint and record the tightening as its own constitutional-amendment ship — the mechanism is now self-hosting.

## D18. Hand-off delivery: the canonical-prompt file is embedded in the message, not pointed at

**Decision.** Operator directive (explicit, 2026-05-19, clarified after two misdeliveries): every Reviewer→implementer / Reviewer→peer-agent hand-off is delivered as exactly ONE self-contained markdown file whose entire contents are the ready-to-paste message to the recipient — a 2–4 line framing preamble at the top (recipient; "the rest of this file is the authoritative spec"; operating boundary; a "Begin" line) followed by the full spec body. The Reviewer hands the operator only the file path; the operator opens it, selects all, pastes — one action. Supersedes the prior § Development workflow wrapper rule ("the wrapper points Sonnet at the canonical prompt file rather than dumping the prompt contents into chat").

**Why this matters.** Three delivery forms were tried 2026-05-19; the first two failed in practice. (a) Pointer-only message (names the path, recipient opens it): fragile — it assumed the operator placed the file where the recipient expected (the clif FSP hand-off told the agent to read a file "in your working directory"). (b) Message dumped inline into the chat reply inside a fence: forced the operator to manually select it out of surrounding Reviewer prose — explicitly rejected. (c) The form that holds: the hand-off IS one file; the only thing handed over is its path; open → select-all → paste. The original anti-dump rationale (a long Reviewer-internal doc whose asides could be mis-read) is already neutralised by the standing self-contained-prompt requirement (root constitution). One file, one paste, zero extraction, zero file-placement dependency.

**Consequences.**

- **v1.1.0a4** (this ship — a constitutional-amendment ship per D17) amends § Development workflow accordingly; this D18 lands; § Scope current line advances; version bumped in both files. Doctrine-only — zero code change; v1.1.0a1/a2 behaviour unaffected; full suite stays 458 passed / 1 skipped.
- The fwd Reviewer regenerates the in-flight clif FSP corrective hand-off in the embedded form immediately.
- The former "9a-iii" bounded reconciliation re-sequences once more (it had been v1.1.0a4) → **v1.1.0a5**, still hard-gated on GATE-1 live Coston2 (linear-forward; the plan is a plan, the version invariant is the rule — same discipline as the v1.1.0a3 re-sequence of it from a3→a4).
- Codified in fwd's CLAUDE.md. Whether to mirror it into the root `proofs.africa/CLAUDE.md` "Sonnet hand-off demarcation (CRITICAL)" section (cross-project binding) is an explicit operator decision — surfaced, not Reviewer-self-taken (scope discipline; the org constitution governs many projects).

**When to revisit.** If a hand-off file ever genuinely cannot be embedded (e.g. exceeds a paste limit), the fallback is a chunked embed with explicit ordered part markers — never a silent return to the pointer-to-file form.

## D19. GATE-1 outcome and the narrowed bounded reconciliation (v1.1.0a5)

**Decision.** v1.1.0a5 ships as a **bounded post-verification reconciliation** (the D17 ship-type, second instance after v1.1.0a3's genesis of the type itself) of the FSP doctrine surface — Core #3, the CLAUDE.md:49 raw-digest note, Core #17 — to the v1.1.0a1/a2 byte-verified FSP code, on the strength of the v1.1.0a4 live-Coston2 drill. Operator-authorized 2026-05-19 ("lets go with your recommendation"), Reviewer-prescribed with the real drill facts in hand (not pre-decided).

**The drill (independently Reviewer-adjudicated — clif self-reports were not the verdict; Core #14).** Full record: `docs/reviews/v1.1.0a4-clif-fsp-live-drill-adjudication.md`.

- **Test A — fee-claimer regression: PASS.** `clif rehearse` real-builder `RewardManager.claim`; chain re-derive: `from`==fwd-custodied executor, `to`==Coston2 RewardManager, selector `0x8e33aba5`, recipient pinned; fwd audit row `sign-and-send approved`. The FSP additions (ABI, FSP policy blocks, migration 0006, address-level segmentation) did not regress the claimer.
- **GATE-1 F1 — CLEARED.** fwd's UPTIME messageHash byte-equals an independent from-scratch recompute of the Step-0 formula AND the frozen Step-0 KAT `0xb7e97e6b…f67d` (key-independent); `fakeVoteHash` byte-equals `0x290decd9…e563`. fwd's preimage builder is byte-correct vs real `signing-tool@838b87f`.
- **B1 — clif↔fwd Leg-1 PASS (protocol-independent).** EIP-191 recovery of fwd's signature == the segmented `clif-fsp-signing-policy` address; clif holds no key.
- **B2(i) — clif↔fwd Leg-2 integration PASS to signed-broadcast.** fwd authenticated, policy-passed, ABI-decoded, segmented-signed and broadcast `signUptimeVote`; the chain rejected solely on the unfunded sender (operator funding wall, a named confound, not a defect). Core #19 forensic-durable `sign-and-send error` row recorded.
- **GATE-1 named residual — substantially closed.** The plan named "on-chain ecrecover + real-binary diff" as the eth-account-EIP-191 ≡ web3-v4-`accounts.sign` arbiter. The live `FlareSystemsManager` (the web3-v4 consumer itself) recovers fwd's eth-account EIP-191 signature successfully (reaches the registry check past recovery; a zero-s contrast proves that point is reached only via successful recovery). The real-binary diff remains belt-and-suspenders, no longer load-bearing.

**Honest deferral — GATE-1 F2 / P3=NO.** Read-only `eth_call signUptimeVote` for ended Coston2 epochs reverts `Error(string) 'invalid signing policy address'` — the FSM recovers fwd's signer but the fresh fwd-generated key is not AP's registered Coston2 signing-policy voter. On-chain FSP-protocol *acceptance* is therefore **not** asserted in doctrine; it is explicitly marked deferred until AP's FSP signing-policy entity is registered on Coston2. This is an on-chain-identity matter, not a clif/fwd defect. D17 constraint (i) — only invariant text the byte-verified code makes true — scopes this honestly: the reconciled text claims the digest is cryptographically real, on-chain-recoverable by the real FSM, and broadcastable (all drill-proven), and stops there.

**Bounded surface (D17 constraints i–iv).** CLAUDE.md Core #3 (EIP-191 reframe), CLAUDE.md:49 (raw-digest note + the v1.1.0a2 "mounts only `/v1/sign-and-send`" drift reconciled), CLAUDE.md Core #17 (FSP hot-key honesty), CLAUDE.md § Scope current line, this D19, `docs/architecture.md` API row, `docs/history/1.1.0a5-*.md` + one README line, the two version files. Bundled (deployed-but-untracked config the v1.1.0a2 code already loads): `config/abis/flare_systems_manager.json` + `config/abis/registry.yaml`; plus the drill adjudication report (the D17(ii) citation source). One stale test-fixture assertion (`tests/unit/test_abi_registry.py` — the ABI-name-set pin) is updated to include `flare_systems_manager`: it should have moved when the FSM ABI was added as the live-drill prerequisite; bundling that config here surfaces and closes it. No `src/` production code is touched (full suite 458 passed / 1 skipped, unchanged). Every doctrine edit annotated inline "code in v1.1.0a1/a2 … makes this true" (constraint ii); no § Scope narrative paragraph (constraint iii); ONE coherent ship (constraint iv). The Core #7 Fast-Updates-VRF carve-out is deliberately **out of scope** (parked 10x; the signing-tool path is keyless-via-fwd and strengthens #7, needing no carve-out) — this is the "narrowing" the P3=NO branch prescribes.

**When to revisit.** When AP registers an FSP signing-policy entity on a target network (Coston2 or, more consequentially, Flare/Songbird mainnet — a separate, larger operator decision): a follow-up bounded reconciliation lands the on-chain-acceptance clause (the F2 text), per the same D17 ship-type, no re-authorization needed.

## D20. Zero egress — fwd is a sign-only signer; clients broadcast (constitutional amendment)

**Decision (operator-directed + operator-authorized 2026-05-27).** fwd makes **no
outbound network connection at all.** It signs ABI-decoded EVM transactions and FSP
messages, allocates nonces, enforces policy, keeps the audit log — but never
broadcasts and never calls an RPC. Each **client** fetches gas/fees, broadcasts the
signed tx, polls the receipt, and reports the outcome back. Shipped a8 (nonce-init)
→ a9 (sign-only excision: `rpc.py`/receipt-watcher/nonce-reconcile/wallet-balances
deleted; `sign_and_send`→`sign_transaction`; `/v1/sign-and-send`→`/v1/sign-transaction`)
→ a10 (report-back) → a11 (network lockdown `internal: true`) → a13
(replacement/reclaim/admin nonce-sync). Proven on real Coston2 (a12 funded drill,
tx `0x14440b…95cbd`, block 31,028,196).

**Constitutional-amendment ship (D17 — operator-authorized, never a Reviewer
self-grant).** Reconciles Core #3 (endpoint rename + no-broadcast clarifier), #4
(local nonce reservation only; client-fed seed/reconcile; no startup RPC reconcile),
#11 (client-triggered replacement; no receipt watcher), #14 (validation boundary →
client↔fwd↔chain integration; a12 = canonical instance), and "What FWD IS NOT"
("Not a broadcaster"; "No network egress at all") to the shipped a9–a13 code. Full
prepared proposal: `docs/zero-egress-D20-amendment-DRAFT.md`.

**Why (the two answers that fixed the shape).** (1) The whole stack must make zero
internet calls — a compromised fwd then has no channel to exfiltrate keys (threat-
model A4 network-exfil channel eliminated). (2) The only RPC is public internet, so
broadcasting cannot stay inside the stack and moves to clients. Nonce *allocation*
stays in fwd (pure-local SQLite reservation), preserving the single-coherence-
boundary property across many clients with zero fwd egress.

**Reclaim mechanic (open question, decided on the operator's behalf):** **same-intent
replacement + operator alarm — never cross-intent auto-reissue.** An orphaned
reservation is re-driven only for its exact recorded intent (`sign-replacement`) or
surfaced as an unresolved hole (`GET /v1/admin/nonce/holes`).

**Rejected alternatives:** a keyless egress *relay* sidecar; a LAN-only network lock
— both moot once "whole-stack zero egress" + "only public internet" were chosen.

**Consumer:** `clif` migrated to the sign-only API (v0.5.5 — signs via fwd,
broadcasts + reports back itself; reward-Merkle root/proof verification); the
epoch-400 Flare/Songbird mainnet drill through migrated clif passed.
**New operational risk:** orphaned nonce reservation; mitigated as above. **Pending:**
the production cutover (live claim/FSP through migrated clif) remains operator-gated.

## D21. Current-state docs describe the present only (Core #18 amended)

**Decision (v1.1.0a22 — operator directive; constitutional-amendment ship).** The current-state docs — `CLAUDE.md`, `README.md`, `architecture.md`, `threat-model.md`, `dependencies.md` — describe the code as it is now, in present tense, with NO archaeology: no "was X / retired / superseded / fixed in vX" annotations, no version-by-version narrative, no references to deprecated or discarded designs. When code changes, the current-state docs are rewritten to the new present (old wording replaced, not annotated-as-superseded). The project's history — evolution, decision rationale, abandoned ideas — lives ONLY in the quarantined record: `docs/history/` (per-version ship narratives + `SHIP-LOG.md`, append-only, Core #13) and this file (`decisions.md`, the append-only decision log).

**What changed.** This amends Core invariant #18, whose prior wording mandated in-place "honest history" annotations in the current-state docs. Over many ships those annotations accreted into archaeology that buried the present — by v1.1.0a21 the `CLAUDE.md` § Scope was a ~1,250-word a8→a21 arrow-chain, and the invariants / architecture / threat-model carried pervasive "Vault retired / was sign-and-send / vestigial" asides. The operator's directive: the docs must reflect the code as it is, not as it used to be.

**Scope (operator-chosen).** Sanitize the current-state docs + remove dead code/config that is no longer part of the project (the retired Vault-snapshot sidecar + scripts, the stale Vault runbooks, the vestigial `replaced` tx status). KEEP the historical-record files (`docs/history/`, `SHIP-LOG.md`, this decision log, `implementation-plan.md`) untouched as the quarantined memory — a reader of the current-state docs never time-travels, but the project's history survives in files that ARE explicitly history.

**Consequences.** Core #18 is the new rule going forward; the per-ship doctrine surface's § Scope artifact is a clean current-state line (no arrow-chain). `SHIP-LOG.md` + `docs/history/` remain append-only (Core #13 unchanged). Audits still catch drift (a current-state claim the code does not do); the fix is to rewrite the doc to the present. Self-ratifying per the constitutional-amendment ship-type (D17): this amendment is governed by the definition it introduces, recorded here honestly.

**When to revisit.** If the quarantine boundary proves wrong (e.g. a current-state doc genuinely needs a historical pointer readers miss), adjust the pointer convention — not by re-admitting inline archaeology.

## Decisions explicitly deferred

These were considered during v0.1.0 design but are intentionally not decided yet — choices are made when the relevant phase lands.

- **Auto-unseal mechanism** (Phase 10): transit-seal via second Vault, or YubiHSM-backed seal. Decide when Phase 10 begins.
- **Hardware-isolated signing** (Phase 10): YubiHSM 2 vs Vault Enterprise vs status-quo soft-Vault. Decide when revenue volume + threat-model evolution justify the hardware spend.
- **Audit-log on-chain anchor** (Phase 10): commit Merkle root weekly to which contract? `ParticipantRegister`-style on Coston2 first; Flare mainnet later.
- **Policy DSL upgrade** (Phase 10+): YAML stays through v1.x. If rules outgrow the schema, evaluate OPA/Rego, a typed Python DSL, or `cel-spec`. Don't pre-decide.
- **mTLS for callers** (Phase 10 trigger): when any caller leaves the host. Format: cert-manager or self-issued.

These deferrals are not avoidance — they are deliberate scope discipline per CLAUDE.md § "What FWD Deliberately IS NOT."
