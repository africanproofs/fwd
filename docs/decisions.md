# Decisions

This document records the architectural decisions made during `fwd`'s v0.1.0 design phase, with alternatives considered and the reasoning behind each. It is not a parallel canon — `architecture.md` is the canonical design — but it preserves the why so future agents can re-litigate any decision deliberately rather than by drift.

Decisions are numbered for reference. Format: **Decision** / **Alternatives considered** / **Why** / **Consequences** / **When to revisit**.

---

## D1. Custody: Vault Transit envelope encryption + in-process secp256k1 signing

**Decision.** AP runs HashiCorp Vault on the same Docker host as `fwd`, with the Transit secrets engine providing one `aes256-gcm96` master key (`exportable=false`). Each wallet's secp256k1 private key is generated externally (secure RNG via `coincurve` or `eth-account.create()`), envelope-encrypted by Vault (`transit/encrypt/fwd-master`), and stored as a `vault:v1:<ciphertext>` blob in SQLite. At signing time, `fwd` calls `transit/decrypt/fwd-master` to recover plaintext, signs the transaction with `eth-account`, and zeroizes the plaintext buffer immediately. Plaintext private keys never persist on disk and exist in `fwd`'s process memory only during the bounded signing operation.

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

**Decision.** `fwd` persists state (nonces, transactions, audit log, callers, wallets) in a single SQLite file in WAL mode, replicated continuously to Scaleway Object Storage by a Litestream sidecar.

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

**Decision.** Generate a fresh secp256k1 key inside Vault during Phase 8. Rotate the on-chain claim recipient via `setClaimRecipient` signed by the identity hardware wallet. Do NOT import the existing `.env`-resident private key.

**Alternatives considered.**
- **Import the existing key** into Vault Transit (Vault supports `wrap`-based key import). Preserves the on-chain configuration. Avoids a rotation transaction.

**Why generate fresh.** Importing preserves convenience but inherits whatever exposure history the existing key has — `.env` files on disk, possibly in shell history, possibly in old git commits, possibly in backup tarballs. We can't audit retroactively. Importing is "stop making it worse"; rotating is "the threat model resets at epoch N, provably." The on-chain rotation cost is one transaction (~$0.10 in FLR gas) plus one hardware-wallet signature ceremony. That's a rounding error against the value protected.

**Consequences.**
- Phase 8 includes a one-time on-chain `setClaimRecipient` transaction.
- The hardware wallet that controls the identity address `0x26534aC74153E3257dDD3471f96faA33D5D3B575` must be available during the cutover. (Identity keys themselves do not migrate to fwd — they stay offline.)
- After rotation, every subsequent claim signed by the new Vault-resident key is cryptographically uncontaminated.
- The procedure becomes a documented runbook (`runbooks/key-rotation.md`) reusable for any future key rotations (compromise response, hardware-wallet upgrade, scheduled hygiene).

**When to revisit.** Per-key, at every migration. Coston2 test wallet (Phase 9) follows the same logic — generate fresh, fund the new address, retire the old. `apcli` and other backends similarly.

---

## D6. Vault unseal: 3-of-5 Shamir, distributed across 5 failure domains

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
- Vault unseal shares (never committed).
- Caller API keys (issued at runtime, stored as argon2id hashes).
- `policy.yaml` *values* for production wallets — values live in a separate private location (private GitLab repo or env-injected on host).
- Litestream credentials, Vault root token, AppRole secret IDs (env-injected).
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

- **Create — HTTP + CLI.** `POST /v1/admin/wallets` (admin-scoped) and `clifwd wallets create` both call the same flow: `fwd` generates a fresh secp256k1 privkey internally via `eth_account.Account.create()`, derives the address, encrypts the privkey via `transit/encrypt/fwd-master`, persists `(name, address, privkey_ciphertext, vault_master_key='fwd-master', policy_path)` in SQLite, and zeroizes the plaintext bytearray. Plaintext privkey never leaves `fwd`'s process; no caller (not even the admin) ever sees it.

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

## Decisions explicitly deferred

These were considered during v0.1.0 design but are intentionally not decided yet — choices are made when the relevant phase lands.

- **Auto-unseal mechanism** (Phase 10): transit-seal via second Vault, or YubiHSM-backed seal. Decide when Phase 10 begins.
- **Hardware-isolated signing** (Phase 10): YubiHSM 2 vs Vault Enterprise vs status-quo soft-Vault. Decide when revenue volume + threat-model evolution justify the hardware spend.
- **Audit-log on-chain anchor** (Phase 10): commit Merkle root weekly to which contract? `ParticipantRegister`-style on Coston2 first; Flare mainnet later.
- **Policy DSL upgrade** (Phase 10+): YAML stays through v1.x. If rules outgrow the schema, evaluate OPA/Rego, a typed Python DSL, or `cel-spec`. Don't pre-decide.
- **mTLS for callers** (Phase 10 trigger): when any caller leaves the host. Format: cert-manager or self-issued.

These deferrals are not avoidance — they are deliberate scope discipline per CLAUDE.md § "What FWD Deliberately IS NOT."
