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

## Decisions explicitly deferred

These were considered during v0.1.0 design but are intentionally not decided yet — choices are made when the relevant phase lands.

- **Auto-unseal mechanism** (Phase 10): transit-seal via second Vault, or YubiHSM-backed seal. Decide when Phase 10 begins.
- **Hardware-isolated signing** (Phase 10): YubiHSM 2 vs Vault Enterprise vs status-quo soft-Vault. Decide when revenue volume + threat-model evolution justify the hardware spend.
- **Audit-log on-chain anchor** (Phase 10): commit Merkle root weekly to which contract? `ParticipantRegister`-style on Coston2 first; Flare mainnet later.
- **Policy DSL upgrade** (Phase 10+): YAML stays through v1.x. If rules outgrow the schema, evaluate OPA/Rego, a typed Python DSL, or `cel-spec`. Don't pre-decide.
- **mTLS for callers** (Phase 10 trigger): when any caller leaves the host. Format: cert-manager or self-issued.

These deferrals are not avoidance — they are deliberate scope discipline per CLAUDE.md § "What FWD Deliberately IS NOT."
