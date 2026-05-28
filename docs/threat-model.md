# Threat model

This document enumerates the realistic ways `fwd`'s keys could be compromised, with mitigations and residual risk for each path. It is deliberately published with the rest of the architecture — security through obscurity is not part of the model (see `decisions.md` § D7).

## Assets

In order of value and consequence-of-compromise:

| Asset | Held in | Value at risk | Compromise consequence |
|---|---|---|---|
| FTSO claim recipient key (Flare) | Sealed (AES-256-GCM) in SQLite | ~1000 FLR / epoch automation revenue (≈ tens of USD) | Theft of one or more epochs' rewards |
| Songbird claim recipient key | Sealed (AES-256-GCM) in SQLite | Reward-epoch revenue (recurring, smaller) | Same, smaller |
| Coston2 test wallet keys | Sealed (AES-256-GCM) in SQLite | Testnet gas (~negligible) | Test environment disruption |
| Future automation keys (`apcli`, `fics` writes, agent wallets) | Sealed (AES-256-GCM) in SQLite | Per-caller, bounded by policy | Bounded by per-caller policy |
| Sealed master key (AES-256-GCM, seals all wallet keys at rest) | Mode-0600 host file owned by the `fwd` user (v1.0.0a1; no Vault/Shamir — D1) | All keys, all assets | Total loss of `fwd`-managed custody (recovery: regenerate wallets + on-chain `setClaimRecipient` rotation) |
| Audit log integrity | SQLite + Litestream | Forensic / non-repudiation | Loss of "what happened, when" record |

What is NOT held in `fwd`:
- Identity addresses' keys (`0x26534aC74153E3257dDD3471f96faA33D5D3B575` Flare, `0xcf3A...` Songbird) — offline hardware wallet.
- Delegation keys — offline hardware wallet.
- Validator key (`NodeID-FLPF99…`) — never exposed; on-validator-host only.
- User-facing wallet keys (frontend flows) — thirdweb v5, separate concern.

These remain offline by deliberate scope (see `CLAUDE.md` § "What FWD Deliberately IS NOT").

## Attacker model

`fwd`'s threat model assumes the following attacker capabilities, in increasing order of severity:

| Tier | Capability | Realistic? |
|---|---|---|
| 1 | Reads public internet, scans public endpoints | Always |
| 2 | Has compromised one of `fwd`'s caller applications (e.g. `ftso-fee-claimer` container) | Plausible |
| 3 | Has shell on the Docker host (non-root) | Plausible |
| 4 | Has root on the Docker host | Possible — operational hygiene matters |
| 5 | Has physical access to the host | Low (datacenter physical security) |
| 6 | Has compromised khosi's laptop AND hardware GPG key | Low — *retired Vault model (A5–A8); no GPG-encrypted shares exist post-v1.0.0a1* |
| 7 | Has compromised 3 of 5 unseal-share locations | N/A — *retired Vault model (A5–A8); the sealed master has no Shamir shares* |
| 8 | Has broken secp256k1 | Affects all of Ethereum |

`fwd`'s job is to make tier-3 and tier-4 compromise **bounded** rather than catastrophic, and to ensure tiers 5–7 require multiple distinct compromises that cannot be achieved through any single incident.

## Attack paths

### A1. Caller is compromised

**How.** Vulnerability in `ftso-fee-claimer` (or any other caller) lets an attacker execute arbitrary code in the caller's container.

**What the attacker gets.** The caller's `FWD_API_KEY` from its environment. They can submit requests to `fwd`.

**What `fwd` allows them to do.** Only what policy allows that specific caller — for `ftso-fee-claimer`, that's "call `claim` on the FTSO RewardManager, beneficiary = the configured claim recipient, max N times per hour." Nothing else. No other contracts. No other methods. No other arguments.

**Mitigations in place.**
- Default-deny policy (Core invariant #2).
- Intent decoding refuses unparseable calldata (Core invariant #3).
- Rate limits per caller, per window.
- Audit log records every request and decision; abuse becomes immediately visible. (True for *denied/errored* requests — the policy-probing case — only since **v0.5.4 / Core invariant #19**: pre-fix those forensic rows were appended on the request session and then rolled back with the failing transaction, so an attacker probing the policy left no audit trace. Bug fixed v0.5.2, codified as an invariant v0.5.4.)
- API key revocation via admin CLI (no service restart needed).

**Residual risk.** Bounded by policy. Compared to today (compromise = total loss of the `.env` private key), this is a dramatic upgrade.

**Comparison to `.env` baseline.** Today: total loss. After `fwd`: bounded to the policy envelope.

---

### A2. Compromised caller authenticates and waits

**How.** An attacker holds a valid caller API key (per A1) and, instead of immediate abuse, waits to time their requests with legitimate ones (e.g. immediately after a reward epoch boundary).

**What changes vs A1.** Nothing materially — they still operate within policy. But timing-based abuse may evade rate limits set on a "reasonable use" assumption.

**Mitigations.**
- Spend caps independent of rate limits (`max_value_wei`, `daily_value_cap`).
- Recipient pattern locks (`beneficiary` constraint — claim recipient must equal a fixed address).
- For high-value methods: `require_human_approval_above_value_wei` — `fwd` can pause and surface to operator.

**Residual risk.** Same envelope as A1. Operator visibility via audit log + alerts (Phase 10) is the catch.

---

### A3. Host root compromise while fwd is running

**How.** Attacker exploits some unrelated vulnerability on the host, chains to root, and inspects `fwd`'s process memory while it's serving signing requests.

**What the attacker gets.** During the bounded signing operation, `fwd` decrypts a wallet's privkey via the sealed master (AES-256-GCM, v1.0.0a1 — D1; no Vault), holds the 32-byte plaintext briefly to sign with `eth-account`, and zeroizes immediately after (Core invariant #16). An attacker with `ptrace` / `gcore` access who times their dump to coincide with an active signing operation can extract that wallet's plaintext privkey. Between signing operations, no plaintext privkeys are in `fwd`'s memory (decrypt-on-demand, no caching).

**Mitigations in place.**
- Single-purpose host recommendation (no other services running, smallest attack surface).
- `fwd` runs with `mlock`-equivalent memory protection (`IPC_LOCK` capability in compose) so plaintext privkeys are not swapped to disk.
- Decrypt-on-demand (Core invariant #16): plaintext privkeys exist in memory only for microseconds per signing operation.
- Host hardening runbook: minimal package set, SSH key-only, fail2ban, prompt patching.
- Audit-log visibility: `fwd` signs but does not broadcast (zero-egress, D20), so extracted-key abuse surfaces as anomalous `sign-transaction` rows in `fwd`'s hash-chained audit log; `fwd` itself cannot be the broadcast or network-exfil channel (no RPC client, no egress).

**Residual risk.** Real, and a degradation from the originally-intended v0.1.0 design (which was infeasible because Vault Transit doesn't support secp256k1). The exposure window is bounded to active signing operations rather than the full Vault uptime, which is a meaningful improvement over a naive "key in memory all the time" pattern. **This is the biggest residual risk in v1.**

**Mitigation upgrade path.** YubiHSM 2 (Phase 10): keys generated inside the chip, never leave it. Host root can ask the HSM to sign things while they have access, but cannot exfiltrate keys for offline reuse — and signing-rate limits in the HSM cap abuse. See `architecture.md` § "Forward compatibility" — the `Signer` protocol exists specifically for this swap.

**Comparison to `.env` baseline.** Today: trivial — read a file. After `fwd`: requires deep host compromise plus active memory exfiltration timed to a signing operation.

---

### A4. `fwd` process itself is compromised (bug or supply chain)

> **v1.1.0a9/a11 zero-egress update (D20):** the **network-exfil channel is
> eliminated.** fwd now makes no outbound connection (no RPC/`httpx` client in the
> daemon; the `internal: true` compose network gives the container no internet
> route). A compromised `fwd` can still sign with recovered keys *during* the
> compromise (and an attacker with host access could still copy ciphertext +
> master), but it **cannot phone home / exfiltrate keys over the network** from the
> fwd process itself — the "Exfiltrate the plaintext privkeys offline" item below
> now requires separate host-level egress the attacker must obtain elsewhere, not a
> capability fwd hands them. The text below is the pre-egress-removal analysis,
> retained as honest history (Core invariant #18).

**How.** Bug in `fwd`'s policy engine or signing path, or malicious dependency, lets an attacker execute code in the running `fwd` process.

**What the attacker gets.** Under Path 2 (v0.1.2 architecture), this is materially worse than the originally-intended design. A compromised `fwd` can:
- Issue arbitrary `transit/decrypt/fwd-master` calls using its Vault token, recovering ALL wallet privkeys it has ciphertexts for.
- Sign anything the recovered keys can sign — bypassing fwd's own policy engine.
- Exfiltrate the plaintext privkeys offline.

This is the cost of collapsing the Vault/fwd process boundary that v0.1.0 originally specified (and which was infeasible because Vault Transit doesn't support secp256k1).

**Mitigations in place.**
- `fwd`'s code is small, public, and auditable — bugs surface to scrutiny.
- Pinned dependency versions; signed Docker images where available.
- Vault's own audit device logs every `transit/decrypt` operation independently of `fwd`'s audit log — sustained abuse becomes visible in Vault audit even if fwd's audit is corrupted.
- Default-deny policy: a compromised fwd that goes through its own code paths still hits policy checks. (Bypass requires defeating both `fwd`'s engine AND signing path, not just the engine.)
- Decrypt-on-demand (Core invariant #16) limits passive exfiltration to "request a signature, observe the decrypt." Bulk decryption (decrypt all wallets, walk away) is detectable in Vault audit as an anomalous burst.

**Residual risk.** The strongest argument in v1 for the Phase 10 YubiHSM 2 upgrade. Until Phase 10, this is the genuine "fwd compromise = lose all wallets fwd manages" weakness, mitigated only by Vault audit visibility and policy default-deny on the fwd side.

**Comparison to `.env` baseline.** Today: there is no policy enforcement point. After `fwd`: a compromised `fwd` is similarly catastrophic (key exfiltration possible), but the audit trail and Vault-side visibility make abuse detectable in ways `.env` files do not.

---

> **A5–A8 describe the RETIRED Vault custody model (Vault removed at v1.0.0a1 — `decisions.md` D1).** There is no Vault, no AppRole, no Transit, and no 3-of-5 Shamir unseal ceremony in the current system, so **A5–A8 no longer obtain**. They are retained as honest history (Core invariant #18). The live custody attack surface is **A3** (host root) and **A4** (process compromise) against the *sealed local master* — both already framed for the current design above. Recovery for the sealed master is regenerate-wallet + on-chain re-authorization, not a share ceremony.

### A5. Vault is compromised directly (or AppRole credentials leak)

**How.** Vulnerability in Vault itself, or compromise of the AppRole credentials (`FWD_VAULT_ROLE_ID` + `FWD_VAULT_SECRET_ID`) `fwd` uses to authenticate to Vault.

**What the attacker gets.** **Under v0.1.2's envelope-encryption design, this is materially as severe as A4.** The `fwd-app` Vault policy grants `transit/decrypt/fwd-master` (see `config/vault/policies/fwd-app.hcl`). An attacker with `fwd`'s AppRole credentials AND access to the SQLite `wallets.privkey_ciphertext` rows can:
- Authenticate to Vault as `fwd` (legitimately, via AppRole login).
- Issue arbitrary `transit/decrypt/fwd-master` calls, recovering ALL wallet plaintext keys.
- Exfiltrate plaintext privkeys offline.

This was incorrectly described in v0.1.0 as "can sign but cannot extract" — that was true under the originally-intended Vault Transit signing design (Path 1), where Vault held opaque keys and `fwd` only had `transit/sign/*`. Under the v0.1.2 pivot to envelope encryption (Path 2), the attacker has the same decrypt capability `fwd` itself has. With Vault root token they could additionally rotate the master key (which would invalidate every wallet ciphertext) or delete keys; the root token is revoked after init (Phase 3 gate).

**Mitigations in place.**
- Root token revoked after Vault init; ongoing access via scoped policies only.
- Vault listens only on `fwd-internal` Docker network (`internal: true`); not reachable from host or external.
- AppRole credentials live in `.env` (mode 0600, gitignored, populated only on the host running `fwd`).
- Vault's audit device logs every operation; sustained `transit/decrypt` abuse becomes visible in Vault audit independently of `fwd`'s audit log.
- Pinned Vault version; security advisory subscription for HashiCorp Vault.

**Residual risk.** Equivalent to A4 in attacker capability (key extraction possible). Distinct in detection surface: AppRole credential leak without `fwd` process compromise leaves `fwd`'s own audit log unwritten — Vault audit is the only forensic trail. AppRole secret_id rotation runbook lands at Phase 8 (per `decisions.md` D10). Phase 10 YubiHSM 2 closes the extraction path by moving signing into the chip; AppRole compromise then degrades to "abuse signing during access window" rather than "exfiltrate keys."

---

### A6. Host compromise while Vault is sealed (host is offline or restarted)

**How.** Attacker steals the disk image during a maintenance window, or accesses a backup that was taken while Vault was sealed.

**What the attacker gets.** Vault Raft data + SQLite state + Litestream replicas. The Raft data is encrypted with the master key, which exists nowhere on disk — it's reconstructible only from 3 of 5 Shamir shares. SQLite state contains audit log, caller hashes, transaction history. None of it includes signing keys or unseal shares.

**Mitigations.**
- Master key never persists to disk.
- Shamir shares geographically distributed (D6).
- Optional: full-disk encryption (LUKS) on the host adds a second layer; not strictly required because Vault's encryption-at-rest is the primary defense.

**Residual risk.** Very low. Attacker has encrypted gibberish unless they also achieve A7.

---

### A7. Unseal shares are stolen

**How.** Attacker compromises ≥3 of the 5 share locations.

**Storage locations** (per D6):
- Paper #1: primary residence, fire-resistant storage.
- Paper #2: off-site (different city, family member, deposit box).
- GPG #1: GPG-encrypted, in a private GitLab repo accessible only to khosi.
- GPG #2: GPG-encrypted, on khosi's primary laptop.
- GPG #3: GPG-encrypted, on a USB drive at the off-site location.

**Compromise paths to 3 shares:**
- 3 paper shares from 3 different physical locations: there are only 2 paper shares, so impossible.
- 3 GPG shares: requires khosi's GPG private key (on YubiKey, PIN-protected) AND access to 3 of (laptop, GitLab repo, USB).
- 2 paper + 1 GPG: requires both physical locations + GPG key + 1 of 3 digital locations. Practically the easiest path, still hard.

**Critical property.** Even with 3 shares, the attacker needs network access to a running Vault to use them. Shares alone do not produce signatures — they unseal a Vault instance, which then signs only what its policy permits.

**Mitigations.**
- Geographic distribution.
- GPG key on hardware token (YubiKey + PIN).
- Audit + alert on `vault operator unseal` operations from unexpected sources.
- Periodic share-rotation drills (re-Shamir without rekeying — Vault supports this).

**Residual risk.** Very low. Requires sophisticated, multi-step, multi-location attack.

---

### A8. Khosi's GPG key alone is compromised (no physical access)

**How.** Sophisticated attack on khosi's YubiKey + PIN harvesting.

**What the attacker gets.** Ability to decrypt any of the 3 GPG shares — but only if they also exfiltrate the encrypted share files. The shares aren't on the YubiKey; they're separately stored (laptop, GitLab repo, USB).

**Realistic combined paths.**
- GPG key + laptop access: 1 share (GPG #2). Below threshold.
- GPG key + GitLab repo access: 1 share (GPG #1). Below threshold.
- GPG key + 2 of 3 digital locations: 2 shares. Below threshold.
- GPG key + all 3 digital locations: 3 shares — threshold met. Requires distinct compromises across laptop, GitLab, and physical USB at second location.

**Residual risk.** Low. The Shamir distribution means GPG-key-only compromise is below threshold for any 2-location attack.

---

### A9. Physical access to the host

**How.** Datacenter break-in, evil-maid attack, server seizure.

**What the attacker gets (v1.0.0a1 sealed-master model).** A *running* host: same as A4 — plaintext recoverable from `fwd`'s process memory during a signing op. An *offline/stopped* host: the SQLite ciphertexts (`seal:v1:`) AND the mode-0600 `master.key` file — if the attacker reads both, they recover all wallet keys; ciphertexts WITHOUT the master file are useless gibberish. (There is no "sealed Vault" state any more — the sealed master is a plaintext 32-byte file at rest, so disk encryption matters more here than in the Vault era.)

**Mitigations.**
- Datacenter physical security (hosting provider).
- Full-disk encryption on the host (defense in depth — now the primary at-rest protection for the `master.key` file, since there is no Vault encryption-at-rest layer).
- The host is never publicly exposed; `fwd` has no egress (D20).

**Residual risk.** Low for hosted environments. Higher for on-premises or if a host is moved. Proportionate to the asset class (low-value automation keys — see the asset table).

---

### A10. Supply-chain attack

**How.** A malicious Python package update, or a backdoored `eth-account` / `cryptography` release. (The `hashicorp/vault` image is no longer an attack vector — Vault was retired at v1.0.0a1.)

**What the attacker gets.** Whatever the malicious code does — could exfiltrate keys at signing time, modify transaction destinations silently, or open a covert channel.

**Mitigations.**
- All Docker image tags pinned to specific digests in `docker-compose.yml`.
- Python dependencies pinned in `poetry.lock`; no floating versions.
- `fwd`'s own image built from source by AP's CI; not pulled from a registry someone else controls.
- Renovate or Dependabot for proposed updates; updates reviewed before merge.
- `fwd`'s own hash-chained audit log records every signing decision — a supply-chain attack that drives signatures through `fwd`'s code paths still leaves audit traces (and `fwd` has no egress to phone home, D20).

**Residual risk.** Industry-wide problem. Affects all software. Specific mitigations are the standard ones.

---

### A11. Side-channel attacks (Spectre/Meltdown family)

**How.** A separate process on the same host reads `fwd`'s memory (where a wallet key is plaintext during a signing op) via speculative-execution side-channels.

**Mitigations.**
- Single-purpose host: no other services running. No untrusted code shares the kernel.
- Host kernel patched (KPTI, retpoline, etc.).
- Cloud providers (Scaleway) apply mitigations at the hypervisor layer.

**Residual risk.** Low for a single-tenant single-purpose host. Higher in multi-tenant cloud, but `fwd`'s `mlockall` (Core invariant #1) prevents swap-to-disk, not speculative reads.

---

### A12. Cryptographic break of secp256k1

**Out of scope.** Affects all of Bitcoin and Ethereum. Not a `fwd`-specific concern. If secp256k1 is broken, `fwd`'s users have bigger problems than `fwd`.

## Summary table

| Threat | Today (`.env`) | After `fwd` v1 | After `fwd` + YubiHSM 2 |
|---|---|---|---|
| Caller compromise | **Total loss** | Bounded by per-caller policy | Bounded by per-caller policy |
| Host root compromise | Total loss | Plaintext recoverable from `fwd` process memory during a signing op; OR host read of BOTH the `master.key` file AND the SQLite ciphertexts (sealed master, v1.0.0a1 — no AppRole) | Keys cannot be extracted; signing can be abused while attacker has access |
| Disk theft (ciphertext only) | Total loss | SQLite ciphertexts WITHOUT `master.key` = useless gibberish; WITH it = recoverable (full-disk encryption is the at-rest defense) | Encrypted, useless |
| Backup theft | Total loss | Same as disk theft — ciphertext useless without the separately-held `master.key` | Encrypted, useless |
| `fwd` process compromise | N/A | **All wallet keys decryptable in-process via the sealed master (per A4); attacker can sign during the compromise** — `fwd`'s audit log makes signing visible, and zero-egress (D20) denies a network exfil channel | Keys cannot be extracted; signing can be abused while compromise persists |
| ~~AppRole credential leak~~ | — | **N/A — Vault/AppRole retired at v1.0.0a1 (D1).** The custody attack surface is host-root / process compromise above. | — |
| Supply-chain | Total loss | Bounded by `fwd`'s hash-chained audit + zero egress | Same |
| Physical | Total loss | Encrypted at rest; in-memory if running | Keys never in host memory |

## The honest one-line summary

**`fwd` does not make AP's keys unstealable.** It makes them dramatically more expensive to steal, makes every theft attempt visible, and bounds the blast radius of caller compromises to the policy envelope of that caller. Combined with policy-bounded per-caller damage, that is the upgrade. Perfect requires hardware (YubiHSM), which is a Phase 10 option, not a v1 requirement.

## When this document is wrong

This threat model captures what was understood at v0.1.0 design time. It must be updated when:
- A new attack class is discovered or published against any component (Vault, Litestream, Docker, secp256k1, etc.).
- `fwd` adds a new attack surface (a new endpoint, a new caller class, a new chain).
- The custody model changes (Phase 10 HSM upgrade — most threats shift).
- Operator practices change (single-operator → multi-operator, on-prem → cloud, etc.).

Updates are themselves audit-logged: every revision of this document carries a `## Revision history` entry at the bottom (added in v0.2.0 onwards).
