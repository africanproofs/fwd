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
| Sealed master key (AES-256-GCM, seals all wallet keys at rest) | Mode-0600 host file owned by the `fwd` user | All keys, all assets | Total loss of `fwd`-managed custody (recovery: regenerate wallets + on-chain `ClaimSetupManager.setClaimExecutors` re-authorization — flagged unverified, see Core #17) |
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
| 6 | Has broken secp256k1 | Affects all of Ethereum |

`fwd`'s job is to make tier-3 and tier-4 compromise **bounded** rather than catastrophic.

## Attack paths

### A1. Caller is compromised

**How.** Vulnerability in `ftso-fee-claimer` (or any other caller) lets an attacker execute arbitrary code in the caller's container.

**What the attacker gets.** The caller's `FWD_API_KEY` from its environment. They can submit requests to `fwd`.

**What `fwd` allows them to do.** Only what policy allows that specific caller — for `ftso-fee-claimer`, that's "call `claim` on the FTSO RewardManager, beneficiary = the configured claim recipient, max N times per hour." Nothing else. No other contracts. No other methods. No other arguments.

**Mitigations in place.**
- Default-deny policy (Core invariant #2).
- Intent decoding refuses unparseable calldata (Core invariant #3).
- Rate limits per caller, per window.
- Audit log records every signing request and decision — including denied/errored requests (the policy-probing case): forensic rows are committed independently of the failing transaction (Core invariant #19), so an attacker probing the policy leaves an audit trace. Abuse through `fwd` becomes immediately visible.
- API key revocation via admin CLI (no service restart needed).

**Residual risk.** Bounded by policy. Compared to today (compromise = total loss of the `.env` private key), this is a dramatic upgrade.

**Comparison to `.env` baseline.** Today: total loss. After `fwd`: bounded to the policy envelope.

---

### A2. Compromised caller authenticates and waits

**How.** An attacker holds a valid caller API key (per A1) and, instead of immediate abuse, waits to time their requests with legitimate ones (e.g. immediately after a reward epoch boundary).

**What changes vs A1.** Nothing materially — they still operate within policy. But timing-based abuse may evade rate limits set on a "reasonable use" assumption.

**Mitigations.**
- Spend caps independent of rate limits: per-method `max_value_wei` and per-wallet `max_aggregate_value_wei_per_day` (the actual policy fields; there is no `daily_value_cap`).
- Recipient pattern locks (`beneficiary` constraint — claim recipient must equal a fixed address).
- (Not implemented) a `require_human_approval_above_value_wei` pause-and-surface gate is a candidate future control, NOT a current policy field — today high-value methods are bounded by `max_value_wei` + the daily aggregate cap + rate limits.

**Residual risk.** Same envelope as A1. Operator visibility via audit log + alerts (Phase 10) is the catch.

---

### A3. Host root compromise while fwd is running

**How.** Attacker exploits some unrelated vulnerability on the host, chains to root, and inspects `fwd`'s process memory while it's serving signing requests.

**What the attacker gets.** During the bounded signing operation, `fwd` decrypts a wallet's privkey via the sealed master (AES-256-GCM), holds the 32-byte plaintext briefly to sign with `eth-account`, and zeroizes immediately after (Core invariant #16). An attacker with `ptrace` / `gcore` access who times their dump to coincide with an active signing operation can extract that wallet's plaintext privkey. Between signing operations, no plaintext privkeys are in `fwd`'s memory (decrypt-on-demand, no caching).

**Mitigations in place.**
- Single-purpose host recommendation (no other services running, smallest attack surface).
- `fwd` calls `mlockall(MCL_CURRENT|MCL_FUTURE)` at startup so plaintext privkeys are not swapped to disk. Because the container runs non-root, the mechanism that lets `mlockall` succeed is `ulimits.memlock: -1` in compose; `cap_add: [IPC_LOCK]` is kept for defense-in-depth (Core invariant #1).
- Decrypt-on-demand (Core invariant #16): plaintext privkeys exist in memory only for microseconds per signing operation.
- Host hardening (operator practice, not a fwd-shipped artifact): minimal package set, SSH key-only, fail2ban, prompt patching.
- Audit-log visibility: `fwd` signs but does not broadcast (zero-egress), so abuse routed *through* `fwd` surfaces as anomalous `sign-transaction` rows in its hash-chained audit log, and `fwd` itself cannot be the broadcast or network-exfil channel (no RPC client, no egress). Use of a key *extracted* from the host (master + ciphertext) happens outside `fwd` and requires external chain monitoring to detect.

**Residual risk.** Real. The exposure window is bounded to active signing operations — plaintext is in memory only during a signing op, not continuously, a meaningful improvement over a naive "key in memory all the time" pattern. **This is the biggest residual risk in v1.**

**Mitigation upgrade path.** YubiHSM 2 (Phase 10): keys generated inside the chip, never leave it. Host root can ask the HSM to sign things while they have access, but cannot exfiltrate keys for offline reuse — and signing-rate limits in the HSM cap abuse. See `architecture.md` § "Forward compatibility" — the `Signer` protocol exists specifically for this swap.

**Comparison to `.env` baseline.** Today: trivial — read a file. After `fwd`: requires deep host compromise plus active memory exfiltration timed to a signing operation.

---

### A4. `fwd` process itself is compromised (bug or supply chain)

**How.** Bug in `fwd`'s policy engine or signing path, or malicious dependency, lets an attacker execute code in the running `fwd` process.

**What the attacker gets.** Code execution in the running `fwd` process can call `SealedMaster.decrypt` (the master is loaded per signing operation from the mode-0600 file, in-process), recovering any wallet privkey it has a `seal:v1:` ciphertext for, and sign anything those keys can sign — bypassing `fwd`'s own policy engine. It **cannot exfiltrate over the network from the `fwd` process itself** (zero egress — fwd makes no outbound connection): exfiltration requires separate host-level egress the attacker must obtain elsewhere. There is no separate key-management process boundary — the deliberate trade-off for low-value automation keys on a never-public host.

**Mitigations in place.**
- `fwd`'s code is small, public, and auditable — bugs surface to scrutiny.
- Pinned dependency versions; images pinned by tag.
- `fwd`'s own hash-chained audit log records every signing decision independently — sustained abuse through `fwd`'s code paths shows up as an anomalous burst of `sign-transaction` rows; the audit log is the authoritative record.
- Default-deny policy: a compromised fwd that goes through its own code paths still hits policy checks. (Bypass requires defeating both `fwd`'s engine AND signing path, not just the engine.)
- Decrypt-on-demand + per-operation master load (Core invariants #16, #8): plaintext keys, and the master itself, are absent from memory between operations — passive bulk extraction must wait for and intercept signing events.
- Zero egress: `fwd` cannot phone home, so a compromise cannot stream keys out on its own.

**Residual risk.** The strongest argument in v1 for the Phase 10 YubiHSM 2 upgrade. Until Phase 10, this is the genuine "fwd compromise = lose the wallets fwd can decrypt while compromised" weakness, mitigated by `fwd`'s audit log, policy default-deny, and the zero-egress denial of an in-process exfil channel.

**Comparison to `.env` baseline.** Today: there is no policy enforcement point. After `fwd`: a compromised `fwd` is similarly catastrophic (key extraction possible with code execution), but the hash-chained audit trail + zero egress make abuse detectable and the exfil path harder in ways `.env` files do not.

---

### A5. Physical access to the host

**How.** Datacenter break-in, evil-maid attack, server seizure.

**What the attacker gets.** A *running* host: same as A4 — plaintext recoverable from `fwd`'s process memory during a signing op. An *offline/stopped* host: the SQLite ciphertexts (`seal:v1:`) AND the mode-0600 `master.key` file — if the attacker reads both, they recover all wallet keys; ciphertexts WITHOUT the master file are useless gibberish. (The sealed master is a plaintext 32-byte file at rest, so disk encryption matters.)

**Mitigations.**
- Datacenter physical security (hosting provider).
- Full-disk encryption on the host (defense in depth — the primary at-rest protection for the `master.key` file).
- The host is never publicly exposed; `fwd` has no egress.

**Residual risk.** Low for hosted environments. Higher for on-premises or if a host is moved. Proportionate to the asset class (low-value automation keys — see the asset table).

---

### A6. Supply-chain attack

**How.** A malicious Python package update, or a backdoored `eth-account` / `cryptography` release.

**What the attacker gets.** Whatever the malicious code does — could exfiltrate keys at signing time, modify transaction destinations silently, or open a covert channel.

**Mitigations.**
- Docker images pinned by tag in `docker-compose.yml` (`fwd` via `${FWD_IMAGE_TAG}`, `litestream:0.3.13`); digest-pinning is a Phase 10 hardening item, not yet applied.
- Python dependencies pinned in `poetry.lock`; no floating versions.
- `fwd`'s own image built from source by AP's CI; not pulled from a registry someone else controls.
- Renovate or Dependabot for proposed updates; updates reviewed before merge.
- `fwd`'s own hash-chained audit log records every signing decision — a supply-chain attack that drives signatures through `fwd`'s code paths still leaves audit traces (and `fwd` has no egress to phone home).

**Residual risk.** Industry-wide problem. Affects all software. Specific mitigations are the standard ones.

---

### A7. Side-channel attacks (Spectre/Meltdown family)

**How.** A separate process on the same host reads `fwd`'s memory (where a wallet key is plaintext during a signing op) via speculative-execution side-channels.

**Mitigations.**
- Single-purpose host: no other services running. No untrusted code shares the kernel.
- Host kernel patched (KPTI, retpoline, etc.).
- Cloud providers apply mitigations at the hypervisor layer.

**Residual risk.** Low for a single-tenant single-purpose host. Higher in multi-tenant cloud, but `fwd`'s `mlockall` (Core invariant #1) prevents swap-to-disk, not speculative reads.

---

### A8. Cryptographic break of secp256k1

**Out of scope.** Affects all of Bitcoin and Ethereum. Not a `fwd`-specific concern. If secp256k1 is broken, `fwd`'s users have bigger problems than `fwd`.

## Summary table

| Threat | Today (`.env`) | After `fwd` v1 | After `fwd` + YubiHSM 2 |
|---|---|---|---|
| Caller compromise | **Total loss** | Bounded by per-caller policy | Bounded by per-caller policy |
| Host root compromise | Total loss | Plaintext recoverable from `fwd` process memory during a signing op; OR host read of BOTH the `master.key` file AND the SQLite ciphertexts | Keys cannot be extracted; signing can be abused while attacker has access |
| Disk theft (ciphertext only) | Total loss | SQLite ciphertexts WITHOUT `master.key` = useless gibberish; WITH it = recoverable (full-disk encryption is the at-rest defense) | Encrypted, useless |
| Backup theft | Total loss | Same as disk theft — ciphertext useless without the separately-held `master.key` | Encrypted, useless |
| `fwd` process compromise | N/A | **All wallet keys decryptable in-process via the sealed master (per A4); attacker can sign during the compromise** — `fwd`'s audit log makes signing visible, and zero egress denies a network exfil channel | Keys cannot be extracted; signing can be abused while compromise persists |
| Supply-chain | Total loss | Bounded by `fwd`'s hash-chained audit + zero egress | Same |
| Physical | Total loss | Encrypted at rest; in-memory if running | Keys never in host memory |

## The honest one-line summary

**`fwd` does not make AP's keys unstealable.** It makes them dramatically more expensive to steal, makes abuse *through* `fwd` visible in its hash-chained audit log (use of an extracted key elsewhere requires external chain monitoring to detect), and bounds the blast radius of caller compromises to the policy envelope of that caller. Combined with policy-bounded per-caller damage, that is the upgrade. Perfect requires hardware (YubiHSM), which is a Phase 10 option, not a v1 requirement.

## When this document is wrong

This threat model captures the current attack surface. It must be updated when:
- A new attack class is discovered or published against any component (Litestream, Docker, secp256k1, etc.).
- `fwd` adds a new attack surface (a new endpoint, a new caller class, a new chain).
- The custody model changes (Phase 10 HSM upgrade — most threats shift).
- Operator practices change (single-operator → multi-operator, on-prem → cloud, etc.).
