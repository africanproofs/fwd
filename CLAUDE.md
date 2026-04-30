# fwd — Flare Wallet Daemon

> Policy-gated signing service for African Proofs' EVM backend keys. Custody-first; substrate-minimal; Anthropic agents are first-class callers. The redesign of `keosd` for autonomous agents on Flare in 2026.

## Identity

`fwd` holds AP's automation private keys inside HashiCorp Vault Transit and signs transactions on behalf of authenticated callers, gated by declarative policy and recorded in an append-only audit log. Every `.env PRIVATE_KEY` line in AP backends — `ftso-fee-claimer`, `apregister/`, `apcli`, future `fics` write paths, future Claude agents — calls `fwd` instead of holding keys directly.

The custody property `fwd` rests on: **Vault Transit keys are `exportable=false`. Keys cannot be extracted via the API even by a Vault admin. The signer abuses keys; it cannot exfiltrate them.**

The workflow doctrine below is settled — transferred verbatim from FICSM (`../ficsm/CLAUDE.md` § Development workflow), where it was earned through FICS' five-month design cycle and the S0+S1+S2 hardware sealing on 2026-04-25. `fwd` inherits the operating discipline, not the substrate; the substrate (single-purpose signing service vs multi-stratum control plane) is fwd's own.

## Scope (current state)

**v0.1.0 (this ship, 2026-04-30):** Documentation only. Architecture, decisions record, threat model, dependency inventory, 10-phase implementation plan. No code, no Docker artifacts, no Vault. Project registered in root `CLAUDE.md` Project Map.

**v0.2.0 (Phase 1 — the spike):** Single throwaway Python script that signs a Coston2 transaction via Vault Transit `ecdsa-p256k1` and broadcasts it. Validates the DER → low-S → v-recovery flow against a real Flare-stack RPC. ~50 lines.

**v0.3.0 (Phase 2–4):** Project scaffold (Poetry, FastAPI, Dockerfile, `docker-compose.yml`), Vault deployed in compose, signing core for `/v1/sign-and-send` against Coston2. Single pre-provisioned wallet. Integration test green.

**v0.4.0 (Phase 5–6):** SQLite + Alembic schema, nonce reservation under `BEGIN IMMEDIATE`, transaction tracking with UUID `tx_id`, receipt watcher, replacement-on-stuck. Litestream sidecar replicating to Scaleway Object Storage. Restore drill passes.

**v0.5.0 (Phase 7):** YAML policy engine, ABI-based intent decoder for FTSO RewardManager + ParticipantRegister, hash-chained audit log, default-deny path verified by synthetic-attack test.

**v1.0.0 (Phase 8):** First production migration — `ftso-fee-claimer` switches from `.env PRIVATE_KEY` to fwd. New claim-recipient address generated in Vault, on-chain rotation via `setClaimRecipient`. One full reward epoch claimed via fwd end-to-end.

**v1.1.x (Phase 9):** Rolling migration of remaining `.env` keys (`apregister/` Coston2 test wallet, `apcli`, `fics` write paths). Identity / delegation / validator keys do NOT migrate — they stay offline behind a hardware wallet.

**v2.x (Phase 10, deferred):** Hardening — auto-unseal, Prometheus metrics, on-chain audit-log anchoring, optional YubiHSM 2 for hardware-isolated signing, optional mTLS for cross-host callers.

## What FWD Deliberately IS NOT

These are not in scope until a real consumer or proven need surfaces. Re-introducing any requires explicit operator authorization tied to a concrete consumer:

- **Not a user wallet.** Frontends (`apregister-web`, `proofs-website`) keep thirdweb v5. fwd is for *backend automation*, not user flows.
- **Not multi-chain beyond EVM Flare-family.** Flare, Songbird, Coston2 only. No Bitcoin, Solana, Cosmos, Antelope.
- **Not clustered, not HA, not horizontally scalable.** A signer is a coherence boundary, not a scaling unit. One container, one wallet set, one nonce manager per (wallet, chain).
- **No K8s, no Pulumi, no Helm.** `docker-compose.yml` is the deployment artifact. K3s exists in AP infra but `fwd` does not run on it.
- **No public network exposure in v1.** Bind to `127.0.0.1` on the host; callers reach fwd via the Docker bridge network only. No `signer.proofs.africa` DNS.
- **No autonomous policy.** Every rule is declarative YAML. The LLM never decides whether to sign.
- **No web UI.** HTTP API + a thin CLI for admin operations. No dashboard.
- **No multi-signer / threshold / MPC in v1.** Single Vault, single key per wallet.
- **No HSM hardware in v1.** YubiHSM 2 is a Phase 10 option.
- **No `web3.py`.** `eth-account` + `httpx` cover the signing path with a fraction of the dependency tree.
- **No raw-digest signing.** `/sign-message` and `/sign-typed-data` exist; arbitrary `eth_sign`-style endpoints do not.
- **No long-lived caller credentials issued by humans.** Caller API keys are minted by `fwd` itself, scoped per policy, rotatable from the CLI.

## Core invariants

1. **Keys never leave Vault.** Vault Transit, key type `ecdsa-p256k1`, `exportable=false`, `derived=false`. The single architectural property the entire project rests on. Compromise of `fwd` lets the attacker *abuse* keys, never *extract* them.

2. **Default-deny.** Every signing request is denied unless policy explicitly permits caller × wallet × contract × method × value × rate. New callers and new wallets enter with zero capabilities.

3. **Sign intent, never opaque bytes.** Every signing request must decode to a known ABI shape against the policy-bound contract. Unparseable calldata = refuse. The audit log records the decoded human-readable intent, not the raw hex.

4. **One nonce manager per (wallet, chain).** SQLite `BEGIN IMMEDIATE` serializes nonce reservation. Concurrent signing requests against the same wallet cannot collide. Nonce release on confirmed-or-dropped, reconciliation on startup.

5. **Append-only audit log.** Every request, decision, signature, and broadcast outcome is recorded in a hash-chained log (`prev_hash`, `row_hash`). Rows are never deleted, never updated. Tamper-evidence is verifiable by a CLI that walks the chain.

6. **Caller identity is bearer-token-with-scope, not username-and-password.** Each caller has an API key issued by `fwd`. The key is mapped in policy to a specific set of `(wallet, contract, method, max_value, rate)` permissions. Compromise of one key cannot exceed that caller's policy.

7. **No `PRIVATE_KEY=` in any AP `.env` file post-migration.** Eliminating that pattern is what `fwd` exists to do. Any commit reintroducing a backend private key into a `.env` file is a regression and must be reverted before merge.

8. **Manual unseal in v1.** Vault is sealed at startup; the operator unseals with 3-of-5 Shamir shares via `docker exec`. Auto-unseal is Phase 10.

9. **Single replica.** `fwd` runs as one container. Restart on failure, not failover. The signer is a singleton by design.

10. **Host-agnostic deployment.** `docker-compose.yml` + `.env.example` runs identically on any host with Docker + Docker Compose. No bake of Scaleway / ap-ftso-02 / IP-specific assumptions into the repo. Host-specific config flows through `.env`, period.

11. **Replacement, not retry-from-zero.** Stuck transactions are resubmitted with the same nonce and bumped `maxPriorityFeePerGas` (× 1.125, capped at 5 retries). A reserved nonce is never silently abandoned; it confirms, replaces, or surfaces to operator.

12. **Public repo, private config.** `gitlab.com/proofs.africa/fwd` is public. The security model is policy + custody, not concealment. Actual `policy.yaml` values, caller API keys, Vault unseal shares, and Litestream credentials live outside the repo (separate private repo or env-injected on the host).

13. **Linear forward versioning.** Every ship bumps the next linear patch number in BOTH `pyproject.toml` and `fwd/version.py`. No back-port semver. Main is the only delivery target. Carryover from FICSM Core invariant #8.

14. **Real-RPC verification is the validation.** Unit tests with mocked RPCs are necessary but not sufficient. Every signing-path change must be verified against a live Coston2 RPC before merging to the production-flow code. Mocks lie. Carryover from FICSM Core invariant #13.

15. **Operator gates every production migration.** No automated `.env` sweep. Each application's migration to `fwd` (Phase 8 onwards) is its own ship with its own operator approval — even when the code change is mechanical. Migrations are the moments where a mistake translates to lost keys.

## Development workflow — Opus prescribes, Sonnet implements with deviation license, Opus reviews with overwrite authority

Four roles in deliberate tension. Carryover from FICSM § Development workflow, abbreviated.

### Reviewer (Opus 4.7) — PRESCRIBES

Drafts the canonical prompt for each ship: file paths, exact contents, drift rules, test deltas, verification block. Reviewer authority is *what `fwd` should be after this ship*.

Reviewer obligations:
- Phase 0: read code, verify codebase semantics, surface design questions to operator.
- Draft a self-contained canonical prompt at `~/.claude/plans/fwd-canonical-prompt-<ship>.md`.
- Pre-handoff scan: shell-var substitution defects, identifier-rename completeness, multi-segment `bash -c` wrapping (FICSM Core invariant #19).
- Demarcate hand-off content explicitly with a `**HAND-OFF — <recipient> (paste verbatim into <destination>):**` block.

### Implementer (Sonnet 4.6) — IMPLEMENTS, WITH LICENSE TO DEVIATE

Reads the canonical prompt cold (no Opus chat history) and executes. Sonnet does NOT execute verbatim if doing so would produce wrong code.

Legitimate deviation (Sonnet adapts AND reports):
- Spec asserts a literal that grep reveals is a shell variable.
- Call site requires a parameter Sonnet discovers during integration.
- Edge case Sonnet uncovers naturally produces a different test count.
- Spec contains a typo.

Illegitimate deviation (REJECT):
- "While I'm here" refactors of unrelated code.
- Adding features the spec didn't request.
- Skipping spec items.
- Improvising a custom workaround when the spec has no path → STOP and surface to operator.

Sonnet obligations: faithful where spec matches reality, narrowest correct adaptation where it doesn't, every deviation reported in the "Open questions / surprises" section, never hidden, never claim spec was followed when it was adapted. Sonnet does NOT commit. Reviewer commits.

### Reviewer at verification — INSISTS, MAY OVERWRITE

After Sonnet's report, file-by-file Read pass (NOT just `git diff`). Authority at this stage is binding:

- **Accept:** sound deviation, common case.
- **Path (a) — Correct in place:** short corrective directive in same Sonnet session for tiny fixes (typo, missed import).
- **Path (b) — Overwrite:** wholesale revert + rewrite canonical prompt + fresh Sonnet session.
- **Path (c) — Inline tweak:** ONLY for non-behavioural adjustments. NEVER for logic.

### Operator (human) — DRIVES, GATES

Gives intent, gates plans + canonical prompts, approves production migrations, holds the unseal shares. May override the reviewer's commit at any time. Operator authority is supreme.

### Co-authorship convention

Two-coauthor trailer on every commit (Sonnet first, Opus last):

```
Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

Reviewer-only commits (docs-only with no Sonnet involvement) drop the Sonnet line. Sonnet-only commits do not exist.

## Behavioural guidelines

Carryover from FICSM § Behavioural guidelines (after Karpathy's principles, via [forrestchang/andrej-karpathy-skills](https://github.com/forrestchang/andrej-karpathy-skills)).

1. **Think before coding.** Don't assume. Don't hide confusion. Surface tradeoffs. State assumptions explicitly, present alternatives, push back when a simpler approach exists.
2. **Simplicity first.** Minimum code that solves the problem. Nothing speculative. No features beyond what was asked, no abstractions for single-use code, no error handling for impossible scenarios. The "What FWD IS NOT" list operationalizes this for fwd-specific scope.
3. **Surgical changes.** Touch only what you must. Don't "improve" adjacent code, don't refactor what isn't broken, match existing style. Every changed line traces to the canonical prompt or a Sonnet-surfaced legitimate deviation.
4. **Goal-driven execution.** Define success criteria. Loop until verified. Every fwd canonical prompt's verification block is the strong criterion for that ship.

## Linear-forward versioning

Per Core invariant #13: every ship bumps the next linear patch number in BOTH `pyproject.toml` and `fwd/version.py`. No back-port semver. The commit message carries the back-reference for any patch fixing an older ship's defect.

## Carryover from FICSM and from `keosd`

`fwd` is not a fork of either. The workflow doctrine (Opus/Sonnet/Reviewer/Operator), the four-layer validation philosophy, the linear-forward versioning, the canonical-prompt completeness checklist, and the substrate ethos (SQLite, single-operator, framework-free) are inherited verbatim from FICSM as design — no FICSM code is imported.

The role itself — *daemon that holds keys and signs on behalf of clients* — is inherited from `keosd` (Antelope/EOSIO `programs/keosd/`). What `fwd` adds that `keosd` does not provide: intent decoding, default-deny per-caller policy, hash-chained audit, EVM-native signing flow, and a custody backend (`Vault Transit`) whose keys are non-exportable by API.

The ~50 banked feedback memories at `~/.claude/projects/-home-l-working-gitlab-com-proofs-africa-fics/memory/` and the FICSM doctrine doc at `../ficsm/CLAUDE.md` act as a Phase-0 checklist for `fwd`'s reviewers.
