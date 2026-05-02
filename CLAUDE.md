# fwd — Flare Wallet Daemon

> Policy-gated signing service for African Proofs' EVM backend keys. Custody-first; substrate-minimal; Anthropic agents are first-class callers. The redesign of `keosd` for autonomous agents on Flare in 2026.

## Identity

`fwd` holds AP's automation private keys envelope-encrypted by HashiCorp Vault Transit (`aes256-gcm96`, `exportable=false`); decryption and signing happen in `fwd`'s own process post-unwrap, gated by declarative policy and recorded in an append-only audit log. Every `.env PRIVATE_KEY` line in AP backends — `ftso-fee-claimer`, `apregister/`, `apcli`, future `fics` write paths, future Claude agents — calls `fwd` instead of holding keys directly.

The custody property `fwd` rests on: **the Vault Transit master encryption key is `exportable=false` and cannot be extracted via the API; private keys are envelope-encrypted at rest and exist as plaintext in `fwd`'s process memory only during the bounded signing operation, after which the buffer is zeroized (Core invariant #16).** This is a deliberate trade-off documented in `decisions.md` D1: the originally-intended design (Vault Transit signing of `ecdsa-p256k1` keys) was infeasible because Vault does not support secp256k1.

The workflow doctrine below is settled — transferred verbatim from FICSM (`../ficsm/CLAUDE.md` § Development workflow), where it was earned through FICS' five-month design cycle and the S0+S1+S2 hardware sealing on 2026-04-25. `fwd` inherits the operating discipline, not the substrate; the substrate (single-purpose signing service vs multi-stratum control plane) is fwd's own.

## Scope (current state)

**v0.1.0 (shipped 2026-04-30):** Documentation only. Architecture, decisions record, threat model, dependency inventory, 10-phase implementation plan. No code, no Docker artifacts, no Vault. Project registered in root `CLAUDE.md` Project Map.

**v0.1.1 (shipped 2026-04-30):** Pre-Phase-1 documentation fixes from the v0.1.0 CTO review — relational schema for decoded intent and hash history (replacing JSON-blob columns), `Idempotency-Key` header contract, error envelope, versioning policy, and layer-boundary specification. No code yet; specs only. Phase 1 builds against this spec base.

**v0.1.2 (shipped 2026-05-01):** Architecture pivot to Vault Transit envelope encryption. The originally-intended D1 (Vault Transit signing of `ecdsa-p256k1` keys) was found infeasible during the v0.2.0 spike attempt — neither Vault OSS, OpenBao, nor Vault Enterprise's native Transit supports secp256k1 (verified against upstream docs). The revised D1 uses Vault Transit `aes256-gcm96` to envelope-encrypt externally-generated secp256k1 privkeys; signing happens in fwd's process post-decrypt. Trade-off documented in threat-model.md A3/A4: the two-process custody boundary is collapsed to a single process; mitigated by Core invariant #16 (decrypt-on-demand, zeroize-on-completion). Phase 10 YubiHSM 2 remains the canonical upgrade path. No code yet; specs only.

**v0.2.0 (shipped 2026-05-01):** Single throwaway Python script that signed a Coston2 transaction via the v0.1.2 envelope-encryption flow (generate secp256k1 privkey externally → encrypt with Vault Transit `aes256-gcm96` → decrypt + sign with `eth-account` in-process → broadcast). The DER → low-S → v-recovery dance does NOT apply under v0.1.2 (eth-account returns Ethereum-shaped output directly). Script lives at `scratch/spike.py` (gitignored); durable record with the on-chain transaction hash and dependency-retirement evidence is at `docs/history/0.2.0-spike-coston2.md`. The architecture is real; Phase 2 (project scaffold) is unblocked.

**v0.2.1 (shipped 2026-05-01):** Pre-Phase-2 documentation fixes from the post-v0.2.0 CTO review — explicit Vault-decryption failure handling in the signing flow (with nonce-release semantics on pre-broadcast failures), and an `## Implementation hazards (v0.1.2 envelope encryption)` section documenting the three patterns specific to the envelope-encryption design (no plaintext caching between requests, `bytearray` not `bytes` for privkey buffers, structlog scrubber for hex-shaped 32-byte values). No code yet; specs only. Phase 2 builds against this updated spec base.

**v0.2.2 (shipped 2026-05-01):** Wallet-provisioning policy. New `decisions.md` D9: HTTP `POST /v1/admin/wallets` and `clifwd wallets create` both generate fresh privkeys inside `fwd` (plaintext never leaves the process); `clifwd wallets import --privkey-file` accepts an existing 32-byte hex privkey via a file with mode 0600 + ownership checks; **plaintext export is deliberately NOT supported** in v1. New `architecture.md` § Wallet provisioning documenting both flows. Phase 3 stale references to per-wallet Vault keys (`transit/keys/<wallet>`) corrected to the v0.1.2 envelope-encryption model (`transit/keys/fwd-master`). Phase 4 deliverables extended to include `clifwd wallets create|import|list`. No code yet; the actual CLI lands in Phase 4.

**v0.2.3 (shipped 2026-05-01):** CLI rename — `fwd-cli` → `clifwd`. Pronounceable as "Clifford" and one token to type. Matches the keosd-lineage naming pattern (Antelope's `cleos` is `cl` + `eos`; ours is `cl` + `i` + `fwd` for pronounceability). Mechanical rename across all docs (29 occurrences in 5 files); no behavioural change. The Phase 2 scaffold and onwards will land the binary as `clifwd` with the entry point `clifwd = "fwd.cli:app"` in `pyproject.toml`. The Python package itself stays `fwd` (the daemon); only the operator-facing CLI command changes. Reviewer-only commit (no Sonnet involvement; pure find/replace).

**v0.3.0-alpha (shipped 2026-05-01):** Project scaffold landed. `pyproject.toml` (Poetry, Python 3.12, all v1 runtime + dev deps pinned per `dependencies.md`). Multi-stage `Dockerfile` (build + slim runtime; non-root user). `docker-compose.yml` with three services (`vault` HashiCorp Vault 1.18.2; `fwd` FastAPI app; `litestream` 0.3.13 with placeholder file replica), two networks (`fwd-internal` internal, `fwd-callers` bridge), and three named volumes. `src/fwd/` package skeleton with the four-layer directory structure (`domain/`, `app/`, `infra/`, `api/`, `cli/`) per `architecture.md` § Layer boundaries — empty stubs for now; Phase 3+ fills them. `/healthz` endpoint live (returns `{vault, rpc, fwd}` shape). `clifwd version` and `clifwd health` subcommands wired. Tests: version-consistency drift test (Core invariant #13), layer-boundary import-graph test (architecture.md § Enforcement), and a `/healthz` smoke test. Alembic initialized with one empty scaffold migration (Phase 5 lands the real schema). GitLab CI pipeline: lint (ruff), type-check (mypy strict), unit tests (pytest), Docker build. **Verification gate met**: `docker compose up -d` brings all three containers up; `/healthz` returns 200 with the expected JSON; `clifwd health` returns the same; CI green. No signing, no Vault init, no real Litestream replication — those are Phase 3, Phase 3, and Phase 6 respectively.

**v0.3.0a1 (shipped 2026-05-02):** Phase 3a — Vault deployment infrastructure. New `config/vault/policies/fwd-app.hcl` (Vault policy: `update` on `transit/encrypt/fwd-master` + `transit/decrypt/fwd-master`, `read` on `transit/keys/fwd-master`; no `transit/sign/*`). New `scripts/vault-init.sh` (POSIX `/bin/sh`, idempotent, runs inside `fwd-vault` post-unseal: enables Transit, creates `aes256-gcm96` master key, writes the policy, enables AppRole, creates the `fwd` role, prints role_id + secret_id for operator capture). New `docs/runbooks/vault-init.md` documenting the full Shamir 3-of-5 ritual per D6. `docker-compose.yml` updated to mount `./config/vault/` and `./scripts/` into the vault container. `.env.example` updated with `FWD_VAULT_ROLE_ID` + `FWD_VAULT_SECRET_ID` placeholders (replacing the prior `# VAULT_TOKEN=` comment). No fwd code changes — Phase 3b lands the Vault client. Verification gate: operator runs the runbook on a fresh Vault and reaches "fwd Vault initialization complete" output without errors.

**v0.3.0a2 (this ship, 2026-05-02):** Reviewer-only fix-up for v0.3.0a1, surfaced during the manual verification ritual. The `vault` CLI inside `fwd-vault` defaults to `https://127.0.0.1:8200` when `VAULT_ADDR` is unset, but our listener is HTTP (`tls_disable = true`; `fwd-internal` is the security boundary). Without `VAULT_ADDR` in container env, every `docker exec fwd-vault vault <cmd>` fails with `http: server gave HTTP response to HTTPS client` — breaking step 1 of `docs/runbooks/vault-init.md` and every subsequent runbook step. The compose healthcheck (line 19) had inlined `VAULT_ADDR=http://127.0.0.1:8200` but never generalized; v0.3.0a1's runbook + script inherited the bug. Fix: add `environment: { VAULT_ADDR: http://127.0.0.1:8200 }` to the vault service. Surgical (5 lines + comment); script and runbook unchanged. The healthcheck's inline prefix is now redundant but left intact (out of scope for a defect fix; cleanup deferred). No Sonnet involvement — the fix is mechanical and was discovered by the Reviewer during the v0.3.0a1 verification gate. Phase 3b shifts to v0.3.0a3.

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

1. **Keys never persist plaintext.** Each wallet's secp256k1 private key is generated externally (secure RNG), envelope-encrypted by Vault Transit (`aes256-gcm96`, `exportable=false`), and stored as `vault:v1:<ciphertext>` in SQLite. Plaintext keys exist in `fwd`'s process memory only during the bounded signing operation, are protected by `mlock` against swap, and are zeroized after each signature. The Vault master key cannot be extracted via the API. Compromise of `fwd` while running grants the attacker the ability to extract plaintext keys from process memory at signing time; offline disk theft yields ciphertext only. (See `decisions.md` D1 for the v0.1.2 pivot from the originally-intended Vault Transit signing design, which was infeasible because Vault does not support secp256k1 as a Transit key type.)

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

16. **Decrypt-on-demand, zeroize-on-completion.** Plaintext private keys are not cached in `fwd`'s process memory between signing operations. Each `/v1/sign-and-send` call decrypts the wallet's privkey via Vault, signs the transaction with `eth-account`, and zeroizes the plaintext buffer immediately. Process-wide privkey caches are forbidden as a regression. The exposure window for any single privkey is bounded to the duration of one signing operation (microseconds per call at AP volume). Combined with `mlock`-protected process memory, this minimizes the A3/A4 attack surface for the v0.1.2 single-process custody design.

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

The role itself — *daemon that holds keys and signs on behalf of clients* — is inherited from `keosd` (Antelope/EOSIO `programs/keosd/`). What `fwd` adds that `keosd` does not provide: intent decoding, default-deny per-caller policy, hash-chained audit, EVM-native signing flow, and a custody backend (Vault Transit `aes256-gcm96` envelope encryption) whose master encryption key is non-exportable by API and whose plaintext private keys exist in `fwd`'s memory only during the bounded signing operation.

The ~50 banked feedback memories at `~/.claude/projects/-home-l-working-gitlab-com-proofs-africa-fics/memory/` and the FICSM doctrine doc at `../ficsm/CLAUDE.md` act as a Phase-0 checklist for `fwd`'s reviewers.
