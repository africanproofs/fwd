# Dependencies

Every dependency `fwd` requires, grouped by tier. The "Status for AP" column flags what is genuinely new for AP versus already in place.

## Infrastructure dependencies (must exist before `fwd` starts)

| Dependency | Status for AP | Notes |
|---|---|---|
| Docker + Docker Compose | Likely present, must be installed if absent | Any host. No K3s required. |
| GitLab repo + CI runners | ✅ Exists | New repo at `gitlab.com/proofs.africa/fwd` |
| GitLab Container Registry | ✅ Exists | Image: `registry.gitlab.com/proofs.africa/fwd/fwd:<tag>` |
| **A local `backup` volume** | ⚠️ Provision one | Docker volume (or host bind) for Litestream SQLite replicas. Local only — no cloud, no IAM, ~€0/mo. |
| The `master.key` file | ⚠️ Generate one | 32-byte mode-0600 sealed master via `clifwd master generate` (v1.0.0a1; replaces Vault). |

**`fwd` needs NO chain RPC** (zero-egress, v1.1.0a9 / D20): it never broadcasts and never reads the chain. The Flare / Songbird / Coston2 RPC endpoints are **caller** prerequisites (the client broadcasts the signed tx), listed under § Cross-project dependencies — not `fwd` infrastructure.

**Net-new operational surface:** one local `backup` volume + the operator-held `master.key` file. Nothing else.

Notably **NOT required:**
- AWS account
- GCP / Azure account
- K3s / Kubernetes
- Pulumi
- Postgres
- Redis
- Public DNS hostname — `fwd` is on an `internal: true` network with no host port (v1.1.0a15); callers reach it intra-network, admin via `docker exec`
- TLS certificate from a public CA
- Any chain RPC endpoint (zero-egress — `fwd` never reaches the chain)

## Containerized services (deployed by `fwd`'s `docker-compose.yml`)

| Service | Image (tag-pinned; digest-pinning is a Phase 10 item) | Role |
|---|---|---|
| `fwd` | `registry.gitlab.com/proofs.africa/fwd/fwd:<tag>` | The gateway service (FastAPI). Custody is in-process: `SealedMaster` AES-256-GCM under a mode-0600 host-file master (v1.0.0a1 retired the `vault` + `vault-snapshot` services — D1) |
| `litestream` | `litestream/litestream:<version-pinned>` | Continuous SQLite replication to a local `backup` volume (v0.4.3 — no cloud) |

Two services (was four pre-v1.0.0a1: `vault` + `vault-snapshot` deleted with the Vault retirement) deployed and managed by `docker-compose.yml`. Nothing manual to install on the host beyond Docker itself.

## Python runtime libraries (inside the `fwd` container)

| Library | Version constraint | Why |
|---|---|---|
| `fastapi` | `^0.115` | HTTP service framework |
| `uvicorn` | `^0.30` | ASGI server |
| `pydantic` | `^2.9` | Request/response validation (with FastAPI) |
| `pydantic-settings` | `^2.6` | Env var configuration |
| `httpx` | `^0.27` | Used by the **CLI** only (`clifwd` admin commands → `fwd`'s own inbound API: health, wallets, callers, nonce). The daemon (`app`/`api`/`infra`) makes NO outbound HTTP — zero-egress (D20). |
| ~~`hvac`~~ | — | NEVER adopted (Vault retired entirely at v1.0.0a1 — D1; the old hand-rolled `vault_client.py` was deleted then). Struck. |
| `eth-account` | `^0.13` | EIP-1559 transaction encoding, RLP |
| `eth-utils` | `^5.0` | keccak256, address formatting, EIP-55 checksum |
| `coincurve` | `^20.0` | secp256k1 — `eth-account`'s active backend (`eth_keys ... CoinCurveECCBackend`); pinned for custody-path supply-chain legibility, NOT directly imported by `fwd` (wallet keygen is `eth_account.Account.create()` per the v0.2.0 spike). Kept v0.5.5 (audit contest). |
| `sqlalchemy` | `^2.0` | DB layer (async) |
| `aiosqlite` | `^0.20` | Async SQLite driver |
| `alembic` | `^1.13` | Schema migrations |
| `argon2-cffi` | `^23.1` | API key hashing (argon2id) |
| `pyyaml` | `^6.0` | Policy file loading |
| `structlog` | `^24.4` | JSON structured logging |
| ~~`prometheus-client`~~ | — | Removed v0.5.5 (audit OE-6): zero src/ use; re-add at Phase 10 when `/metrics` is built |
| ~~`tenacity`~~ | — | **Removed v1.1.0a21** — was the retry policy for RPC calls; zero `src/`+`tests/` use since the v1.1.0a9 RPC excision (`fwd` makes no RPC, zero-egress), and not a transitive dep of anything. Dropped from `pyproject.toml` + `poetry.lock` (minimal `--no-update` re-lock). |
| `typer` | `^0.16` | CLI framework |
| `rich` | `^13.9` | CLI rendering |

Notably **NOT present:**
- `web3.py` — too heavy, we don't need contract abstractions. `eth-account` covers the signing path with a fraction of the dependency tree (`httpx` is CLI/admin-client only — the daemon makes no outbound HTTP; zero-egress, D20).
- `kubernetes` — no K8s API access needed (no TokenReview).
- `boto3` — no AWS dependency.

Dependency tree pinned in `poetry.lock`; floating versions are forbidden. Updates proposed via Renovate or Dependabot, reviewed before merge.

## Build, dev, and test tooling

| Tool | Version | Notes |
|---|---|---|
| Python | 3.12 | AP standard. Pinned in `.python-version`. |
| Poetry | ≥ 1.8 | AP standard for dependency management |
| `pytest` | `^8.3` | Test framework |
| `pytest-asyncio` | `^0.24` | Async test support |
| `pytest-cov` | `^6.0` | Coverage reporting (CI gate) |
| `ruff` | `^0.8` | Lint + format (AP standard) |
| `mypy` | `^1.13` | Strict type-checking (AP standard) |
| Docker | Recent | For local image builds and `docker-compose` |
| Docker Compose | v2 | Native CLI (`docker compose`, not `docker-compose`) |
| GitLab CI runner | Existing | Lints, tests, builds the image, pushes to registry |

## Operator prerequisites (one-time, human-side)

| Item | Why | Status |
|---|---|---|
| `master.key` (32-byte sealed master) | Custody root — generate via `clifwd master generate`, mode-0600, bind-mounted, backed up off-host out-of-band. Replaces the entire Vault unseal-share apparatus (no GPG/YubiKey/paper/Shamir — Vault retired v1.0.0a1, D1). | Generate before first boot |
| Off-host copy of the `backup` volume + `master.key` | Disaster recovery (litestream restore + the master file). Operator's own transport (rsync/restic/USB/NAS) — `fwd` does not ship backups off-host (no egress). No cloud IAM / S3 bucket. | Operator-driven |
| Hardware wallet for identity rotation | `ClaimSetupManager.setClaimExecutors` transaction signed by the identity address | Already in use by AP |

## Cross-project dependencies (callers, not `fwd`'s deps)

These are projects that *change* because of `fwd`, not projects `fwd` depends on:

| Project | Migration | Phase |
|---|---|---|
| `ftso-fee-claimer` | Replace `.env PRIVATE_KEY` with `FWD_URL` + `FWD_API_KEY`; rotate claim recipient on-chain | 8 |
| `apregister/` | Replace Coston2 test wallet `.env`; generate new test wallet | 9 |
| `apcli` | Audit which keys it holds; migrate as appropriate | 9 |
| `fics` write paths | When `fics` gains writes (currently observe-only) | When applicable |
| Identity / delegation / validator keys | **Do not migrate** — stay offline on hardware wallet | Never |

## Things `fwd` explicitly does NOT depend on

Listed because earlier design drafts implied otherwise; making the absences explicit prevents reintroduction by drift.

- **No AWS** — KMS path was rejected; no IAM, no us-east-1, no second cloud account.
- **No GCP / Azure** — same reason.
- **No HSM hardware** in v1 — YubiHSM 2 is a Phase 10 upgrade, not a v1 requirement.
- **No K3s / Kubernetes** — Docker Compose is the deployment unit.
- **No Pulumi** — the Pulumi-exclusivity rule from root `CLAUDE.md` applies to K8s deployments only; `fwd` is not on K8s.
- **No Postgres** — SQLite + Litestream replaces it.
- **No Redis** — SQLite handles nonce locking via `BEGIN IMMEDIATE`.
- **No public DNS / TLS cert** — `fwd` is on an `internal: true` network with no host port (v1.1.0a15); reachable only intra-network, admin via `docker exec`.
- **No chain RPC / `web3.py` / broadcast path** — `eth-account` signs; the client broadcasts (zero-egress, D20).
- **No external auth provider** (Auth0, Keycloak, etc.) — bearer API keys are the auth model in v1, mTLS is the Phase 10 option.
- **No service-mesh** (linkerd, Istio) — the `fwd-callers` `internal: true` Docker network is the boundary.

## Honest summary

The only genuinely net-new operational dependencies AP picks up by building `fwd` are **a local `backup` volume for Litestream** and the operator-held **`master.key`** sealed-master file (v1.0.0a1 — HashiCorp Vault was retired; there is no Vault container, no AWS, no cloud account). Everything else is either already operating, already in AP's standard stack, or trivially provisioned.

Compared to the AWS-KMS alternative, `fwd` adds *less* total dependency surface — no cloud account, no KMS, one daemon + one backup sidecar. Compared to the K3s alternative, `fwd` removes the K8s control-plane dependency at the cost of slightly weaker caller authentication (bearer keys vs SA tokens), with a documented Phase 10 mTLS upgrade path.

## Verification spike (Phase 1 risk retirement)

> **Historical (Phase 1, v0.2.0).** Both assumptions below were tested under the original Vault-Transit + fwd-broadcasts design. Both have since been superseded: **(1)** Vault was retired at v1.0.0a1 — custody round-trips through the in-process `SealedMaster` (AES-256-GCM), proven live by the v1.0.0a3 sealed-master drill; **(2)** `fwd` no longer broadcasts (v1.1.0a9 / D20) — the client does, and the signed-tx + broadcast path is proven by the v1.1.0a12 funded Coston2 drill + the epoch-400 mainnet drill. Retained as honest history of the Phase 1 risk retirement.

The Phase 1 spike retired two specific dependency assumptions under the (then-current) v0.1.2 architecture:

1. **Vault Transit `aes256-gcm96` round-trips arbitrary 32-byte plaintext intact** — confirm `transit/encrypt/fwd-master` accepts a base64-encoded 32-byte secp256k1 privkey and `transit/decrypt/fwd-master` returns the original bytes verbatim. The roundtrip is asserted in the spike before the privkey is used.
2. **`eth-account` 0.13.x signs a type-0x02 (EIP-1559) transaction for chainId 114 that Coston2 RPC accepts** — confirm `Account.sign_transaction(tx_dict, privkey)` produces a correctly-RLP-encoded signed transaction whose `eth_sendRawTransaction` broadcast succeeds and produces a successful receipt.

If either fails, dependency selection revisits before Phase 2 begins. DER parsing, low-S normalization, and v-recovery are NOT exercised in this spike — they are out of scope under v0.1.2 (`eth-account` returns Ethereum-shaped output directly) and return only when Phase 10 introduces a hardware-backed signer.
