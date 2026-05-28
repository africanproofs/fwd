# Dependencies

Every dependency `fwd` requires, grouped by tier. The "Status for AP" column flags what is genuinely new for AP versus already in place.

## Infrastructure dependencies (must exist before `fwd` starts)

| Dependency | Status for AP | Notes |
|---|---|---|
| Docker + Docker Compose | Likely present, must be installed if absent | Any host. No K3s required. |
| GitLab repo + CI runners | ✅ Exists | New repo at `gitlab.com/proofs.africa/fwd` |
| GitLab Container Registry | ✅ Exists | Image: `registry.gitlab.com/proofs.africa/fwd/fwd:<tag>` |
| **A local `backup` volume** | ⚠️ Provision one | Docker volume (or host bind) for Litestream SQLite replicas. Local only — no cloud, no IAM, ~€0/mo. |
| The `master.key` file | ⚠️ Generate one | 32-byte mode-0600 sealed master via `clifwd master generate`. |

**`fwd` needs NO chain RPC** (zero-egress): it never broadcasts and never reads the chain. The Flare / Songbird / Coston2 RPC endpoints are **caller** prerequisites (the client broadcasts the signed tx), listed under § Cross-project dependencies — not `fwd` infrastructure.

**Net-new operational surface:** one local `backup` volume + the operator-held `master.key` file. Nothing else.

Notably **NOT required:**
- AWS account
- GCP / Azure account
- K3s / Kubernetes
- Pulumi
- Postgres
- Redis
- Public DNS hostname — `fwd` is on an `internal: true` network with no host port; callers reach it intra-network, admin via `docker exec`
- TLS certificate from a public CA
- Any chain RPC endpoint (zero-egress — `fwd` never reaches the chain)

## Containerized services (deployed by `fwd`'s `docker-compose.yml`)

| Service | Image (tag-pinned; digest-pinning is a Phase 10 item) | Role |
|---|---|---|
| `fwd` | `registry.gitlab.com/proofs.africa/fwd/fwd:<tag>` | The signing daemon (FastAPI). Custody is in-process: `SealedMaster` AES-256-GCM under a mode-0600 host-file master. |
| `litestream` | `litestream/litestream:<version-pinned>` | Continuous SQLite replication to a local `backup` volume (no cloud) |

Two services deployed and managed by `docker-compose.yml`. Nothing manual to install on the host beyond Docker itself.

## Python runtime libraries (inside the `fwd` container)

| Library | Version constraint | Why |
|---|---|---|
| `fastapi` | `^0.115` | HTTP service framework |
| `uvicorn` | `^0.30` | ASGI server |
| `pydantic` | `^2.9` | Request/response validation (with FastAPI) |
| `pydantic-settings` | `^2.6` | Env var configuration |
| `httpx` | `^0.27` | Used by the **CLI** only (`clifwd` admin commands → `fwd`'s own inbound API: health, wallets, callers, nonce). The daemon (`app`/`api`/`infra`) makes NO outbound HTTP — zero-egress (D20). |
| `eth-account` | `^0.13` | EIP-1559 transaction encoding, RLP |
| `eth-utils` | `^5.0` | keccak256, address formatting, EIP-55 checksum |
| `eth-abi` | `^5.0` | ABI encode/decode for intent decoding (`domain/intent.py`) + FSP message reconstruction (`domain/fsp_message.py`) |
| `coincurve` | `^20.0` | secp256k1 — `eth-account`'s active backend (`eth_keys ... CoinCurveECCBackend`); pinned for custody-path supply-chain legibility, NOT directly imported by `fwd` (wallet keygen is `eth_account.Account.create()`). |
| `sqlalchemy` | `^2.0` | DB layer (async) |
| `aiosqlite` | `^0.20` | Async SQLite driver |
| `alembic` | `^1.13` | Schema migrations |
| `argon2-cffi` | `^23.1` | API key hashing (argon2id) |
| `cryptography` | `^44.0` | AES-256-GCM sealed-master custody primitive (`infra/sealed_master.py`) |
| `pyyaml` | `^6.0` | Policy file loading |
| `structlog` | `^24.4` | JSON structured logging |
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
| `types-pyyaml` | `^6.0` | PyYAML type stubs for `mypy --strict` (policy loader) |
| Docker | Recent | For local image builds and `docker-compose` |
| Docker Compose | v2 | Native CLI (`docker compose`, not `docker-compose`) |
| GitLab CI runner | Existing | Lints, tests, builds the image, pushes to registry |

## Operator prerequisites (one-time, human-side)

| Item | Why | Status |
|---|---|---|
| `master.key` (32-byte sealed master) | Custody root — generate via `clifwd master generate`, mode-0600, bind-mounted, backed up off-host out-of-band. | Generate before first boot |
| Off-host copy of the `backup` volume + `master.key` | Disaster recovery (litestream restore + the master file). Operator's own transport (rsync/restic/USB/NAS) — `fwd` does not ship backups off-host (no egress). | Operator-driven |
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
- **No public DNS / TLS cert** — `fwd` is on an `internal: true` network with no host port; reachable only intra-network, admin via `docker exec`.
- **No chain RPC / `web3.py` / broadcast path** — `eth-account` signs; the client broadcasts (zero-egress, D20).
- **No external auth provider** (Auth0, Keycloak, etc.) — bearer API keys are the auth model in v1, mTLS is the Phase 10 option.
- **No service-mesh** (linkerd, Istio) — the `fwd-callers` `internal: true` Docker network is the boundary.

## Honest summary

The only genuinely net-new operational dependencies AP picks up by building `fwd` are **a local `backup` volume for Litestream** and the operator-held **`master.key`** sealed-master file (no AWS, no cloud account). Everything else is either already operating, already in AP's standard stack, or trivially provisioned.

Compared to the AWS-KMS alternative, `fwd` adds *less* total dependency surface — no cloud account, no KMS, one daemon + one backup sidecar. Compared to the K3s alternative, `fwd` removes the K8s control-plane dependency at the cost of slightly weaker caller authentication (bearer keys vs SA tokens), with a documented Phase 10 mTLS upgrade path.

