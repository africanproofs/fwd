# Dependencies

Every dependency `fwd` requires, grouped by tier. The "Status for AP" column flags what is genuinely new for AP versus already in place.

## Infrastructure dependencies (must exist before `fwd` starts)

| Dependency | Status for AP | Notes |
|---|---|---|
| Docker + Docker Compose | Likely present, must be installed if absent | Any host. No K3s required. |
| GitLab repo + CI runners | ✅ Exists | New repo at `gitlab.com/proofs.africa/fwd` |
| GitLab Container Registry | ✅ Exists | Image: `registry.gitlab.com/proofs.africa/fwd/fwd:<tag>` |
| Flare RPC | ✅ Exists | `ap-ftso-01:9650` (archive node, internal) |
| Songbird RPC | ✅ Exists | `ap-ftso-02:9650` (pruned node, internal) |
| Coston2 RPC | ✅ Public | `https://coston2-api.flare.network/ext/C/rpc` — outside AP's control, fine for spike + tests |
| **Scaleway Object Storage bucket** | ⚠️ Create one | New bucket for Litestream backups. ~€0/mo at AP volume. |

**Net-new operational surface:** one Scaleway Object Storage bucket. Nothing else.

Notably **NOT required:**
- AWS account
- GCP / Azure account
- K3s / Kubernetes
- Pulumi
- Postgres
- Redis
- Public DNS hostname (ClusterIP-equivalent — bound to `127.0.0.1`)
- TLS certificate from a public CA

## Containerized services (deployed by `fwd`'s `docker-compose.yml`)

| Service | Image (pinned) | Role |
|---|---|---|
| `vault` | `hashicorp/vault:<version-pinned>` | Custody + signing (Transit engine, ECDSA secp256k1) |
| `fwd` | `registry.gitlab.com/proofs.africa/fwd/fwd:<tag>` | The gateway service (FastAPI) |
| `litestream` | `litestream/litestream:<version-pinned>` | Continuous SQLite replication to S3-compatible storage |

All three deployed and managed by `docker-compose.yml`. Nothing manual to install on the host beyond Docker itself.

## Python runtime libraries (inside the `fwd` container)

| Library | Version constraint | Why |
|---|---|---|
| `fastapi` | `^0.115` | HTTP service framework |
| `uvicorn` | `^0.30` | ASGI server |
| `pydantic` | `^2.9` | Request/response validation (with FastAPI) |
| `pydantic-settings` | `^2.6` | Env var configuration |
| `httpx` | `^0.27` | Async HTTP — RPC + Vault |
| `hvac` | `^2.3` | HashiCorp Vault Python client (Transit-compatible) |
| `eth-account` | `^0.13` | EIP-1559 transaction encoding, RLP |
| `eth-utils` | `^5.0` | keccak256, address formatting, EIP-55 checksum |
| `coincurve` | `^20.0` | secp256k1 native bindings — for v-recovery (try both parities, match against known address) |
| `sqlalchemy` | `^2.0` | DB layer (async) |
| `aiosqlite` | `^0.20` | Async SQLite driver |
| `alembic` | `^1.13` | Schema migrations |
| `argon2-cffi` | `^23.1` | API key hashing (argon2id) |
| `pyyaml` | `^6.0` | Policy file loading |
| `structlog` | `^24.4` | JSON structured logging |
| `prometheus-client` | `^0.21` | Metrics (Phase 10, dependency present from start) |
| `tenacity` | `^9.0` | Retry policies for RPC calls |
| `typer` | `^0.16` | CLI framework |
| `rich` | `^13.9` | CLI rendering |

Notably **NOT present:**
- `web3.py` — too heavy, we don't need contract abstractions. `eth-account` + `httpx` cover the signing path with a fraction of the dependency tree.
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
| GPG keypair on YubiKey hardware token | Encrypting unseal shares for digital backup; PIN-protected | Verify or set up |
| Printer access | Paper backup of 2 of 5 unseal shares | Trivial |
| Off-site physical location | One paper share + one encrypted USB lives outside primary residence | Decide |
| Scaleway Object Storage IAM keys | Litestream → bucket credentials (read+write scoped to `s3://ap-fwd-backups/...`) | Generate at Phase 6 |
| Hardware wallet for identity rotation | Phase 8 `setClaimRecipient` transaction signed by identity address | Already in use by AP |

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
- **No public DNS / TLS cert** — ClusterIP-equivalent (`127.0.0.1` on host) only.
- **No `web3.py`** — `eth-account` is enough.
- **No external auth provider** (Auth0, Keycloak, etc.) — bearer API keys are the auth model in v1, mTLS is the Phase 10 option.
- **No service-mesh** (linkerd, Istio) — `fwd-internal` Docker network is the boundary.

## Honest summary

The only genuinely net-new operational dependency AP picks up by building `fwd` is **HashiCorp Vault running in Docker** (and a Scaleway bucket for state's backup). Everything else is either already operating, already in AP's standard stack, or trivially provisioned.

Compared to the AWS-KMS alternative, `fwd` adds *less* total dependency surface — it removes a cloud account at the cost of one extra container. Compared to the K3s alternative, `fwd` removes the K8s control-plane dependency at the cost of slightly weaker caller authentication (bearer keys vs SA tokens), with a documented Phase 10 mTLS upgrade path.

## Verification spike (Phase 1 risk retirement)

The Phase 1 spike retires three specific dependency assumptions:

1. **`hvac` against pinned Vault version** — confirm the Transit `sign` endpoint accepts `prehashed=true, marshaling_algorithm=asn1` and returns parseable DER signatures.
2. **`coincurve` v-recovery** — confirm `coincurve.PublicKey.from_signature_and_message` correctly recovers the public key for both parities, and matching against the address derived from `transit/keys/<name>` works.
3. **Coston2 RPC accepts our type-0x02 transactions** — confirm `eth_sendRawTransaction` with the encoded transaction succeeds and returns a valid hash.

If any of these fail, dependency selection revisits before Phase 2 begins.
