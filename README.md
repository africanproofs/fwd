# fwd — Flare Wallet Daemon

Policy-gated signing service for African Proofs' EVM backend keys (Flare, Songbird, Coston2). Replaces every `.env PRIVATE_KEY` across AP automation with one HTTP endpoint, one custody backend, and one tamper-evident audit log.

> **Status: v0.3.0-alpha — Project scaffold landed (+ one validated spike on Coston2).** v0.1.0–v0.2.3 documented the architecture; v0.2.0 validated the signing flow with a real Coston2 transaction; v0.3.0-alpha lands the runnable-but-inert scaffold (pyproject.toml, Dockerfile, docker-compose with three services, src/fwd/ four-layer skeleton, tests, alembic, CI). Phase 3 (Vault deployment + signing core) is the next ship.

## What this repo is

`fwd` is what [`keosd`](https://github.com/AntelopeIO/spring/tree/main/programs/keosd) would look like if it were redesigned for autonomous agents on Flare in 2026. Three things `keosd` does not do that `fwd` does:

1. **Decode intent.** Every signing request is parsed against an ABI; opaque bytes are refused.
2. **Default-deny policy.** Per-caller allowlists of `(contract × method × max_value × rate)`. Compromise of one caller is bounded by its policy, not by the wallet's balance.
3. **Tamper-evident audit log.** Every request, decision, and signature is hash-chained and replayable.

Custody is HashiCorp Vault Transit (`aes256-gcm96`, `exportable=false`) running in the same Docker host as an envelope-encryption layer for externally-generated secp256k1 private keys; signing happens in `fwd`'s own process post-decrypt. Plaintext keys exist in memory only during the bounded signing operation. State is SQLite + Litestream replicating to Scaleway Object Storage. Deployment is `docker compose up`. See `docs/architecture.md` for the full design and `docs/decisions.md` D1 for the v0.1.2 architectural pivot.

## What this repo is NOT

See `CLAUDE.md` § "What FWD Deliberately IS NOT" for the hard policy. Briefly:

- Not a user wallet (frontends keep thirdweb v5).
- Not multi-chain except EVM (Flare/Songbird/Coston2).
- Not clustered, not HA, not horizontally scalable.
- No K8s, no Pulumi, no public network exposure in v1.
- No autonomous policy decisions — every rule is declarative YAML.

## Setup

Local development:

```bash
# Prerequisites: Python 3.12, Poetry ≥ 1.8, Docker + Docker Compose v2.
poetry install
poetry run pytest                    # unit tests
poetry run ruff check .              # lint
poetry run mypy --strict src/        # type-check

# Bring up the compose stack:
cp .env.example .env
docker compose up -d
curl http://127.0.0.1:8080/healthz
poetry run clifwd health             # equivalent CLI probe
```

Phase 2 ships an inert scaffold — Vault is uninitialized, no wallets are provisioned, no signing path is wired. Phase 3 lands `vault operator init`, AppRole auth, and `/v1/sign-and-send` against Coston2.

## Documentation

| Document | Purpose |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Operating doctrine for agents and humans |
| [`docs/architecture.md`](docs/architecture.md) | Components, trust boundaries, signing flow, schema, API |
| [`docs/decisions.md`](docs/decisions.md) | Architectural decisions and alternatives considered |
| [`docs/threat-model.md`](docs/threat-model.md) | Attack-surface analysis with mitigations and residual risk |
| [`docs/implementation-plan.md`](docs/implementation-plan.md) | 10-phase roadmap with explicit gates |
| [`docs/dependencies.md`](docs/dependencies.md) | Infrastructure, services, Python libraries, operator prerequisites |
| [`docs/operator-runbook.md`](docs/operator-runbook.md) | Bring-up, unseal, restore, migration (fills as we operate) |

## Provenance

- Custody pattern: HashiCorp Vault Transit engine as envelope-encryption (`aes256-gcm96`); signing in-process with `eth-account` post-decrypt. (See `docs/decisions.md` D1 for v0.1.2 pivot.)
- Workflow doctrine: inherited verbatim from [`../ficsm/CLAUDE.md`](../ficsm/CLAUDE.md) — Opus prescribes, Sonnet implements with deviation license, Opus reviews with overwrite authority, Operator drives + gates.
- Lineage: `keosd` (Antelope/EOSIO) is the role; `fwd` is the redesign.
