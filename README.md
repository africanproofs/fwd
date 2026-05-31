# fwd — Flare Wallet Daemon

Policy-gated, **zero-egress, sign-only** signing service for a Flare FTSO
provider's EVM backend keys (Flare, Songbird, Coston2). It replaces every
`.env PRIVATE_KEY` across an operator's automation with one HTTP endpoint, one
sealed custody backend, and one tamper-evident audit log — and it **never
connects to the internet**. Each provider runs their own single-host stack
(`curl -sfL https://get.proofs.africa/fwd | sh -`); see
`docs/one-command-install.md`.

> **Status: production-deployed**, proven on Coston2 + Flare/Songbird mainnet. fwd
> **signs** EVM transactions and Flare FSP protocol messages; it does **not** broadcast
> and makes **no outbound network connection**. Clients broadcast the signed payload
> themselves and report the outcome back. Custody is a sealed local master
> (AES-256-GCM, mode-0600 host file).

## What fwd is

`fwd` is what [`keosd`](https://github.com/AntelopeIO/spring/tree/main/programs/keosd)
would look like if it were redesigned for autonomous agents on Flare in 2026. It
holds the operator's automation private keys AES-256-GCM-sealed under a 32-byte master key (a
mode-0600 host file), decrypts a key only for the bounded duration of a single
signing operation, and zeroizes it immediately after. Four things `keosd` does not do
that `fwd` does:

1. **Decode intent.** Every `sign-transaction` request is ABI-decoded against the
   policy-bound contract; every `sign-fsp-message` request reconstructs the FSP
   `messageHash` from typed fields. Opaque caller-supplied digests are refused.
2. **Default-deny policy.** Per-caller allowlists of
   `(wallet × contract × method × max_value × rate)`. Compromise of one caller key is
   bounded by its policy, not by the wallet's balance.
3. **Tamper-evident audit log.** Every signing request, decision, signature, and
   reported outcome is hash-chained (`prev_hash` → `row_hash`) and replayable.
4. **Zero egress.** fwd has no RPC client and no network route to the internet. It
   signs and allocates nonces locally; the **client** broadcasts and reports back.

State is SQLite + a Litestream sidecar replicating to a **local** backup volume (no
cloud egress). Deployment is `docker compose up`. See
[`docs/architecture.md`](docs/architecture.md) for the full design and
[`docs/decisions.md`](docs/decisions.md) D1 (custody pivot) + D20 (zero-egress).

## How it works — sign, then the client broadcasts

fwd never touches the chain. The client owns broadcasting and feeds the outcome back
so fwd can keep its nonce ledger and audit log coherent:

```
  client                              fwd (no egress)                 chain
    │  POST /v1/sign-transaction  ───────▶ decode intent, check policy,
    │                                      reserve nonce, sign, audit
    │  ◀── signed_raw_tx + tx_id ──────────┘
    │  eth_sendRawTransaction ─────────────────────────────────────────▶
    │  POST /v1/transactions/{tx_id}/broadcast-result ──▶ record accepted/rejected
    │  (poll receipt) ◀────────────────────────────────────────────────
    │  POST /v1/transactions/{tx_id}/receipt ──────────▶ record mined/reverted
```

- fwd attaches to a Docker network with **`internal: true`** — no route to the
  internet, and (a consequence) **no host port**: you cannot `curl` it from the host.
  Admin runs via `docker exec fwd clifwd …`; callers reach it intra-network at
  `http://fwd:8080`.
- A caller container must be **dual-homed**: on fwd's internal network (to call fwd)
  **and** on its own egress network (to broadcast to an RPC it owns).
- **Use the shared client library** — don't hand-roll the loop:
  [`gitlab.com/proofs.africa/fwd-client`](https://gitlab.com/proofs.africa/fwd-client)
  (public). The reward claimer / FSP client `clif` already depends on it.

## Quickstart

Prerequisites: **Docker + Compose v2**. For local development and the `clifwd` CLI
locally: **Python 3.12 + Poetry ≥ 1.8**.

### 1. Provision the sealed master key

The master key never lives in the repo or image — you generate it on the host:

`master generate` runs **in-process** (it does not need the daemon), so generate the
key *before* the container starts — the container won't boot without it. With the CLI
installed locally:

```bash
clifwd master generate --out config/master.key   # writes a 32-byte key, mode 0600
```

Docker-only host (no local Python)? Run the same command inside the image — it
overrides the daemon entrypoint and writes to the bind-mounted host path:

```bash
docker run --rm -v "$PWD/config:/config" \
  registry.gitlab.com/proofs.africa/fwd/fwd:${FWD_IMAGE_TAG:-dev} \
  clifwd master generate --out /config/master.key
```

It refuses to overwrite an existing file. This file is `policy.yaml`-class private
config: gitignored, operator-provisioned, bind-mounted into the container. Back it up
out-of-band — losing it means re-sealing every wallet.

### 2. Configure

```bash
cp .env.example .env
# Edit .env: set FWD_ADMIN_KEY to a random ≥32-char string; set gas caps if desired.
cp docs/policy.example.yaml config/policy.yaml   # then edit for your callers/wallets
```

`config/policy.yaml` is operator-controlled, gitignored, and bind-mounted. Create the
file before `docker compose up` — with the compose bind mount, a missing path can be
created as a *directory* and fail confusingly.

### 3. Bring up the daemon

```bash
docker compose up -d
docker exec fwd clifwd health          # → master ok / fwd ok  (NO `rpc` field — zero egress)
```

There is **no host port** (`internal: true`), so probe and administer fwd from inside
the container with `docker exec fwd clifwd …`, not from the host.

### 4. Create a wallet (fwd generates + seals the key)

```bash
docker exec fwd clifwd wallets create --name clif-claimer-flr-prod --policy <policy-path>
docker exec fwd clifwd wallets list
```

### 5. Mint a caller API key

```bash
docker exec fwd clifwd callers create --name clif --policy <policy-path>
# Prints the bearer API key ONCE — capture it into the caller's secret config now.
```

### 6. Seed the nonce

fwd can't read the chain, so the operator seeds the starting nonce once per
(wallet, chain) from on-chain truth:

```bash
docker exec fwd clifwd nonce init --wallet clif-claimer-flr-prod --chain 14 --starting-nonce <N>
```

### 7. Sign → broadcast → report back (client side)

Via `fwd-client` (recommended) or directly:

```
POST /v1/sign-transaction            # → { tx_id, hash, signed_raw_tx, nonce }
  ── client broadcasts signed_raw_tx itself (hash is the tx_hash to report back) ──
POST /v1/transactions/{tx_id}/broadcast-result   # outcome: accepted | rejected_*
  ── client polls the chain ──
POST /v1/transactions/{tx_id}/receipt            # outcome: mined_success | mined_reverted
```

Stuck transaction? `POST /v1/transactions/{tx_id}/sign-replacement` re-signs the same
intent at the same nonce with bumped fees. Flare protocol (FSP) signing uses
`POST /v1/sign-fsp-message` (UPTIME / REWARD_DISTRIBUTION) — fwd reconstructs the
EIP-191 `messageHash` from typed fields; you supply no digest.

## HTTP API

Auth: **caller** = the bearer API key minted in step 5; **admin** = `FWD_ADMIN_KEY`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | none | Liveness + sealed-master readiness |
| `POST` | `/v1/sign-transaction` | caller | Sign an ABI-decoded EVM tx — returns `{ tx_id, hash, signed_raw_tx, nonce }`; client broadcasts |
| `POST` | `/v1/sign-fsp-message` | caller | Sign an EIP-191 FSP message (`UPTIME` or `REWARD_DISTRIBUTION`) |
| `GET` | `/v1/transactions/{tx_id}` | caller | Look up a signed tx's lifecycle status |
| `POST` | `/v1/transactions/{tx_id}/broadcast-result` | caller | Report broadcast outcome (`accepted` / `rejected_releaseable` / `rejected_nonce_too_low`) |
| `POST` | `/v1/transactions/{tx_id}/receipt` | caller | Report on-chain receipt (`mined_success` / `mined_reverted` + block) |
| `POST` | `/v1/transactions/{tx_id}/sign-replacement` | caller | Re-sign same intent + nonce with new gas/fees (stuck-tx replacement) |
| `POST` | `/v1/admin/wallets` | admin | Create a wallet (fwd generates + seals the key) |
| `GET` | `/v1/admin/wallets` | admin | List wallets (no secret material) |
| `POST` | `/v1/admin/callers` | admin | Create a caller (API key returned once) |
| `GET` | `/v1/admin/callers` | admin | List callers (active + revoked) |
| `DELETE` | `/v1/admin/callers/{name}` | admin | Revoke a caller's API key |
| `POST` | `/v1/admin/nonce-init` | admin | Seed the starting nonce for a (wallet, chain) |
| `POST` | `/v1/admin/nonce-sync` | admin | Bounded-monotonic advance of fwd's nonce to operator-supplied on-chain truth |
| `GET` | `/v1/admin/nonce/holes` | admin | Surface stale/orphaned pending reservations for operator alarm |

`sign-transaction` body: `wallet`, `chain`, `to`, `value_wei`, `data`, `gas`,
`max_fee_per_gas`, `max_priority_fee_per_gas` (+ optional `Idempotency-Key` header).
`sign-fsp-message` body: `wallet`, `message_type`, `reward_epoch_id`; for
`REWARD_DISTRIBUTION` also `chain_id`, `no_of_weight_based_claims`, `rewards_hash`.

## CLI — `clifwd`

Run admin commands inside the container (`docker exec fwd clifwd …`). HTTP commands
need `FWD_ADMIN_KEY` (and `FWD_URL`, default `http://127.0.0.1:8080`); in-process
commands (`master generate`, `wallets import`, `audit *`, `fsp scope`) do not.

| Command | Purpose |
|---|---|
| `clifwd version` | Print the fwd version |
| `clifwd health` | Probe `/healthz` |
| `clifwd master generate --out PATH` | Generate the 32-byte sealed master (0600; refuses overwrite) |
| `clifwd wallets create --name … --policy …` | Create a wallet (fwd generates + seals) |
| `clifwd wallets import --name … --privkey-file … --policy …` | Import an existing key (optionally shreds the source file with `--shred-source`) |
| `clifwd wallets list` | List wallets |
| `clifwd callers create --name … --policy …` | Mint a caller API key (printed once) |
| `clifwd callers list` | List callers |
| `clifwd callers revoke --name …` | Revoke a caller key |
| `clifwd nonce init --wallet … --chain … --starting-nonce …` | Seed a (wallet, chain) nonce |
| `clifwd audit verify` / `show SEQ` / `tail -n N` | Walk / inspect the hash-chained audit log |
| `clifwd fsp scope --caller … --wallet … --policy-path … --message-types …` | Print the FSP policy stanza (read-only helper) |

## Configuration

All operator-facing config flows through `.env` (gitignored) + the bind-mounted
`policy.yaml` and `master.key`. See [`.env.example`](.env.example) for the annotated
list.

| Variable | Purpose |
|---|---|
| `FWD_IMAGE_TAG` | fwd container image tag (default `dev`; CI sets a versioned tag) |
| `FWD_MASTER_KEY_FILE` | Path to the 32-byte sealed master (mode 0600; bind-mounted) |
| `FWD_ADMIN_KEY` | Bearer key for `/v1/admin/*` (random ≥32 chars in production) |
| `FWD_POLICY_PATH` | Path to the YAML policy file (operator-controlled, bind-mounted) |
| `FWD_ABIS_DIR` | ABI registry directory (ships in the image) |
| `FWD_MAX_GAS` / `FWD_MAX_FEE_PER_GAS` | Zero-egress sanity caps on client-supplied gas/fees |
| `FWD_NONCE_SYNC_MAX_ADVANCE` | Max monotonic jump `nonce-sync` will accept |
| `FWD_RESERVATION_LEASE_SEC` | Age after which a pending reservation is a "hole" |
| `DATABASE_URL` | SQLite path for the daemon + Alembic migrations (no `FWD_` prefix — this is the one setting field without the `fwd_` prefix) |
| `FWD_LOG_LEVEL` | `DEBUG` / `INFO` / `WARNING` / `ERROR` (default `INFO`) |
| `FWD_DISABLE_MLOCK` | Set `1` only in dev/test to skip `mlockall` |
| `FWD_URL` | CLI-side: the daemon URL `clifwd` HTTP commands target |

## Custody model

Each wallet's secp256k1 private key is envelope-encrypted with AES-256-GCM under a
32-byte master held in a **mode-0600 host file** (`seal:v1:…` ciphertext in SQLite),
decrypted only during a bounded signing operation, then zeroized; process memory is
`mlockall`-locked against swap. The custody backend is proportionate to the asset
class — low-value Flare automation keys on a host that is never publicly exposed.
Rationale + threat model: [`docs/decisions.md`](docs/decisions.md) and
[`docs/threat-model.md`](docs/threat-model.md).

## What fwd is NOT

See [`CLAUDE.md`](CLAUDE.md) § "What FWD Deliberately IS NOT" for the binding policy.
Briefly:

- **Not a broadcaster.** fwd signs + allocates nonces; **clients broadcast** and
  report back. fwd never calls `eth_sendRawTransaction`.
- **No network egress at all, no host port.** `internal: true` blocks the internet
  route and removes host→container publishing. Inbound-only from callers; admin via
  `docker exec`. No `signer.proofs.africa` DNS.
- **Not a user wallet.** Frontends keep thirdweb v5. fwd is backend automation only.
- **Not multi-chain beyond EVM Flare-family** (Flare/Songbird/Coston2).
- **Not clustered / HA / scalable.** One container, one wallet set, one nonce manager
  per (wallet, chain). Restart on failure, not failover.
- **No K8s, no Pulumi, no Helm.** `docker-compose.yml` is the deployment artifact.
- **No raw-digest signing.** Only `/v1/sign-transaction` and `/v1/sign-fsp-message`
  are mounted; arbitrary `eth_sign`-style endpoints will never exist.
- **No autonomous policy.** Every rule is declarative YAML; the LLM never decides
  whether to sign.
- **No long-lived human-issued credentials.** Caller API keys are minted by fwd,
  scoped per policy, and rotatable from the CLI.

## Documentation

| Document | Purpose |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Operating doctrine + Core invariants for agents and humans |
| [`docs/architecture.md`](docs/architecture.md) | Components, trust boundaries, signing flow, schema, API |
| [`docs/decisions.md`](docs/decisions.md) | Architectural decisions and rationale (append-only log) |
| [`docs/threat-model.md`](docs/threat-model.md) | Attack-surface analysis, mitigations, residual risk |
| [`docs/dependencies.md`](docs/dependencies.md) | Infrastructure, services, libraries, operator prerequisites |
| [`docs/implementation-plan.md`](docs/implementation-plan.md) | Phased build-out record |
| [`docs/history/`](docs/history/) | Per-version ship records ([`SHIP-LOG.md`](docs/history/SHIP-LOG.md) + index) |

## Provenance

- **Custody:** sealed local master (AES-256-GCM, 32-byte mode-0600 host file);
  signing in-process with `eth-account` post-decrypt.
- **Role:** `keosd` (Antelope/EOSIO) is the lineage; `fwd` is the redesign — intent
  decoding, default-deny policy, hash-chained audit, EVM-native + FSP signing, and
  zero egress are what `fwd` adds.
- **Workflow doctrine:** inherited from `ficsm` — Opus prescribes, Sonnet implements
  with deviation license, Opus reviews with overwrite authority, Operator drives +
  gates.
