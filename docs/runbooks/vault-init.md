# Vault initialization runbook

> ⚠️ **RETIRED (v1.0.0a1) — DO NOT FOLLOW.** HashiCorp Vault was removed entirely
> (`decisions.md` D1); there is no Vault to initialize or unseal. Custody is a sealed
> local master — provision it with `clifwd master generate` (see README § Quickstart).
> This file is kept only as honest history of the Phase 3a–7 Vault model (Core
> invariant #18).

> First-run ritual to bring Vault from uninitialized → operational. Performed once per `fwd` deployment, after `docker compose up -d` brings the stack up. Subsequent restarts only require unseal (steps 4–5).
>
> **Per `decisions.md` D6: 5 unseal shares, threshold 3, distributed as 2 paper + 3 GPG-encrypted across 5 distinct failure domains.** The operator is responsible for placing each share in its planned location BEFORE proceeding past step 3.

## Prerequisites

- `docker compose up -d` has succeeded; `fwd-vault`, `fwd`, `fwd-litestream` are all running.
- `docker exec fwd-vault vault status` shows `Initialized: false`, `Sealed: true`.
- The operator has decided on the share-distribution plan per D6 (paper locations + GPG keypair location).
- The operator has GPG installed locally and a working YubiKey (or equivalent) with the GPG private key.

## Steps

### 1. Initialize Vault (Shamir 3-of-5)

```sh
docker exec fwd-vault vault operator init \
    -key-shares=5 \
    -key-threshold=3 \
    -format=json \
    > /tmp/vault-init-output.json
```

This produces `/tmp/vault-init-output.json` containing `unseal_keys_b64` (5 shares), `unseal_keys_hex`, `recovery_keys_*` (empty for Shamir), and `root_token`. **THIS FILE CONTAINS THE KEYS TO EVERYTHING — handle it like a private key.**

### 2. Distribute the unseal shares

Per `decisions.md` D6, the 5 shares go to 5 distinct locations:

| Share | Location | Format |
|---|---|---|
| 1 | Primary residence, fire-resistant safe | Printed paper |
| 2 | Secondary off-site location | Printed paper |
| 3 | `apafricaresearch/secrets/vault-share-3.gpg` | GPG-encrypted to YubiKey |
| 4 | `~/.fwd/share-4.gpg` (operator's primary laptop) | GPG-encrypted to YubiKey |
| 5 | USB drive at the secondary off-site location | GPG-encrypted to YubiKey |

For each share:

```sh
# Paper:
echo "<unseal_keys_b64[N]>" | enscript --header= -o - | lpr

# GPG-encrypted:
echo "<unseal_keys_b64[N]>" | gpg --encrypt --armor --recipient <gpg-key-id> > /path/to/destination.gpg
```

After ALL 5 shares are placed in their planned locations:

```sh
shred -u /tmp/vault-init-output.json
```

(The root token still lives in your shell history at this point; capture it from history NOW for step 6, then clear shell history.)

### 3. Verify share recoverability

Decrypt each GPG-encrypted share and confirm the contents match what was written. Read the paper shares and confirm legibility. **Do this BEFORE step 4 — once Vault is unsealed, mistakes become harder to recover from.**

### 4. Unseal Vault

Provide 3 of the 5 shares. Each `unseal` call advances the threshold by 1.

```sh
docker exec -it fwd-vault vault operator unseal
# (paste share 1)
docker exec -it fwd-vault vault operator unseal
# (paste share 2)
docker exec -it fwd-vault vault operator unseal
# (paste share 3 — Sealed: false after this)
```

Confirm: `docker exec fwd-vault vault status` shows `Initialized: true`, `Sealed: false`.

### 5. Run the post-unseal init script

```sh
docker exec -e VAULT_TOKEN=<root-token-from-step-1> fwd-vault /vault/scripts/vault-init.sh
```

The script is idempotent. Output ends with:

```
==================================================================
  fwd Vault initialization complete.

  Add these to your .env file (replacing any prior values):

    FWD_VAULT_ROLE_ID=<role-id>
    FWD_VAULT_SECRET_ID=<secret-id>
  ...
==================================================================
```

The extended script (v0.4.2+) creates BOTH the `fwd` AppRole (for the
daemon's encrypt/decrypt operations) AND the `fwd-snapshot` AppRole (for
the periodic vault-snapshot sidecar). Both `role_id` + `secret_id` pairs
are printed at the end for `.env` capture.

### 6. Update `.env` and restart fwd

Add the role_id and secret_id pairs to `.env` (which is gitignored):

```
FWD_VAULT_ROLE_ID=<from script output>
FWD_VAULT_SECRET_ID=<from script output>
FWD_VAULT_SNAPSHOT_ROLE_ID=<from script output>
FWD_VAULT_SNAPSHOT_SECRET_ID=<from script output>
```

Then:

```sh
docker compose restart fwd vault-snapshot
```

### 7. Verify fwd authenticates against Vault

Phase 3b ships the actual Vault client; for v0.3.0a1, this verification is manual using the Vault CLI:

```sh
# From the host:
docker exec fwd-vault vault read auth/approle/role/fwd
docker exec fwd-vault vault list auth/approle/role/fwd/secret-id
docker exec fwd-vault vault policy read fwd-app
docker exec fwd-vault vault read transit/keys/fwd-master
```

All four should return data without errors.

### 8. Revoke the root token (Phase 3.5)

After Phase 3b's `EnvelopeSigner` and `clifwd wallets create` are working end-to-end, revoke the root token:

```sh
docker exec fwd-vault vault token revoke <root-token>
```

From this point, fwd authenticates via AppRole only. There is no path back to root-level Vault access without going through the unseal process again (and the root token is generated anew via `vault operator generate-root` if needed).

## Subsequent restarts

After any `docker compose down` or host reboot, Vault returns to sealed state. The operator must unseal it again (step 4 only — the rest of the init state is persisted in the `vault-data` volume).

```sh
docker exec -it fwd-vault vault operator unseal  # × 3
docker compose restart fwd                        # so fwd re-authenticates
```

Auto-unseal is a Phase 10 deliverable (Vault transit-seal via a second tiny Vault, or a YubiHSM 2 PKCS#11 backend). v1 is manual.

## What this runbook deliberately does NOT cover

- **Share recovery procedures.** If you lose 3+ shares, fwd is dead — the keys cannot be decrypted. There is no recovery. This is by design; the alternative (a backdoor) defeats the threshold model.
- **Re-keying.** Vault supports `vault operator rekey` to issue new unseal shares with a new threshold. Documented separately when needed.
- **Migration to YubiHSM 2 / Vault Enterprise / cloud KMS.** Phase 10 considerations, not v1.

## When this runbook is wrong

- A `vault` CLI flag or argument changes — update the affected step.
- The init script changes (`scripts/vault-init.sh`) — update step 5's expected output.
- Auto-unseal lands in Phase 10 — replace step 4 with the auto-unseal procedure.
