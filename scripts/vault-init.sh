#!/bin/sh
# scripts/vault-init.sh — fwd Vault post-unseal initialization.
#
# Run inside the fwd-vault container, AFTER `vault operator init` and
# `vault operator unseal` × 3 (Shamir threshold reached). The runbook at
# docs/runbooks/vault-init.md walks the operator through the full ritual.
#
# Invocation:
#   docker exec -e VAULT_TOKEN=<root-token> fwd-vault /vault/scripts/vault-init.sh
#
# This script is idempotent: re-running it on an already-initialized Vault
# is safe — it skips already-enabled engines and existing keys.

set -e

if [ -z "$VAULT_TOKEN" ]; then
    echo "ERROR: VAULT_TOKEN env var must be set." >&2
    echo "Use the root token from 'vault operator init -format=json'." >&2
    exit 1
fi

echo "fwd vault-init: starting"

# 1. Enable the Transit secrets engine (idempotent).
if vault secrets list -format=json | grep -q '"transit/"'; then
    echo "[OK]   transit/ engine already enabled"
else
    vault secrets enable transit
    echo "[NEW]  transit/ engine enabled"
fi

# 2. Create the master encryption key (idempotent).
if vault read transit/keys/fwd-master >/dev/null 2>&1; then
    echo "[OK]   transit/keys/fwd-master already exists"
else
    vault write -f transit/keys/fwd-master \
        type=aes256-gcm96 \
        exportable=false \
        allow_plaintext_backup=false
    echo "[NEW]  transit/keys/fwd-master created (aes256-gcm96, exportable=false)"
fi

# 3. Write the fwd-app policy.
vault policy write fwd-app /vault/config/policies/fwd-app.hcl
echo "[OK]   fwd-app policy written"

# 4. Enable the AppRole auth method (idempotent).
if vault auth list -format=json | grep -q '"approle/"'; then
    echo "[OK]   approle auth already enabled"
else
    vault auth enable approle
    echo "[NEW]  approle auth enabled"
fi

# 5. Create or update the fwd role bound to the fwd-app policy.
vault write auth/approle/role/fwd \
    token_policies=fwd-app \
    token_ttl=24h \
    token_max_ttl=72h \
    secret_id_ttl=0 \
    secret_id_num_uses=0 \
    >/dev/null
echo "[OK]   auth/approle/role/fwd configured (token_ttl=24h, secret_id non-expiring)"

# 6. Read role_id (stable per role).
ROLE_ID=$(vault read -format=json auth/approle/role/fwd/role-id | sed -n 's/.*"role_id" *: *"\([^"]*\)".*/\1/p')

# 7. Generate a fresh secret_id (each call returns a new one).
SECRET_ID=$(vault write -f -format=json auth/approle/role/fwd/secret-id | sed -n 's/.*"secret_id" *: *"\([^"]*\)".*/\1/p')

if [ -z "$ROLE_ID" ] || [ -z "$SECRET_ID" ]; then
    echo "ERROR: failed to read role_id or secret_id" >&2
    exit 2
fi

# 8. Print results for operator capture.
cat <<EOF

==================================================================
  fwd Vault initialization complete.

  Add these to your .env file (replacing any prior values):

    FWD_VAULT_ROLE_ID=$ROLE_ID
    FWD_VAULT_SECRET_ID=$SECRET_ID

  Then: docker compose restart fwd

  Phase 3.5: revoke the root token after confirming fwd authenticates.
    docker exec fwd-vault vault token revoke <root-token>
==================================================================
EOF
