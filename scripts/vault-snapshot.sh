#!/bin/sh
# scripts/vault-snapshot.sh — periodic Vault Raft snapshot + S3 upload.
#
# Runs as PID 1 inside the vault-snapshot sidecar (see docker-compose.yml).
# Loops forever; on each iteration: login via AppRole, take a Raft snapshot,
# upload to Scaleway Object Storage, rotate old snapshots, sleep.
#
# All errors in a single iteration are logged and the loop continues —
# snapshot is best-effort by design (Litestream covers the SQLite RPO; this
# loop covers Vault state which only changes on wallet/caller create).
#
# Required env (from .env via docker-compose env_file):
#   VAULT_ADDR                       — set inline in compose to http://vault:8200
#   FWD_VAULT_SNAPSHOT_ROLE_ID       — from vault-init.sh (extended) Step 11
#   FWD_VAULT_SNAPSHOT_SECRET_ID     — from vault-init.sh (extended) Step 12
#   LITESTREAM_S3_ENDPOINT           — reused (same bucket as state.db)
#   LITESTREAM_S3_BUCKET
#   LITESTREAM_S3_REGION
#   LITESTREAM_S3_ACCESS_KEY_ID
#   LITESTREAM_S3_SECRET_ACCESS_KEY
#
# Optional env (defaults shown):
#   VAULT_SNAPSHOT_S3_PATH=vault-snapshots
#   VAULT_SNAPSHOT_INTERVAL_SEC=86400
#   VAULT_SNAPSHOT_RETENTION_COUNT=7

set -u

INTERVAL="${VAULT_SNAPSHOT_INTERVAL_SEC:-86400}"
PREFIX="${VAULT_SNAPSHOT_S3_PATH:-vault-snapshots}"
KEEP="${VAULT_SNAPSHOT_RETENTION_COUNT:-7}"

# aws-cli reads AWS_* env vars. Map from LITESTREAM_S3_* for credential reuse.
export AWS_ACCESS_KEY_ID="${LITESTREAM_S3_ACCESS_KEY_ID}"
export AWS_SECRET_ACCESS_KEY="${LITESTREAM_S3_SECRET_ACCESS_KEY}"
export AWS_DEFAULT_REGION="${LITESTREAM_S3_REGION}"

log() {
    printf '%s vault-snapshot: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

run_once() {
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    snapshot="/tmp/vault-${ts}.snap"

    # 1. Login via AppRole (fwd-snapshot role — see config/vault/policies/fwd-snapshot.hcl).
    token=$(vault write -field=token \
        auth/approle/login \
        role_id="${FWD_VAULT_SNAPSHOT_ROLE_ID}" \
        secret_id="${FWD_VAULT_SNAPSHOT_SECRET_ID}" 2>&1) || {
        log "FAILED at login: ${token}"
        return 1
    }
    export VAULT_TOKEN="${token}"

    # 2. Save snapshot (raft storage, gzip'd tarball at the Vault end).
    if ! vault operator raft snapshot save "${snapshot}" 2>&1; then
        log "FAILED at snapshot save"
        rm -f "${snapshot}"
        return 2
    fi

    # 3. Upload to S3 with a timestamped key.
    if ! aws --endpoint-url "${LITESTREAM_S3_ENDPOINT}" \
            s3 cp "${snapshot}" \
            "s3://${LITESTREAM_S3_BUCKET}/${PREFIX}/vault-${ts}.snap" 2>&1; then
        log "FAILED at s3 cp"
        rm -f "${snapshot}"
        return 3
    fi

    # 4. Rotate: list snapshots, keep newest KEEP, delete the rest.
    listing=$(aws --endpoint-url "${LITESTREAM_S3_ENDPOINT}" \
        s3 ls "s3://${LITESTREAM_S3_BUCKET}/${PREFIX}/" 2>&1 \
        | awk '{print $4}' \
        | grep -E '^vault-[0-9]{8}T[0-9]{6}Z\.snap$' \
        | sort) || listing=""

    count=$(printf '%s\n' "${listing}" | grep -c . || true)
    if [ "${count}" -gt "${KEEP}" ]; then
        delete_count=$((count - KEEP))
        printf '%s\n' "${listing}" | head -n "${delete_count}" | while IFS= read -r name; do
            [ -z "${name}" ] && continue
            aws --endpoint-url "${LITESTREAM_S3_ENDPOINT}" \
                s3 rm "s3://${LITESTREAM_S3_BUCKET}/${PREFIX}/${name}" \
                >/dev/null 2>&1 || log "WARN: failed to delete ${name}"
        done
        log "rotated: kept newest ${KEEP}, deleted ${delete_count}"
    fi

    # 5. Cleanup.
    rm -f "${snapshot}"
    vault token revoke -self >/dev/null 2>&1 || true
    return 0
}

log "starting (interval=${INTERVAL}s, prefix=${PREFIX}, retention=${KEEP})"

while true; do
    if run_once; then
        log "ok"
    else
        rc=$?
        log "FAILED iteration (rc=${rc}); continuing"
    fi
    sleep "${INTERVAL}"
done
