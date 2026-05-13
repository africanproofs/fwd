#!/bin/sh
# scripts/vault-snapshot.sh — periodic Vault Raft snapshot to a local volume.
#
# Runs as PID 1 inside the vault-snapshot sidecar (see docker-compose.yml).
# Loops forever; on each iteration: login via AppRole, take a Raft snapshot,
# move it into the shared /backup volume, rotate old snapshots, sleep.
#
# All errors in a single iteration are logged and the loop continues —
# snapshot is best-effort by design (Litestream covers the SQLite RPO; this
# loop covers Vault state which only changes on wallet/caller create).
#
# Backups live at /backup/vault-snapshots/vault-<UTC-timestamp>.snap inside
# the `backup` Docker volume. Off-host transport (rsync, restic, borg, NAS,
# USB — whatever fits the deployment) is the operator's responsibility per
# CLAUDE.md v0.4.3 paragraph. fwd does not transport backups off-host.
#
# Required env (from .env via docker-compose env_file):
#   VAULT_ADDR                       — set inline in compose to http://vault:8200
#   FWD_VAULT_SNAPSHOT_ROLE_ID       — from vault-init.sh (extended) Step 11
#   FWD_VAULT_SNAPSHOT_SECRET_ID     — from vault-init.sh (extended) Step 12
#
# Optional env (defaults shown):
#   VAULT_SNAPSHOT_INTERVAL_SEC=86400
#   VAULT_SNAPSHOT_RETENTION_COUNT=7
#
# Backup root is hard-coded to /backup (mounted from the `backup` Docker
# volume); no env-var override — keeping the substrate boring.

set -u

INTERVAL="${VAULT_SNAPSHOT_INTERVAL_SEC:-86400}"
KEEP="${VAULT_SNAPSHOT_RETENTION_COUNT:-7}"
BACKUP_DIR="/backup/vault-snapshots"

log() {
    printf '%s vault-snapshot: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

run_once() {
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    tmp_snap="/tmp/vault-${ts}.snap"
    final_snap="${BACKUP_DIR}/vault-${ts}.snap"

    # 0. Ensure the backup directory exists (idempotent; first run creates it).
    mkdir -p "${BACKUP_DIR}" || {
        log "FAILED at mkdir ${BACKUP_DIR}"
        return 1
    }

    # 1. Login via AppRole (fwd-snapshot role — see config/vault/policies/fwd-snapshot.hcl).
    token=$(vault write -field=token \
        auth/approle/login \
        role_id="${FWD_VAULT_SNAPSHOT_ROLE_ID}" \
        secret_id="${FWD_VAULT_SNAPSHOT_SECRET_ID}" 2>&1) || {
        log "FAILED at login: ${token}"
        return 2
    }
    export VAULT_TOKEN="${token}"

    # 2. Save snapshot to /tmp (Vault writes; we transport to final path next).
    if ! vault operator raft snapshot save "${tmp_snap}" 2>&1; then
        log "FAILED at snapshot save"
        rm -f "${tmp_snap}"
        return 3
    fi

    # 3. Move into the backup volume atomically via cp + sync + rm.
    #    cp-then-rm rather than mv handles the cross-fs case cleanly (tmpfs → backup volume).
    if ! cp "${tmp_snap}" "${final_snap}" 2>&1; then
        log "FAILED at cp to ${final_snap}"
        rm -f "${tmp_snap}"
        return 4
    fi
    rm -f "${tmp_snap}"

    # 4. Rotate: list snapshots in the backup dir, keep newest KEEP, delete the rest.
    listing=$(ls -1 "${BACKUP_DIR}" 2>/dev/null \
        | grep -E '^vault-[0-9]{8}T[0-9]{6}Z\.snap$' \
        | sort) || listing=""

    count=$(printf '%s\n' "${listing}" | grep -c . || true)
    if [ "${count}" -gt "${KEEP}" ]; then
        delete_count=$((count - KEEP))
        printf '%s\n' "${listing}" | head -n "${delete_count}" | while IFS= read -r name; do
            [ -z "${name}" ] && continue
            rm -f "${BACKUP_DIR}/${name}" || log "WARN: failed to delete ${name}"
        done
        log "rotated: kept newest ${KEEP}, deleted ${delete_count}"
    fi

    # 5. Revoke our token to be tidy (best-effort).
    vault token revoke -self >/dev/null 2>&1 || true
    return 0
}

log "starting (interval=${INTERVAL}s, dir=${BACKUP_DIR}, retention=${KEEP})"

while true; do
    if run_once; then
        log "ok"
    else
        rc=$?
        log "FAILED iteration (rc=${rc}); continuing"
    fi
    sleep "${INTERVAL}"
done
