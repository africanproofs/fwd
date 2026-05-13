#!/bin/sh
# scripts/vault-snapshot-entrypoint.sh — privilege-bracket wrapper for
# vault-snapshot.sh.
#
# Why this exists: the snapshot loop runs as the unprivileged `nobody` user
# (defense-in-depth per Core invariant #1). The /backup mount is a Docker
# named volume created root-owned mode 755 by the Docker daemon — `nobody`
# cannot mkdir into it. This wrapper executes briefly as root to
# create + chown /backup/vault-snapshots, then drops to nobody via su-exec
# before entering the snapshot loop. The main loop never runs as root.
#
# Litestream writes to /backup/state.db.litestream/ (a different subtree),
# so we deliberately do NOT chown /backup itself — only the subdirectory
# this sidecar owns.

set -eu

BACKUP_SUBDIR="/backup/vault-snapshots"

mkdir -p "${BACKUP_SUBDIR}"
chown -R nobody:nobody "${BACKUP_SUBDIR}"

exec su-exec nobody:nobody /usr/local/bin/vault-snapshot.sh "$@"
