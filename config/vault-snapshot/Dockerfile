# fwd vault-snapshot — periodic Vault Raft snapshot sidecar.
#
# Multi-stage:
#   - vault-stage: pulls the official vault image to extract the vault CLI
#     binary (we need vault CLI for `operator raft snapshot save`).
#   - runtime: alpine + the vault CLI binary + the snapshot loop. Snapshot
#     files are written to a shared Docker volume at /backup/vault-snapshots/;
#     off-host transport is the operator's responsibility (rsync / restic /
#     borg / NAS / USB — out of band, with the operator's tool of choice).
#
# No aws-cli, no S3 client. The v0.4.2 cloud-upload path was reverted at
# v0.4.3 per the operator's "no outside dependencies" directive. See
# CLAUDE.md v0.4.3 paragraph for the doctrine alignment.
#
# Runs as non-root (alpine `nobody`) per Core invariant #1 defense-in-depth.

FROM hashicorp/vault:1.18.2 AS vault-stage

FROM alpine:3.19

# ca-certificates (Vault HTTPS — present even though the in-compose Vault
# listener is HTTP, kept for any future TLS-enabled Vault). su-exec is used
# by the entrypoint wrapper to drop from root to nobody after chowning the
# /backup/vault-snapshots subdirectory (a Docker named volume mount is
# root-owned mode 755 at creation; nobody cannot mkdir into it). Coreutils
# (`cp`, `ls`, `rm`, `sort`, `date`) and `/bin/sh` come from busybox baked
# into the alpine base.
RUN apk add --no-cache ca-certificates su-exec \
    && rm -rf /var/cache/apk/*

# Vault image places the binary at /bin/vault. Copy it into the runtime image.
COPY --from=vault-stage /bin/vault /usr/local/bin/vault

COPY scripts/vault-snapshot.sh /usr/local/bin/vault-snapshot.sh
COPY scripts/vault-snapshot-entrypoint.sh /usr/local/bin/vault-snapshot-entrypoint.sh
RUN chmod +x /usr/local/bin/vault-snapshot.sh /usr/local/bin/vault-snapshot-entrypoint.sh

# No `USER nobody` directive — the entrypoint wrapper runs briefly as root
# to chown the /backup/vault-snapshots subdir, then drops to nobody via
# su-exec before exec'ing the main snapshot loop. The snapshot loop never
# executes with root privileges; only the one-shot chown does.
ENTRYPOINT ["/usr/local/bin/vault-snapshot-entrypoint.sh"]
