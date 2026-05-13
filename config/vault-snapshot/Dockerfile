# fwd vault-snapshot — periodic Vault Raft snapshot + S3 upload sidecar.
#
# Multi-stage:
#   - vault-stage: pulls the official vault image to extract the vault CLI
#     binary (we need vault CLI for `operator raft snapshot save`).
#   - runtime: alpine + aws-cli + the vault CLI binary + the snapshot loop.
#
# Runs as non-root (alpine `nobody`) per Core invariant #1 defense-in-depth.

FROM hashicorp/vault:1.18.2 AS vault-stage

FROM alpine:3.19

RUN apk add --no-cache \
        aws-cli \
        bash \
        ca-certificates \
    && rm -rf /var/cache/apk/*

# Vault image places the binary at /bin/vault. Copy it into the runtime image.
COPY --from=vault-stage /bin/vault /usr/local/bin/vault

COPY scripts/vault-snapshot.sh /usr/local/bin/vault-snapshot.sh
RUN chmod +x /usr/local/bin/vault-snapshot.sh

USER nobody

ENTRYPOINT ["/usr/local/bin/vault-snapshot.sh"]
