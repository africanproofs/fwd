# fwd-snapshot — Vault policy for the vault-snapshot sidecar.
#
# Capability minimum: read on sys/storage/raft/snapshot to invoke
# `vault operator raft snapshot save`. NO transit/* access — this role
# cannot decrypt wallet ciphertexts. NO sys/storage/raft/snapshot-force
# either — restore is operator-driven via the root token during a drill.
#
# Per Core invariant #18 + D11-style isolation: the fwd-app policy
# (encrypt + decrypt) and the fwd-snapshot policy (snapshot read) are
# disjoint. Compromise of the snapshot AppRole credentials does not grant
# the ability to decrypt wallets, and compromise of the fwd AppRole does
# not grant the ability to take or read snapshots.

path "sys/storage/raft/snapshot" {
  capabilities = ["read"]
}
