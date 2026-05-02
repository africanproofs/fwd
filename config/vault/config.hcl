storage "raft" {
  path    = "/vault/data"
  node_id = "fwd-vault-node"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://vault:8200"
cluster_addr = "http://vault:8201"
ui           = false
disable_mlock = false
log_level    = "info"

# TLS is intentionally disabled in Phase 2 (Vault is reachable only via the
# fwd-internal Docker network, which is the security boundary). Phase 3 will
# enable TLS via a self-signed internal CA per architecture.md § Vault configuration.
