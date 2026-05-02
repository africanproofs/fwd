# fwd-app — Vault policy for the fwd application.
# Per architecture.md § Vault configuration: fwd needs only encrypt + decrypt
# against the single shared transit master key. NO transit/sign/* (Vault is
# an envelope-encryption layer under the v0.1.2 architecture, not a signer).

path "transit/encrypt/fwd-master" {
  capabilities = ["update"]
}

path "transit/decrypt/fwd-master" {
  capabilities = ["update"]
}

path "transit/keys/fwd-master" {
  capabilities = ["read"]
}

# NO transit/sign/*, NO transit/keys/+/export, NO transit/keys/+/rotate, NO transit/keys/+/config
