# vault/config/vault.hcl — production Vault server for the gateway (T87).
#
# Vault is long-lived infrastructure: run it as its own stack or use a managed
# Vault, never inside the gateway's compose project.
#   * Raft integrated storage (add retry_join blocks for an HA cluster);
#   * TLS on the listener (a certificate the gateway's AI_VAULT_CA_FILE trusts);
#   * auto-unseal through a cloud KMS or HSM (seal stanza), or split custody of
#     the unseal shares (vault operator init -key-shares=5 -key-threshold=3);
#   * mlock kept (IPC_LOCK on the container), no UI unless needed.

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-node-1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_disable     = false
  tls_cert_file   = "/vault/certs/vault.crt"
  tls_key_file    = "/vault/certs/vault.key"
  tls_min_version = "tls12"
}

# The address clients (the gateway) use; it must match the certificate.
api_addr     = "https://vault.internal:8200"
cluster_addr = "https://vault.internal:8201"

# Auto-unseal example (replace with the deployment's KMS):
# seal "awskms" {
#   region     = "eu-west-1"
#   kms_key_id = "alias/vault-unseal"
# }

ui = false
