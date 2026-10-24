# Learning Vault for vault_transit_m8 and vault_kv_m8 (T87). LEARNING-ONLY.
#
# Unlike `vault server -dev`, storage persists in the vault_data volume, so a
# restart keeps the transit key and every KV secret (a dev-mode restart would
# lose the KEK and orphan every stored credential). TLS uses the stack-local
# CA that init.sh generates. What still makes it learning-only: one unseal
# share and the root token kept in the vault_bootstrap volume beside it
# (shared/scripts/vault-bootstrap.sh). Production: vault_prod_template.

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/run/secrets/vault_tls.crt"
  tls_key_file    = "/run/secrets/vault_tls.key"
  tls_min_version = "tls12"
}

api_addr      = "https://vault:8200"
# Runs as an unprivileged uid with no capabilities, so no IPC_LOCK.
disable_mlock = true
ui            = false
