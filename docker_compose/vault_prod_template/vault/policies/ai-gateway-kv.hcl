# vault/policies/ai-gateway-kv.hcl — the gateway's AppRole policy for the
# alternative backend (AI_CREDENTIAL_STORAGE_BACKEND=vault, KV v2; T24).
#
# The gateway's own prefix only. Its exact sub-paths (per installation, per
# credential version) are fixed by T24; this policy grants nothing outside
# ai-gateway/ on the ai-kv mount.
#
#   vault policy write ai-gateway vault/policies/ai-gateway-kv.hcl

path "ai-kv/data/ai-gateway/*" {
  capabilities = ["create", "read", "update"]
}

path "ai-kv/metadata/ai-gateway/*" {
  capabilities = ["read", "list", "delete"]
}
