# vault/policies/ai-gateway-transit.hcl — the gateway's AppRole policy for the
# recommended backend (database + vault_transit, T23).
#
# Encrypt and decrypt with one key, nothing else: no read of transit/keys/*
# (the gateway learns the key version from encrypt answers), no export, no
# rotation, no rewrap endpoint (the gateway rewraps by decrypt + encrypt,
# because every data key carries its version's associated data). The token's
# default policy supplies auth/token/lookup-self, which the health probe uses.
# A policy granting encrypt without decrypt fails the gateway's health check.
#
#   vault policy write ai-gateway vault/policies/ai-gateway-transit.hcl

path "transit/encrypt/ai-gateway-kek" {
  capabilities = ["update"]
}

path "transit/decrypt/ai-gateway-kek" {
  capabilities = ["update"]
}
