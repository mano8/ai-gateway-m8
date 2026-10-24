#!/bin/sh
# vault-init one-shot for the learning Vault of vault_transit_m8 and
# vault_kv_m8 (T87). LEARNING-ONLY: it initialises Vault with ONE unseal share
# and keeps that share and the root token in the vault_bootstrap volume, next
# to the Vault they unlock. A real deployment uses vault_prod_template: an
# external Vault, split unseal custody or auto-unseal, no root token kept.
#
# Every start: initialise once, unseal, then (idempotently) enable the engine
# this stack uses, write the gateway's policy and AppRole, and write the
# AppRole's role_id and a secret_id into the vault_approle volume, which the
# gateway services mount read-only. An existing secret_id is kept.
#
# Environment:
#   VAULT_ADDR, VAULT_CACERT   the stack's TLS Vault and its CA
#   AI_VAULT_ENGINE            transit | kv
#   AI_VAULT_TRANSIT_MOUNT, AI_VAULT_TRANSIT_KEY      (transit)
#   AI_VAULT_KV_MOUNT, AI_VAULT_KV_PATH_PREFIX        (kv)
set -eu
umask 077

BOOT=/vault/bootstrap
OUT=/vault/approle
INIT="${BOOT}/init.json"

until vault status -format=json >/dev/null 2>&1 || [ "$?" -eq 2 ]; do
    echo "==> vault-init: waiting for ${VAULT_ADDR}"
    sleep 1
done

initialized() { vault status -format=json 2>/dev/null | grep -q '"initialized": true'; }
sealed() { vault status -format=json 2>/dev/null | grep -q '"sealed": true'; }

if ! initialized; then
    echo "==> vault-init: initialising (learning-only: one unseal share)"
    vault operator init -key-shares=1 -key-threshold=1 -format=json > "${INIT}.tmp"
    mv "${INIT}.tmp" "${INIT}"
fi
[ -s "${INIT}" ] || { echo "ERROR: Vault is initialised but ${INIT} is missing" >&2; exit 1; }

UNSEAL_KEY="$(sed -n '/"unseal_keys_b64"/,/]/p' "${INIT}" | grep -o '"[A-Za-z0-9+/=]\{20,\}"' | head -n 1 | tr -d '"')"
ROOT_TOKEN="$(grep -o '"root_token": *"[^"]*"' "${INIT}" | sed 's/.*"\([^"]*\)"$/\1/')"
if sealed; then
    vault operator unseal "${UNSEAL_KEY}" >/dev/null
    echo "==> vault-init: unsealed"
fi
export VAULT_TOKEN="${ROOT_TOKEN}"

POLICY=/tmp/ai-gateway.hcl
case "${AI_VAULT_ENGINE}" in
    transit)
        vault secrets list -format=json | grep -q "\"${AI_VAULT_TRANSIT_MOUNT}/\"" \
            || vault secrets enable -path="${AI_VAULT_TRANSIT_MOUNT}" transit
        vault read "${AI_VAULT_TRANSIT_MOUNT}/keys/${AI_VAULT_TRANSIT_KEY}" >/dev/null 2>&1 \
            || vault write -f "${AI_VAULT_TRANSIT_MOUNT}/keys/${AI_VAULT_TRANSIT_KEY}" type=aes256-gcm96 >/dev/null
        # Encrypt and decrypt with this one key; no export, no key management.
        cat > "${POLICY}" <<EOF
path "${AI_VAULT_TRANSIT_MOUNT}/encrypt/${AI_VAULT_TRANSIT_KEY}" {
  capabilities = ["update"]
}
path "${AI_VAULT_TRANSIT_MOUNT}/decrypt/${AI_VAULT_TRANSIT_KEY}" {
  capabilities = ["update"]
}
EOF
        ;;
    kv)
        vault secrets list -format=json | grep -q "\"${AI_VAULT_KV_MOUNT}/\"" \
            || vault secrets enable -path="${AI_VAULT_KV_MOUNT}" kv-v2
        # The gateway's own prefix only (KV v2 data and metadata paths).
        cat > "${POLICY}" <<EOF
path "${AI_VAULT_KV_MOUNT}/data/${AI_VAULT_KV_PATH_PREFIX}/*" {
  capabilities = ["create", "read", "update"]
}
path "${AI_VAULT_KV_MOUNT}/metadata/${AI_VAULT_KV_PATH_PREFIX}/*" {
  capabilities = ["read", "list", "delete"]
}
EOF
        ;;
    *) echo "ERROR: AI_VAULT_ENGINE must be transit or kv" >&2; exit 1 ;;
esac
vault policy write ai-gateway "${POLICY}" >/dev/null

vault auth list -format=json | grep -q '"approle/"' || vault auth enable approle >/dev/null
# Short-lived tokens the gateway renews by logging in again; the secret_id has
# no TTL or use limit because the gateway re-reads it at every login.
vault write auth/approle/role/ai-gateway \
    token_policies=ai-gateway token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=0 secret_id_num_uses=0 >/dev/null

vault read -field=role_id auth/approle/role/ai-gateway/role-id > "${OUT}/role_id.tmp"
mv "${OUT}/role_id.tmp" "${OUT}/role_id"
if [ ! -s "${OUT}/secret_id" ]; then
    vault write -f -field=secret_id auth/approle/role/ai-gateway/secret-id > "${OUT}/secret_id.tmp"
    mv "${OUT}/secret_id.tmp" "${OUT}/secret_id"
fi
chmod 0400 "${OUT}/role_id" "${OUT}/secret_id"
echo "==> vault-init: ${AI_VAULT_ENGINE} ready; AppRole ai-gateway written to the vault_approle volume"
