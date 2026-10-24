# vault_prod_template

> **Reference template, not runnable as-is.** It connects the gateway to an
> external, production Vault. Learn the moving parts first in
> [`vault_transit_m8`](../vault_transit_m8/), whose bundled Vault is
> learning-only.

| File | Purpose |
| --- | --- |
| [`docker-compose.template.yml`](docker-compose.template.yml) | `ai-migrate`, `ai_gateway` and `ai_gateway_scheduler` to merge into the deployment's stack, with no `vault` or `vault-init` service |
| [`gateway.env.example`](gateway.env.example) | production and strict mode, an `https` `AI_VAULT_ADDR`, AppRole from Docker secrets, the ratified first-deployment values |
| [`vault/config/vault.hcl`](vault/config/vault.hcl) | Vault server: Raft storage, TLS listener, an auto-unseal stanza to fill in |
| [`vault/policies/ai-gateway-transit.hcl`](vault/policies/ai-gateway-transit.hcl) | the AppRole policy for the recommended backend (`database` + `vault_transit`) |
| [`vault/policies/ai-gateway-kv.hcl`](vault/policies/ai-gateway-kv.hcl) | the AppRole policy for the KV alternative (`AI_CREDENTIAL_STORAGE_BACKEND=vault`), once this build serves it |

The compose policy test checks this template like the runnable stacks: the
hardened services, the per-service secret list and the `https` Vault address.

## 1. Run Vault outside the gateway's stack

Vault outlives any one deployment. Run it as its own stack or use a managed
Vault, with `vault/config/vault.hcl`:

- Raft storage;
- a TLS certificate for the name in `api_addr`;
- auto-unseal through the deployment's KMS or HSM, or split custody
  (`vault operator init -key-shares=5 -key-threshold=3`).

## 2. Configure transit and the AppRole, then drop the root token

```sh
export VAULT_ADDR=https://vault.internal:8200 VAULT_CACERT=/path/to/vault-ca.pem
export VAULT_TOKEN=<initial-root-token>      # used once, for this setup only

vault secrets enable transit
vault write -f transit/keys/ai-gateway-kek type=aes256-gcm96
vault policy write ai-gateway vault/policies/ai-gateway-transit.hcl

vault auth enable approle
vault write auth/approle/role/ai-gateway \
    token_policies=ai-gateway token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=0 secret_id_num_uses=0 \
    secret_id_bound_cidrs=<the gateway host's address>/32 \
    token_bound_cidrs=<the gateway host's address>/32

vault token revoke -self                      # the root token is gone
```

- **`token_ttl` and `token_max_ttl`.** The gateway logs in again past 80 % of
  each token's lease, and once more on a `403`. It never renews a token past
  its maximum.
- **`secret_id_ttl` and `secret_id_num_uses`.** The `secret_id` has no TTL
  and no use limit because the gateway re-reads it at every login. Rotate it
  by issuing a new one, swapping the secret file and restarting the gateway
  services. Then destroy the old one with
  `vault write auth/approle/role/ai-gateway/secret-id-accessor/destroy`.
- **Bound CIDRs.** These pin both the login and the token to the gateway's
  host.
- **The policy.** It grants transit encrypt and decrypt on one key and nothing
  else. It has no read of `transit/keys/*`: the gateway learns the key version
  from encrypt answers, and its health probe uses only `lookup-self` and an
  encrypt → decrypt round trip. A policy that grants encrypt without decrypt
  fails that probe.

To rotate the transit key, follow D-23: rotate the key, run
`python -m ai_gateway.credentials rewrap` and then `rewrap --verify`, and only
then raise `min_decryption_version` (the README's *Credential storage and key
rotation*).

## 3. Deliver the secrets

The template reads every secret from `./secrets/<name>`. Each file is mode
`0400`, owned by uid 1000 and never committed. The deployment's secrets
pipeline writes them, or a Vault Agent sidecar for the AppRole files.

| Secret | Who holds it |
| --- | --- |
| `vault_ca.pem` | all three gateway services: the CA that signs Vault's certificate |
| `vault_role_id`, `vault_secret_id` | all three gateway services |
| `ai_fingerprint_key`, `ai_receipt_seed` | `ai_gateway` only (D-42) |
| `ai_owner_db_password` | `ai-migrate` only |
| `ai_runtime_db_password` | `ai_gateway`, `ai_gateway_scheduler` |
| `ai_deployment_id` | all three: generated once, never rotated, backed up |
| the consumer secrets (`gateway_*`, `event_signing_key`, `health_detail_credential`, `metrics_scrape_credential`, `ai_service_clients.json`) | all three |

`../shared/scripts/generate_material.py` shows how each one is generated, and
`python -m ai_sdk_m8.jobcontext keygen --out <file>` writes the receipt seed.

## 4. Merge and start

1. Merge the three services, `ai_spool` and the secrets into the deployment's
   stack.
2. Pin `image:` to a released tag or digest.
3. Replace every `changethis` in `gateway.env` and keep `AI_VAULT_ADDR` on
   `https`.
4. Create the `ai_owner`/`ai_runtime` roles as
   [`shared/scripts/db-init.sh`](../shared/scripts/db-init.sh) does.
5. Start `ai-migrate`, then the web service and the scheduler.

## Production checklist

- [ ] Vault runs outside this stack, in server mode with Raft, TLS and
  auto-unseal or split custody.
- [ ] No root token, unseal key or `VAULT_TOKEN` in any env file, compose file
  or volume of this stack.
- [ ] `AI_VAULT_ADDR` is `https`, `AI_VAULT_CA_FILE` names the CA, and Vault's
  certificate verifies under Python's strict X.509 checks (Authority and
  Subject Key Identifiers, key usage).
- [ ] The AppRole policy is `ai-gateway-transit.hcl` (or `ai-gateway-kv.hcl`)
  unchanged, with bound CIDRs set.
- [ ] `AI_DEPLOYMENT_ID` is generated once and backed up with the other
  secrets.
- [ ] The `ai_spool` filesystem is local (`ext4`, `xfs` or `btrfs`) and sized;
  the volume label states that size.
- [ ] `ENVIRONMENT=production`, `STRICT_PRODUCTION_MODE=true`, and the
  ratified values are unchanged (the compose policy test).
