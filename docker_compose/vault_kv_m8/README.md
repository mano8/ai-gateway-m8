# vault_kv_m8

The gateway alone in the **production posture**, with the alternative
*Hardened Vault* backend: provider secrets in Vault KV v2 under the gateway's
prefix (`AI_CREDENTIAL_STORAGE_BACKEND=vault`), with no KEK.

**Not bootable yet.** This build does not serve the KV store. Vault, KV v2 and
the AppRole come up, but `ai-migrate` then exits with
`AI_CREDENTIAL_STORAGE_BACKEND=vault is not served by this build`, so the web
service and the scheduler never start. The stack ships now so that the compose
policy test pins its shape and the KV work and the live suite have their
target.

```bash
bash init.sh
docker compose up -d
```

The bundled Vault is learning-only, as in
[`vault_transit_m8`](../vault_transit_m8/). The AppRole policy grants the
gateway's `ai-kv/data/ai-gateway/*` and `ai-kv/metadata/ai-gateway/*` paths
only.
