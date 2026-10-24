# Compose stacks

Gateway-only deployment examples. Each runnable stack holds the gateway (web
service, `ai_gateway_scheduler` and the `ai-migrate` one-shot), its own
PostgreSQL `ai_db`, the issuer (`tepochtli/fa-auth-m8`, configured only: the
gateway is one `PRIVATE_API_CONSUMERS` row), Redis for the issuer and a
Traefik front. No stack contains the media services. The integrated target
with media is the media plan's stack.

| Stack | Credential backend | Posture | Status |
| --- | --- | --- | --- |
| [`postgres_m8`](postgres_m8/) | `database`, local KEK file | development (`ENVIRONMENT=local`) | boots; scheduler healthy |
| [`encrypted_db_m8`](encrypted_db_m8/) | `database`, local KEK file | production, strict; optional local Ollama | boots; scheduler healthy |
| [`vault_transit_m8`](vault_transit_m8/) | `database`, `vault_transit` KEK (learning Vault, TLS, AppRole) | production, strict | boots; scheduler healthy |
| [`vault_kv_m8`](vault_kv_m8/) | `vault` (KV v2; learning Vault, TLS, AppRole) | production, strict | **not bootable yet**: the KV store is not served by this build, so `ai-migrate` refuses the backend |
| [`vault_prod_template`](vault_prod_template/) | external production Vault (transit, or KV once served) | production, strict | reference template, not runnable as-is |

`encrypted_db_m8` and `vault_transit_m8` are the targets for the gateway's
live security suite. Every stack is a gateway-only target.

## Start a stack

```bash
cd docker_compose/encrypted_db_m8
bash init.sh
docker compose up -d
docker compose ps
```

`init.sh` needs only bash and Docker. It:

1. copies each `*.env.example` to its runtime name when that file is absent;
2. builds the gateway image from this repository (`ai-gateway-m8:stack`);
3. runs [`shared/scripts/generate_material.py`](shared/scripts/generate_material.py)
   inside that image, with no network, a read-only root and no capabilities,
   to create every missing file under `./secrets` (mode `0600`). It never
   overwrites a file;
4. copies the derived, non-secret values (key ids, the gateway's issuer row)
   into the env files.

It generates:

- **`ai_deployment_id`**: the installation id, generated only when absent. It
  is never regenerated or rotated.
- **Keys**: the KEK (local-KEK stacks only), the fingerprint key and the OCR
  receipt seed.
- **The security suite's test issuer**: an Ed25519 seed in the
  `jobcontext keygen` form, registered in `AI_SERVICE_CLIENTS` with its
  service-client secret.
- **Database and issuer secrets**: the `ai_owner` and `ai_runtime` database
  passwords, every issuer secret and the issuer's RS256 key pair.
- **TLS**: a stack-local CA and Traefik's certificate (Vault's too, in the
  Vault stacks).

Each secret is at least 256 bits and carries every character class the fleet's
settings require.

**Back up `./secrets`.** It holds the installation id and, in the local-KEK
stacks, the KEK. Without them, the stored credentials cannot be read.

Rotation is not an `init.sh` operation. Rotating the KEK or the fingerprint
key is a gateway command (the README's *Credential storage and key rotation*). A regenerated key
would leave every stored credential unreadable.

The stack directory must sit on a Linux filesystem. The gateway refuses a key
file with group or other permission bits. A Windows drive mounted into WSL or
a container does not keep Unix modes, so keep the stack under the WSL or Linux
home directory.

## What every stack guarantees

`tests/test_compose_policy.py` asserts all of this for every stack and for
the production template.

- **Container hardening.** `ai_gateway`, `ai_gateway_scheduler` and
  `ai-migrate`:
  - run as uid 1000 with a read-only root;
  - drop every capability and add none, with `no-new-privileges`;
  - set memory and pid limits;
  - mount no host path and no Docker socket. Configuration comes from
    `env_file` and every secret is a Docker secret. The only mounts are the
    `ai_spool` volume and, in the learning-Vault stacks, the read-only AppRole
    volume.
- **Secret placement (D-42).** The OCR receipt seed and the fingerprint key
  are mounted on the web service only. The `ai_owner` password is mounted on
  `ai-migrate` only, and the `ai_runtime` password never is.
- **Migrations (D-04).** Only `ai-migrate` runs Alembic, as `ai_owner`, then
  records or verifies `AI_DEPLOYMENT_ID`. The web service and the scheduler
  start after it has completed successfully. `db-init` creates the roles: the
  runtime role can insert and read the audit tables but never update or
  delete them.
- **Scheduler.** The scheduler uses the same image and `env_file` as the web
  service. Its networks are `data_net`, `ai_net` and `ai_egress`. It has no
  `app_net`, no published port and no Traefik route. Its healthcheck is
  `python -m ai_gateway.scheduler --healthcheck`.
- **Spool (D-45).** `ai_spool` is a `local` named volume without NFS, CIFS or
  SMB options, mounted at `/spool` on the web service and the scheduler. Its
  `org.m8.ai-spool.size-bytes` label declares the size of the filesystem the
  operator provisions for it. The sizing rule is checked:
  `AI_OCR_SPOOL_MAX_BYTES` ≤ the declared size, and
  `AI_MAX_CONCURRENT_SPOOLS × AI_MAX_REQUEST_BYTES` ≤ `AI_OCR_SPOOL_MAX_BYTES`.
- **Ratified first-deployment values.**
  - `AI_USER_BYOK_ENABLED=true`;
  - the default data-class table (`AI_DATA_CLASS_POLICY` unset);
  - `AI_JOB_CONTEXT_MAX_TTL_SECONDS=900`;
  - `AI_RESTRICTED_OCR_RESTORE_RESIDUAL_ACCEPTED` unset;
  - `API_KEY_INTROSPECTION_ENABLED` unset;
  - `ocr` absent from `AI_CAPABILITIES_ENABLED`.
- **Networks.** `app_net`, `data_net` and `ai_net` are internal. Only the
  web service and the scheduler join `ai_egress`. `ai_net` holds the gateway,
  the scheduler and, optionally, Ollama.
- **Self-containment.** No stack file refers to anything outside this
  repository.

## Ingress

Traefik runs as uid 1000, uses the file provider only and has no Docker
socket. Its configuration is in [`shared/traefik/`](shared/traefik/).

- **`websecure`** is the public router. It is published on
  `${PUBLIC_BIND_IP:-127.0.0.1}:${PUBLIC_HTTPS_PORT:-4431}`.
  - It never routes `/ai/v1/execute`, `/ai/v1/internal`, `/ai/metrics`,
    `/ai/docs`, `/ai/redoc` or `/ai/openapi.json` (nor their `/ai/v1/`
    spellings).
  - It removes the `X-Internal-Client`, `X-Internal-Token` and
    `X-AI-Job-Context` headers.
  - It never routes the issuer's `/user/private` or `/user/metrics`.
  - `/ai/health/` is shallow. The detail needs `HEALTH_DETAIL_CREDENTIAL`.
- **`api`** is unfiltered. It is published on `127.0.0.1:${API_PORT:-18080}`
  only. It stands in for callers on `app_net`, such as a co-located service or
  the live suite. Never bind it to a LAN address.

The production stacks answer on their `DOMAIN` (`ai-gateway.lan`): resolve
that name to the host. Clients trust `secrets/stack_ca.pem`. To expose the
public router on an isolated LAN segment, set `PUBLIC_BIND_IP` in `.env`.

## Topology

One Docker host, or an isolated LAN segment under `auth-sdk-m8`'s single-host
trust. The production stacks set `ALLOW_INTERNAL_HTTP=true` because the gateway
reaches the issuer over `app_net`, an internal network on that one host. No
example implies multi-host support, which needs TLS between services first.

## Vault stacks are learning-only

`vault_transit_m8` and `vault_kv_m8` run Vault in server mode, with
persistent file storage and TLS from the stack CA. A restart keeps the transit
key; a `-dev` restart would lose it. The `vault-init` one-shot initialises
Vault once, unseals it on every `up`, enables the engine and writes the
gateway's AppRole. The AppRole policy for transit grants encrypt and decrypt
on one key and no read of `transit/keys/*`.

What makes them learning-only: Vault is initialised with **one** unseal share,
and that share and the root token are kept in the `vault_bootstrap` volume
next to it. Production uses [`vault_prod_template`](vault_prod_template/):
an external Vault, split custody or auto-unseal, and no root token.

After a host restart, Vault is sealed until `docker compose up -d` runs
`vault-init` again. Until then the gateway's health detail reports the
credential store `fail`, and credential operations answer
`credential_unavailable`.

## Optional local models (`encrypted_db_m8`)

```bash
docker compose --profile ollama up -d
OLLAMA_MODEL=nomic-embed-text docker compose run --rm ollama-pull
```

Ollama joins `ai_net` only, so nothing but the gateway and its scheduler can
reach it, and it has no egress. `ollama-pull` is the one service with its own
egress network, `ollama_pull_net`. It runs only when invoked and exits after
the pull. Register the runtime as a `local` provider with `base_url`
`http://ollama:11434`.

## Live checks

`tests/live/test_vault_transit_stack.py` runs against a started
`vault_transit_m8` (the module docstring has the command). It checks:

- the health probe passes under the documented AppRole policy;
- a credential written through the API is stored under the transit key, and
  its secret is absent from a database dump;
- revoked tokens recover by a fresh login;
- a policy that grants encrypt without decrypt fails health.
