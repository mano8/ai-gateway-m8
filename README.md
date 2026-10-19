# ai-gateway-m8

The AI provider gateway of the m8 stack. It is the only service that holds AI
provider credentials: it enforces data-class policy, meters admission units,
verifies signed job contexts and executes provider calls on behalf of the
fleet's services.

- Package: `ai_gateway` (`ai_gateway/__init__.py` `__version__`, served as
  `SERVICE_VERSION` at `{API_PREFIX}/meta`; the API contract is versioned
  separately as `CONTRACT_VERSION`).
- Image: `tepochtli/ai-gateway-m8`.
- Licence: Apache-2.0 (`LICENSE`).

> **Status: foundation in progress.** The settings refuse every contradiction
> at boot, `/meta` reports the gateway's ratified values, and `/health` checks
> the database and the application–database clock skew. Every execution
> request is still refused until the job-context verifier lands.

## Architecture

- Built on [`fastapi-m8`](https://pypi.org/project/fastapi-m8/):
  `create_app`, `ConsumerServiceSettings`, `build_auth_deps` and
  `create_db_engine`, each built once per process in `ai_gateway/core/deps.py`.
  Service code never imports `auth-sdk-m8` directly (`ruff` `TID251`).
- **Two authentication models, never mixed.** Management routes authenticate
  users with the issuer's JWT (`fa-auth-m8`, JWT/JWKS plus its private
  revocation API) at the reader, writer, admin or superuser tier. Execution
  routes accept only a signed job context from an authenticated service
  client; they are built by `build_execution_router`, which attaches the
  mandatory guard, and a user JWT is never sufficient there. No route accepts
  an API-key principal.
- **Own database.** PostgreSQL `ai_db` with its own `alembic_version_ai`
  table. Migrations are packaged with the image.

## Run-modes

One image, three commands:

| Command | Role | Migrates? |
| --- | --- | --- |
| `ai_gateway/scripts/docker_start.sh` (default `CMD`) | web | never |
| `ai_gateway/scripts/scheduler_start.sh` | scheduler | never |
| `ai_gateway/scripts/ai_migrate.sh` | `ai-migrate` one-shot, schema-owner role | the only one |

The web and scheduler run-modes wait for the database, then read
`alembic_version_ai` and exit unless it equals the head packaged in the image
(`python -m ai_gateway.prestart`). Run `ai-migrate` first after every upgrade.
The image runs as `appuser`, carries no pip, and supports a read-only root
filesystem.

## Configuration

Copy `ai_gateway/.env.example` to `ai_gateway/.env` and replace every
`changethis`, or delete a line to take the key's default. Every gateway key
(`AI_*`) is listed there; an unknown key, a missing required key and a
remaining placeholder all fail at startup. Secrets can be mounted as files
(`<FIELD>_FILE=/run/secrets/<name>`); keys always are.

The settings refuse to boot on any contradiction they can see:

- a `vault` backend with a KEK setting; a `database` backend without a KEK
  provider or a fingerprint key; a `local` KEK file that is unreadable, not
  32 bytes, or readable by group or others; `vault_transit` or `vault`
  without the address, auth method and auth files; a non-`https` Vault address
  under `production`/strict;
- the same key in two key files, or (under `production`/strict) the same
  secret value for two purposes;
- an `AI_SERVICE_CLIENTS` entry with a plaintext secret, an unknown scope,
  `job-context:issue` without public keys, a key whose `kid` it does not
  derive, or one key under two clients;
- an `AI_DATA_CLASS_POLICY` that lets `restricted` reach an external provider
  without the context's own BYOK credential;
- `AI_USER_BYOK_ENABLED` unset under `production`/strict;
  `API_KEY_INTROSPECTION_ENABLED=true`;
- `ocr` enabled without a receipt key and a spool directory; a receipt `kid`
  that differs from the seed's; an issuer key equal to the receipt key;
- a dispatch-context TTL above the context TTL, a credential-resolve timeout
  not below both the reservation and dispatch TTLs, or a skew bound above the
  sweeper grace (30 s);
- an internal host that is not a lower-case `name:port` pair.

At start, the web and scheduler run-modes also refuse an OCR spool that is not
on `ext4`, `xfs` or `btrfs` or whose locks do not exclude another process.

`{API_PREFIX}/meta` serves the fleet `ServiceMeta` fields plus a `gateway`
block: the installation id, `user_byok_enabled`, both context TTLs, the
SHA-256 of the effective data-class policy, the enabled capabilities, the
storage backend and this replica's key generations (truncated hashes, never
key material). `/health` reports the database and the application–database
clock skew; above `AI_MAX_CLOCK_SKEW_SECONDS` it is degraded and every
execution answers `503 clock_skew_exceeded`.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r ai_gateway/requirements_dev.txt
ruff format --check . && ruff check .
mypy ai_gateway --ignore-missing-imports
bandit -r ai_gateway --severity-level medium
pytest                      # branch coverage gate: 100%
docker build -f ai_gateway/Dockerfile .
```

The test suite needs no `.env`: `tests/conftest.py` sets a complete
throwaway environment and writes random `0600` key files. It needs a
PostgreSQL server, because the gateway's invariants live in the database:
point `AI_GATEWAY_TEST_PG_ADMIN_URL` at a superuser connection (default
`postgresql://postgres:postgres@127.0.0.1:5432/postgres`), and the harness
creates the `ai_owner`/`ai_runtime` roles and a fresh test database. For
example:

```bash
docker run -d --rm --name ai-gw-pg -p 5432:5432 \
  -e POSTGRES_PASSWORD=postgres --tmpfs /var/lib/postgresql postgres:18-alpine
```

Regenerate the production lock with Python 3.14 on Linux, from PyPI only:

```bash
cd ai_gateway
pip-compile --generate-hashes --no-emit-index-url --no-strip-extras \
  --output-file=requirements_prod.lock requirements_prod.txt
```

## Deployment

Compose stacks will live under `docker_compose/`; none ships yet. Images are
published by `.github/workflows/docker-publish.yaml` on a published GitHub
release only (multi-arch, Trivy-gated, SPDX SBOM, keyless cosign signature,
build provenance).

See [`SECURITY.md`](SECURITY.md) for the threat model and how to report a
vulnerability, and [`SCAFFOLD.md`](SCAFFOLD.md) for the template this service
was adapted from.
