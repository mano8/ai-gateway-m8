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

> **Status: scaffold.** The application factory, settings, authentication
> wiring, run-modes and CI are in place. No management or execution route, no
> table and no scheduler job exists yet, and every execution request is refused
> (`401 context_invalid`) until the job-context verifier lands.

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
`changethis`. Every gateway key (`AI_*`) is listed there; an unknown key and a
missing required key both fail at startup. Secrets can be mounted as files
(`<FIELD>_FILE=/run/secrets/<name>`).

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

The test suite needs no `.env` and no running service: `tests/conftest.py`
sets a complete throwaway environment.

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
