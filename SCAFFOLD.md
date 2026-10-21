# Scaffold record

## Template source

`fa-auth-m8@e25a41bd7536972a8f4fefabe41581a8a9046fbe:examples/fastapi_full`

That revision is `fa-auth-m8`'s `main` when the scaffold was made
(2026-10-18). The last commit touching `examples/fastapi_full` is `6e45845`
(2026-09-25), so both name the same template tree. `fastapi_full` is the
production-oriented `fastapi-m8` consumer reference: the gateway's management
routes need its reader/writer/admin/superuser authentication.

## Platform pin

- `fastapi-m8[db,postgres]>=4.6.0,<5.0.0` and
  `ai-sdk-m8[jobcontext]>=0.2.0,<0.3.0`. `fastapi-m8` 4.6.0 is the published
  minor that adds the service-client guard and the internal-header re-exports.
  `ai-sdk-m8` 0.2.0 carries the signed-object rule, the C-01 schemas and the
  management wire models.
- The lock pins `fastapi-m8==4.6.0`, `auth-sdk-m8==3.2.1` (the floor
  `fastapi-m8` 4.6.0 requires) and `ai-sdk-m8==0.2.0`. All three are on PyPI.
  The lock moved on 2026-10-20 with one narrow `pip-compile --upgrade-package`
  for each of the three, under Python 3.14.7 in the Dockerfile's
  `python:3.14-slim` digest with pip-tools 7.6.2. No other pin changed.
- The scaffold's earlier pin, until 2026-10-20, was `fastapi-m8==4.5.1` and
  `auth-sdk-m8==3.2.0`.

## File mapping

Paths on the left are relative to the template directory; paths on the right
are relative to this repository.

### Kept, adapted

| Template | Gateway | Adaptation |
| --- | --- | --- |
| `__init__.py` | `ai_gateway/__init__.py` | own `__version__` (`0.1.0`), re-surfaced as `SERVICE_VERSION` |
| `main.py` | `ai_gateway/main.py` | same `create_app(settings, api_router, health=HealthConfig(...), lifecycle=AppLifecycle(auth_deps=…, db_engine=…, lifespan_extras=…))` wiring and metrics guard; passes `service_version`; the DB health check reports the exception type, never its message |
| `core/config.py` | `ai_gateway/core/config.py` | same `ConsumerServiceSettings` subclass and `find_dotenv`/`extra="forbid"` config; contract `1.0` / `>=1.0.0 <2.0.0`; every gateway key declared, the four without a safe default required; the audit-retention fields dropped |
| `core/deps.py` | `ai_gateway/core/deps.py` | same build-once `build_auth_deps` / `create_db_engine` and tier re-exports; API-key writer and issuer user directory dropped |
| `core/events.py` | `ai_gateway/core/events.py` | unchanged logic (auth event-stream lifespan extras) |
| `core/exceptions.py` | `ai_gateway/core/exceptions.py` | unchanged |
| `core/utc_session.py` | `ai_gateway/core/utc_session.py` | unchanged logic; docstring rewritten for a schema with no legacy columns |
| `app/__init__.py` | `ai_gateway/app/__init__.py` | docstring |
| `app/main.py` | `ai_gateway/app/main.py` | includes the management and execution routers; no API-key router |
| `app/deps.py` | `ai_gateway/app/deps.py` | tier re-exports plus `require_job_context`; no API-key or owner-verifier export |
| `app/routes/__init__.py` | `ai_gateway/app/routes/__init__.py` | docstring |
| `controllers/__init__.py` | `ai_gateway/controllers/__init__.py` | docstring |
| `db_models/__init__.py` | `ai_gateway/db_models/__init__.py` | the gateway's own tables (`T16`) |
| `schemas/__init__.py` | `ai_gateway/schemas/__init__.py` | docstring |
| `alembic.ini` | `ai_gateway/alembic.ini` | `%(here)s`-relative packaged `alembic/versions`, `version_table = alembic_version_ai` |
| `alembic/env.py` | `ai_gateway/alembic/env.py` | same offline/online flow and UTC pin; packaged version location |
| `alembic/script.py.mako` | `ai_gateway/alembic/script.py.mako` | unchanged |
| `alembic/README` | `ai_gateway/alembic/README` | rewritten |
| `Dockerfile` | `ai_gateway/Dockerfile` | same two stages, digest, Debian patch layer and lock install; setuptools/wheel guard and import check as in `media-service-m8`; scripts normalised; build context is the repository root |
| `scripts/docker_start.sh` | `ai_gateway/scripts/docker_start.sh` | **no autogenerate, no migration**: pre-start checks, then uvicorn |
| `scripts/pre_start.sh` | `ai_gateway/scripts/pre_start.sh` | **no `alembic upgrade`**: runs `python -m ai_gateway.prestart` (DB wait plus the read-only revision check) |
| `requirements_base.txt` | `ai_gateway/requirements_base.txt` | `fastapi-m8[db,postgres]` only (PostgreSQL-only); unrelated dependencies dropped |
| `requirements_dev.txt` | `ai_gateway/requirements_dev.txt` | `ruff` pinned exactly, `pip-audit` added, build tools dropped |
| `requirements_prod.txt` | `ai_gateway/requirements_prod.txt` | unchanged |
| `requirements_prod.lock` | `ai_gateway/requirements_prod.lock` | regenerated from the gateway's own requirements (Python 3.14, Linux, PyPI only) |
| `.example_env` | `ai_gateway/.env.example` | RS256/JWKS, stateful revocation, strict `iss`/`aud`, PostgreSQL `ai_db`; every gateway key set to `changethis` |
| `.dockerignore` | `.dockerignore` | repository-root context |
| `.coveragerc` | `.coveragerc` | 100% branch gate; omits only the live-only event stream and Alembic |
| `pytest.ini` | `pytest.ini` | run from the repository root |
| `tests/conftest.py` | `tests/conftest.py` | same pre-import environment and `find_dotenv` stub; strict `iss`/`aud`; issuer-shaped token helper |
| `tests/test_utc_session.py` | `tests/test_utc_session.py` | adapted to the gateway engine |
| `tests/test_acceptance_matrix.py` | `tests/test_auth.py` | the real-token tier matrix, over the gateway's tier dependencies |

### Not copied

| Template | Reason |
| --- | --- |
| `app/routes/api_key_category.py` and its `get_current_api_key_writer` wiring | no gateway route accepts an API-key principal |
| `app/routes/category.py`, `dashboard.py`, `audit.py`; `controllers/dashboard.py`; `schemas/dashboard.py`; `db_models/categories.py`, `privileged_action_audit.py` | the example's domain; replaced by the gateway's own |
| `app/audit.py`, `app/ownership.py` | example domain helpers |
| `core/user_directory.py` | the issuer user-directory client; no gateway requirement needs it yet |
| `core/db_models.py` (`prefixed_tables`) | gateway tables are named explicitly (`ai_*`) |
| `.gitignore`, `.coverage`, the domain tests | example-specific; the repository keeps its own `.gitignore` |

### New in the gateway

| File | Purpose |
| --- | --- |
| `ai_gateway/core/execution_guard.py` | mandatory service-client and job-context dependency and the execution-router factory; verifies since `T17` (`core/job_context.py`) |
| `ai_gateway/app/routes/execution.py`, `management.py` | the two routers; management serves `admin.py` and `profiles.py` since `T18` |
| `ai_gateway/prestart.py` | DB wait and the read-only `alembic_version_ai` check |
| `ai_gateway/scheduler.py`, `scripts/scheduler_start.sh` | scheduler run-mode; refuses to run until a job exists |
| `ai_gateway/scripts/ai_migrate.sh` | the `ai-migrate` one-shot, the only Alembic caller |
| `ai_gateway/{credentials,providers}/` | domain packages; `credentials/ruff.toml` lifts only the credential-model ban |
| `ruff.toml` | `TID251` bans |
| `tests/test_{app,execution_guard,prestart,repository,revocation,settings,exceptions}.py` | scaffold acceptance tests |
