# Changelog

All notable changes to `ai-gateway-m8` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Settings (`T15`): every C-14 key typed, with defaults for the technical
  bounds, and boot refusals for every contradiction the settings can see —
  backend and KEK combinations, unsafe or reused key files, placeholders,
  reused secrets under production, malformed service clients (plaintext
  secrets, unknown scopes, issuers without keys, a `kid` its key does not
  derive, a key under two clients), a policy that widens `restricted`, an
  implicit `AI_USER_BYOK_ENABLED` under production, API-key introspection,
  OCR without its receipt key and spool, receipt-key conflicts, TTL, timeout
  and skew ordering, and malformed host or port lists. Keys are read once from
  mode-checked files and never shown in `repr`. Boot errors list field names
  and messages, never the input values.
- `{API_PREFIX}/meta` is the fleet shape plus a `gateway` block (installation
  id, user-BYOK flag, context TTLs, policy hash, capabilities, storage backend,
  key generations).
- `/health` checks the application–database clock skew; above the bound it is
  degraded and execution routes answer the typed `503 clock_skew_exceeded`.
- Typed `AiError` answers for execution-route refusals, with an opaque request
  id and `Retry-After`.
- Start-up refusal of an OCR spool that is not on a local filesystem or whose
  locks do not exclude another process.
- The initial schema (`T16`, revision `0001_initial`): installation identity,
  restore state, scheduler lease and epoch sequence; providers, models,
  profiles with immutable revisions and bindings (`NULLS NOT DISTINCT` per
  scope); credentials and their versions; job-context redemption, usage, rate
  windows, client occupancy and spool capacity; executions; remote
  artifacts; credential and admin audit trails. Triggers enforce the D-24
  and D-43 transition tables, frozen endpoints and model identities,
  credential ownership, monotonic version numbers, set-once lifecycle stamps
  and the material-destruction preconditions; the runtime role gets DML only
  (audit insert/read only, installation read only).
- Provider destination guard (`T19`, `ai_gateway/core/ssrf.py`): a static
  write-time pass and a resolved call-time pass over every A/AAAA answer,
  with the D-20 precedence (always-blocked classes before the allowlist,
  `is_global` for external providers, IPv4-mapped normalisation, local
  exemptions scoped to an allowlisted name and port, HTTPS for external
  providers under production, port allowlist, no userinfo, IDNA compare).
- `python -m ai_gateway.installation init`, run by `ai-migrate`, records the
  installation id once; web and scheduler refuse to start against another id
  or none.
- Auth dependencies (`T17`): `CurrentReader`, `CurrentWriter`,
  `CurrentAdmin`, `CurrentSuperuser` and `require_superuser` on the
  fresh-revocation path. The execution guard authenticates the service client
  through `fastapi-m8`'s guard with the route's `execute:` scope, and verifies
  `X-AI-Job-Context` against the issuer's registered keys, the presenting
  client (`azp`), the route's capability and the recorded installation
  (`aud`). `redeem_job_context` counts `(iss, jti)` once, atomically, with
  `exp` asserted on the database clock. Refusals are typed `AiError` answers.
- The superuser registry (`T18`) under `v1/admin`: providers (static
  destination check, boundary fixed, endpoint frozen at first use), models
  (derived C-07 `execution_identity`, identity frozen and capabilities
  shrink-only from the first reservation), profiles with immutable revisions,
  and global bindings. Every write is audited in `ai_admin_audit`, and each
  row is logged as an `ai_gateway.audit` event once the change commits.
- Published profiles at `v1/profiles` for reader JWTs and `profiles:read`
  service clients: keys, capability, revision, dimensions,
  `embedding_space_id`, `ocr_execution_identity` and `identity_assurance`;
  never a credential or `base_url`.

### Changed

- Requires `fastapi-m8>=4.6.0` and `ai-sdk-m8[jobcontext]>=0.2.0`. The
  production lock pins `fastapi-m8` 4.6.0, `auth-sdk-m8` 3.2.1 and
  `ai-sdk-m8[jobcontext]` 0.2.0; no other pin moved. Tests cover
  `fastapi-m8`'s service-client guard over the gateway's `AI_SERVICE_CLIENTS`
  registry, and check that the lock satisfies both floors.
- The test suite runs against PostgreSQL (CI starts a service container).
- Execution routes live under `v1/execute`, the `ai-sdk-m8` route table's
  prefix. The test environment registers real service clients and issuer
  keys.
- Management routes live under `v1` (`v1/admin`, `v1/profiles`), the
  `ai-sdk-m8` route table's paths, instead of `/manage`.
- The route walk in the tests uses `fastapi.routing.iter_route_contexts`,
  because FastAPI 0.143 no longer flattens included routers into
  `app.routes`. The earlier execution-route check was vacuous.

## [0.1.0] - 2026-10-18

### Added

- Service scaffold adapted from `fa-auth-m8`'s `examples/fastapi_full`
  (`SCAFFOLD.md` maps every file): the `fastapi-m8` application factory,
  `ConsumerServiceSettings` subclass declaring every gateway key, build-once
  auth and database dependencies, the auth event-stream lifespan, the database
  health check and the optional metrics endpoint.
- Execution-route guard: every execution router is built with a mandatory
  job-context dependency that never reads the `Authorization` header and,
  until the verifier lands, refuses every request with `401 context_invalid`.
- Run-modes: web and scheduler start scripts that wait for the database and
  exit unless `alembic_version_ai` equals the packaged head, and the
  `ai-migrate` one-shot as the only command that runs Alembic.
- Two-stage `Dockerfile` on the fleet's pinned `python:3.14-slim` digest with
  the Debian patch layer, a hash-locked install, pip/setuptools/wheel removed
  and a non-root `appuser`.
- `ruff` `TID251` bans: `auth_sdk_m8` in service code, and the credential
  version model outside `ai_gateway/credentials/`.
- CI (lint, type check, bandit, pip-audit, Trivy, tests on Python 3.12–3.14
  at 100% branch coverage, tests against the shipped lock, hadolint, image
  scan, gitleaks) and the release-only Docker publish workflow.
- Repository baseline: `.codacy.yml`, `.dockerignore`, `.gitleaks.toml`,
  `.markdownlint.yaml`, `.github/dependabot.yml`, `.github/FUNDING.yml`,
  `SECURITY.md`.
