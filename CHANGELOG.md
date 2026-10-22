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
- The credential-store contract (`T21`, `ai_gateway/credentials/store.py`):
  `store`, `replace`, `resolve_for_execution` (the recorded, current version
  of an active credential only), `resolve_for_cleanup` (retired versions
  too), `delete`, `destroy`, `rewrap`, `refingerprint`, `generations` and
  `health`. The plaintext is a `ResolvedSecret`: redacted when shown, wiped
  when its block ends. One contract test suite runs against every backend.
- `DatabaseCredentialStore` with the `local` KEK (`T22`): an AES-256-GCM
  envelope per version, with a fresh data key wrapped under the KEK file and
  both bound to the C-05 row context; scope-bound HMAC fingerprints;
  resolution bounded by `AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS`; logical
  delete; destruction that keeps the tombstone; `rewrap` and `refingerprint`.
  `python -m ai_gateway.credentials generations|rewrap|refingerprint
  [--verify]` runs the D-23 rotation steps and audits each change.
- Credentials per scope (`T20`) at `v1/admin/credentials`,
  `v1/tenants/{tenant_id}/credentials` and `v1/me/credentials`: create, list,
  get, update (name, incident-listing consent), logical delete, `:rotate`,
  `:disable`, `:enable`, `:reconfirm` and `remote-artifacts`. Scopes come from
  the route and the token only (D-05, A-1). A foreign or missing id answers
  one `404`. A same-scope duplicate key is `409`. The per-scope cap holds
  under concurrency, and creates and rotations are rate-limited per `sub`.
  Bindings follow their credential's status, and every transition is
  audited in `ai_credential_audit`. The superuser's `v1/admin/user-credentials`
  stop lists, disables and deletes user keys only (A-2).
- Tenant and user bindings (`T20a`) at `v1/tenants/{tenant_id}/bindings` and
  `v1/me/bindings`, with the same rules as global bindings. A credential the
  scope does not hold answers one `422`. While BYOK is off, user binding
  writes answer `403`.
- C-04 resolution (`controllers/resolution.py`), for the reservation to call:
  user → tenant → global from the signed claims; an unavailable credential
  fails closed unless the owner set `fall_through`, which is audited; D-08,
  the `rerank` local-only rule, `allowed_boundaries` and the restricted-OCR
  restore residual on the resolved candidate, each refusal final. The
  embedding space is derived from the resolved model and profile revision.
- `/health` reports the user bindings held unavailable while
  `AI_USER_BYOK_ENABLED` is false (degraded while any exist).
- The `vault_transit` KEK provider (`T23`). `hvac` runs on a dedicated
  session with `trust_env=False`, TLS verification always on and redirects
  refused. Authentication is `token_file` (re-read on a `403`) or `approle`
  (a new login before 80 % of the lease, and once on a `403`). Data keys are
  wrapped by `transit/encrypt` and unwrapped by `transit/decrypt`, with the
  version's AAD as associated data. Generations are labelled `transit-v<n>`,
  and `rewrap` decrypts and encrypts under the latest version. The health
  probe is `lookup-self` plus an encrypt → decrypt round trip, never a
  metadata read. `database` + `vault_transit` deployments are now served.
- `/health` reports the credential store (KEK probe). The web and scheduler
  refuse to start while a stored version needs a KEK or fingerprint-key
  generation the replica does not hold.
- Published profiles at `v1/profiles` for reader JWTs and `profiles:read`
  service clients: keys, capability, revision, dimensions,
  `embedding_space_id`, `ocr_execution_identity` and `identity_assurance`;
  never a credential or `base_url`.
- The hardened provider client (`T26`, `ai_gateway/providers/`): one
  `httpx.AsyncClient` per provider call with redirects refused,
  `trust_env=False` on the client and its transport, TLS verification on and
  no connection retries; the destination guard on every request; fixed,
  URL-encoded routes; the credential in its validated header only; request
  and response caps (raw and decoded), a JSON depth cap and the call's total
  deadline; dispatch progress recorded before the first request byte; a
  per-provider breaker fed by transport failures, timeouts and `5xx` only;
  `429` cooldowns from a bounded `Retry-After` on the database clock; closed
  `ProviderFailure`s that keep no provider text. The adapter protocol and the
  shared output validator (embeddings, rerank hits, OCR pages).
- `AiError` answers carry the provider status class and closed
  `provider_metadata` when a provider call failed.
- The execution core (`T27`, `ai_gateway/execution/`): `ExecutionService.run`
  follows the D-24 sequence — the reservation transaction (C-04/D-08
  resolution, first-use stamps with the identity re-read after them, the
  identity pin, the `jti` redemption, admission units per signed scope, one
  rate-window admission per principal, the client's occupancy slot, the
  `pending` row recording the resolved provider, boundary, model, profile
  revision, credential version and context `exp`); the material fetch of
  exactly the recorded version; the marker re-validating everything
  recorded before any provider I/O; the adapter call under the stored
  absolute deadline; one compare-and-set settlement from the recorded scopes
  and budget day. Jobs for embedding, rerank and structured output fix their
  admission units before dispatch and validate every answer. Sweepers settle
  expired `pending` rows as `abandoned` and stale `dispatching` rows as
  `charged_uncertain`.
- Under `production`/strict the settings refuse to boot without the three
  daily budgets, the rate limit and the in-flight cap.
- The Ollama adapter (`T28`): `POST /api/embed` (`truncate: false`), `POST
  /api/chat` with the request's JSON schema as `format`, `num_predict` set to
  the reserved output cap and `temperature: 0`, and `GET /api/tags` as the
  probe. Registering or renaming an Ollama model reads its listed digest into
  `model_revision` with `identity_assurance = provider_digest` (an unlisted
  model is `422`, an unreachable provider `503`); `DigestReader.recheck`
  flags and audits a model whose digest changed or vanished, and flagged
  models are never reserved or dispatched.
- An embedding of the wrong dimension is audited against the model
  (`model.incident`).

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
- `cryptography>=48.0.1` is a direct requirement (the envelope uses it); the
  lock is unchanged except for that annotation.
- A deployment configured for the `vault` KV backend refuses to start until
  that store lands (`T24`).
- `hvac>=2.3.0` is a direct requirement. The lock adds `hvac` 2.4.0,
  `requests` 2.34.2, `urllib3` 2.8.0 and `charset-normalizer` 3.5.2, and
  moves `certifi` 2026.7.22 → 2026.10.19 (PYSEC-2026-4320) with a narrow
  `--upgrade-package certifi`; no other pin moved.
- Management routes live under `v1` (`v1/admin`, `v1/profiles`), the
  `ai-sdk-m8` route table's paths, instead of `/manage`.
- The route walk also refuses any unexpected query parameter, which is how
  an annotation FastAPI cannot resolve would show itself.
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
