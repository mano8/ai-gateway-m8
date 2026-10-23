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
> the database and the application–database clock skew. Execution requests
> are authenticated and their job contexts verified; no execution route is
> served yet. The superuser registry (providers, models, profiles, global
> bindings) and the published-profile view are served.

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
- **Management tiers** (`ai_gateway/core/deps.py`): `CurrentReader`,
  `CurrentWriter`, `CurrentAdmin` and `CurrentSuperuser` (`require_superuser`:
  the `SUPERADMIN` role and `is_superuser`). All four use `fastapi-m8`'s
  fresh-revocation path, so a token revoked inside the positive-cache window
  is refused.
- **Execution guard** (`ai_gateway/core/execution_guard.py`). The route's
  capability comes from the `ai-sdk-m8` route table, and a route outside it
  is refused. The service client is authenticated by `fastapi-m8`'s guard over
  `AI_SERVICE_CLIENTS` with that capability's `execute:` scope. Then
  `X-AI-Job-Context` is verified (`ai_gateway/core/job_context.py`): the
  signed-object rule, `iss` holding `job-context:issue` and owning `kid`,
  `azp` equal to the presenting client, the route's capability, and `aud`
  equal to `ai-gateway/<deployment_id>` as `ai_installation` records it. The
  handler binds the request's profile and redeems `(iss, jti)` once, in the
  transaction that records the execution, with `exp` re-asserted on the
  database clock.
- **Provider client** (`ai_gateway/providers/http.py`, D-20). One
  `httpx.AsyncClient` per provider call: redirects never followed,
  `trust_env=False` on the client and its transport (no proxy variables, no
  `.netrc`, no `SSL_CERT_FILE`), TLS verification always on, no connection
  retries. Every request re-runs the destination guard on a fresh resolution
  and must target the provider's own origin; bodies are bounded both ways
  (`AI_MAX_REQUEST_BYTES`, `AI_MAX_RESPONSE_BYTES` on raw and decoded bytes),
  JSON is parsed under a depth cap, and the whole call runs under its stored
  total deadline. A per-provider circuit breaker counts transport failures,
  timeouts and 5xx only. Adapters (`ai_gateway/providers/base.py`) build fixed
  routes and extract values; `ai_gateway/providers/outputs.py` validates them
  before any settlement.
- **Adapters** (`ai_gateway/providers/registry.py`): `ollama` — `/api/embed`,
  `/api/chat` with a JSON-schema `format`, `/api/tags`; `openai_compatible` —
  `/v1/embeddings`, `/v1/chat/completions` with a `json_schema` response
  format, `/v1/rerank` (the Jina/Cohere shape) for models that declare it,
  `/v1/models`; `mistral` — `/v1/embeddings` and `/v1/chat/completions` in
  the OpenAI shape, `/v1/ocr`, `/v1/files`, `/v1/models`. Paths are appended
  to the provider's `base_url`, so an OpenAI-compatible `base_url` names the
  server root, not its `/v1`.
- **OCR** (`ai_gateway/execution/jobs.py`, `ai_gateway/providers/mistral.py`).
  A document below `AI_OCR_UPLOAD_INLINE_THRESHOLD_BYTES` whose bytes are a
  PDF or a PNG, JPEG, GIF, TIFF or WebP image is sent inline as a data URL;
  any other is uploaded as `purpose=ocr`, `visibility=user`, the shortest
  `expiry` covering `AI_PROVIDER_FILE_EXPIRY_SECONDS`, named
  `m8ai-<AI_DEPLOYMENT_ID>-<execution_id>` with a fixed media type. The
  provider is sent the gateway's reserved page list with images and blocks
  off, and the answer is held to that list. `:dispatch` reserves on the
  `spooled` row phase 1 created, under the spool binding (D-44). Every `ok`
  OCR execution carries the signed `m8.ai.ocr-receipt.v1` receipt over
  `SHA-256(JCS(OcrResult))`; without `AI_EXECUTION_RECEIPT_KEY_FILE` OCR is
  refused before any request.
- **Remote artifacts** (`ai_gateway/execution/artifacts.py`, D-43). Each
  provider-side file is a row from before its first upload byte to a
  deletion proof under the recorded credential version. The scheduler's jobs
  (run by `T33a`) age lost uploads, retire files no call can read, delete
  with backoff and park the exhausted as `manual_cleanup_required`
  (`ai_remote_artifacts{status}`), list for lost ids where permitted, and
  sweep platform keys for untracked files of this deployment's prefix when
  `AI_REMOTE_ARTIFACT_PLATFORM_SWEEP_ENABLED`.
- **Execution core** (`ai_gateway/execution/`, D-24). One call follows the
  D-24 sequence: a reservation transaction (destination by C-04 with D-08,
  the model's and provider's first use stamped and the frozen identity
  re-read, the identity pin, the `jti` redemption, the admission units of
  every signed scope, one rate-window admission per principal and the
  client's occupancy slot, all recorded on a `pending` row); the credential
  material of exactly the recorded version; the marker that re-validates
  every recorded value and moves the row to `dispatching` before any provider
  I/O; the adapter call under the stored absolute deadline; one settlement.
  Uncertain outcomes after the marker are charged, never refunded; the
  sweepers settle by stored status.

## Execution routes

Paths are the `ai-sdk-m8` route table's, under `{API_PREFIX}`; every one
needs a service client with `execute:<capability>` and a signed job context
(`X-AI-Job-Context`), and nothing else:

| Route | Body | Bounds |
| --- | --- | --- |
| `v1/execute/embed` | `EmbedRequest` | `AI_MAX_EMBED_INPUTS` inputs of `AI_MAX_INPUT_CHARS` |
| `v1/execute/rerank` | `RerankRequest` | `AI_MAX_RERANK_CANDIDATES` candidates; query and each within `AI_MAX_INPUT_CHARS`; `local` providers only |
| `v1/execute/structured-output` | `StructuredOutputRequest` | input within `AI_MAX_INPUT_CHARS`; the schema in the closed dialect, `AI_MAX_SCHEMA_BYTES`, `AI_MAX_SCHEMA_DEPTH` |
| `v1/execute/ocr` | `multipart/form-data`: `options` (`OcrRequest`), then `document` | a `phase=spool` context; the signed `input_bytes` (at most `AI_MAX_REQUEST_BYTES`); `AI_MAX_OCR_PAGES` |
| `v1/execute/ocr/{spool_id}:dispatch` | none | a `phase=dispatch` context bound to the spool |

- **Bodies.** Every body is counted while it is read, chunked or not, and
  aborted at `AI_MAX_REQUEST_BYTES` (`413 request_too_large`) before anything
  is parsed; `Content-Length` is never trusted. A body outside its model is
  FastAPI's `422`.
- **Structured output.** The schema may use `type` (`string`, `number`,
  `integer`, `boolean`, `array`, `object`), `enum`, `required`, `minimum`,
  `maximum`, `minLength`, `maxLength`, `format` (`date`, `date-time`, `uri`),
  `description`, `properties`, `additionalProperties` (a boolean), `items`,
  and `$ref` to `#/$defs/<name>` only; anything else is `422` with no
  provider call. The output is validated against it before the execution
  settles (`502 provider_rejected` otherwise, charged).
- **OCR, two phases (D-44).** Phase 1 creates the `receiving` row (the
  context redeemed, one rate admission, the client slot, the spool slot and a
  capacity reservation sized from the signed `input_bytes`), streams the
  `document` part into `AI_OCR_SPOOL_DIR` — never past the signed size and
  within `AI_UPLOAD_TOTAL_TIMEOUT_SECONDS` — checks its SHA-256, size and
  options hash, and answers `{spool_id, expires_at}` without calling any
  provider. `:dispatch` reserves the budget on that row, reads the spool under
  its lock and runs the provider call; the requested pages, or the first
  `AI_MAX_OCR_PAGES`, are the units. A spool not dispatched within
  `AI_OCR_SPOOL_TTL_SECONDS` is abandoned. `AI_MAX_CONCURRENT_SPOOLS` uploads
  at a time, and `AI_OCR_SPOOL_MAX_BYTES` reserved in all, answer `503
  capacity_exhausted` with `Retry-After` beyond them. The family is `404`
  unless `ocr` is in `AI_CAPABILITIES_ENABLED`.
- **`ocr_options_hash`** is SHA-256 over the JCS of `OcrRequest.options`
  (`{"pages": null}` when no pages are named).

## Management routes

Paths are the `ai-sdk-m8` route table's, under `{API_PREFIX}`:

| Routes | Who | What |
| --- | --- | --- |
| `v1/admin/providers`, `v1/admin/models`, `v1/admin/profiles`, `v1/admin/bindings` | superuser | providers, models, profiles with their revisions, and global bindings; every write audited |
| `v1/profiles`, `v1/profiles/{profile_key}` | reader JWT, or a `profiles:read` service client | the published profiles |
| `v1/admin/credentials` | superuser | the platform's own credentials |
| `v1/tenants/{tenant_id}/credentials` | an `ADMIN` whose token carries that `tenant_id`, or a superuser | one tenant's credentials |
| `v1/me/credentials` | `WRITER` and above | the caller's own credentials (owner and tenant from the token) |
| `v1/admin/user-credentials` | superuser | list, disable or delete a user's credential, nothing else |
| `v1/tenants/{tenant_id}/bindings`, `v1/me/bindings` | as the scope's credentials | the scope's bindings |

- **Providers.** `base_url` passes the static destination check on every
  write. `boundary` is fixed. The endpoint (`base_url`, `provider_type`,
  `auth_type`, `auth_header_name`) is frozen at first use, and a change is a
  new provider row. `enabled=false` is the emergency stop.
- **Models.** `execution_identity = h(provider_id, external_model_id,
  model_revision)` (C-07) is derived by the gateway. From the first
  reservation, the identity fields and `model_version_label` are frozen and
  `capabilities` may only shrink. A capability that a binding relies on is
  never removed. An **Ollama** model's `model_revision` is the digest its
  provider lists at `/api/tags`, read when the model is registered or renamed
  (`identity_assurance = provider_digest`, never set by hand); a model the
  provider does not list is refused (`422`), an unreachable provider is
  `503`. The scheduler re-reads the listing, and a model whose digest
  changed or vanished is flagged, audited and refused until a new row is
  registered.
- **Profiles.** Execution-affecting configuration lives in immutable
  revisions. A changed `execution_config` adds a revision and moves
  `current_revision`; its hash is `SHA-256(JCS(execution_config))`.
- **Global bindings.** A binding names a model that carries the profile's
  capability, and a global credential of that model's provider unless the
  provider takes none. A global binding cannot fall through.
- **Credentials.** Each scope has the same verbs: list, create, get, update
  (name and incident-listing consent), delete (logical), `:rotate`,
  `:validate`, `:disable`, `:enable`, `:reconfirm` and `remote-artifacts`. A
  credential outside the caller's scope answers the same `404` as one that
  never existed. No body can name a provider change, a scope, a tenant or an owner.
  The same key twice in one scope is refused (`409`). Tenant and user scopes
  hold at most `AI_MAX_CREDENTIALS_PER_SCOPE` credentials. Creates,
  rotations and validations are rate-limited per JWT `sub` (20 per minute).
  While `AI_USER_BYOK_ENABLED` is false, creating, rotating, validating,
  enabling and re-confirming a user credential answer `403`. `:validate`
  probes the provider (`GET /api/tags` or `/v1/models`) with an `active`
  credential's current version and answers `valid`, `auth_failed` or
  `inconclusive`: only a `401`/`403` counts, the third in a row makes the
  credential `invalid`, a success resets the count, and a timeout, a `5xx`,
  an open breaker or a store outage changes nothing. A binding follows its
  credential: unless the credential is `active`, the binding is
  `credential_unavailable`.
- **Bindings and resolution (C-04).** A binding names a model and one of
  its own scope's credentials. An execution resolves the user binding first,
  then the tenant's, then the global one, from the signed context's
  `(tenant_id, user_id)` only. A scope without a binding falls through. A
  scope with one fails closed when its credential is unavailable, unless its
  owner set `fall_through`, and each fall-through is audited. The D-08 policy
  is then applied to the candidate actually resolved, and a denial there is
  final.
- **Published profiles.** A profile is published when it has a global
  binding. Embedding profiles carry `dimensions` and `embedding_space_id =
  h(provider_id, external_model_id, model_revision, dimensions,
  execution_config_hash)`. OCR profiles carry the model's
  `ocr_execution_identity`.
- **Own database.** PostgreSQL `ai_db` with its own `alembic_version_ai`
  table. Migrations are packaged with the image. Two roles: `ai_owner` owns
  the schema and is used only by `ai-migrate`; `ai_runtime` (web and
  scheduler) has DML on the operational tables, `INSERT`/`SELECT` only on the
  audit tables, `SELECT` only on the installation row, and no DDL. The schema
  enforces the invariants itself: the D-24 execution and D-43 remote-artifact
  transition tables, endpoint and model identity frozen at first use,
  immutable profile revisions, credential ownership fixed at creation,
  version numbers never reused, a deferred check that an active credential
  points at committed live material, and material that cannot be destroyed
  while a provider file or a sweep obligation needs it.

## Run-modes

One image, three commands:

| Command | Role | Migrates? |
| --- | --- | --- |
| `ai_gateway/scripts/docker_start.sh` (default `CMD`) | web | never |
| `ai_gateway/scripts/scheduler_start.sh` | scheduler | never |
| `ai_gateway/scripts/ai_migrate.sh` | `ai-migrate` one-shot, schema-owner role: `alembic upgrade head`, then records the installation (`python -m ai_gateway.installation init`) | the only one |

The web and scheduler run-modes wait for the database, then read
`alembic_version_ai` and exit unless it equals the head packaged in the image
(`python -m ai_gateway.prestart`), and exit unless the database records
this `AI_DEPLOYMENT_ID` as its installation. Run `ai-migrate` first after
every upgrade. The migration grants privileges to the runtime role
`ai_runtime` (override with `alembic -x runtime_role=<name>`), which the
database bootstrap must create beforehand.
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
- under `production`/strict, any admission bound left unset: the three daily
  budgets (`AI_CLIENT_`, `AI_TENANT_`, `AI_USER_DAILY_BUDGET_UNITS`),
  `AI_RATE_LIMIT_PER_MINUTE` and `AI_MAX_INFLIGHT_PER_CLIENT`. Elsewhere an
  unset bound is not enforced, though every counter is kept;
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

## Credential storage and key rotation

The `database` backend stores each credential version as an AES-256-GCM
envelope in `ai_db`. Every version gets a fresh data key bound to the
version's row context. With the `local` KEK the data key is wrapped by the KEK
file. With `vault_transit`, the recommended hardened mode, it is wrapped by
a Vault transit key, the version's context is sent as associated data, and
the gateway holds no KEK at all. The `vault` KV backend (`T24`) is not served
yet, and a deployment configured for it refuses to start. The web and
scheduler run-modes also refuse to start while a stored version needs a KEK
or fingerprint-key generation this replica does not hold, and they name it.

Rotate a key in the D-23 order:

1. Deploy the new key to every replica as decrypt-only
   (`AI_CREDENTIAL_KEK_PREVIOUS_FILES`, or
   `AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE`).
2. Switch the active key on every replica.
3. Check `/meta`: every replica must report the new generation.
4. Run `python -m ai_gateway.credentials rewrap` (or `refingerprint`).
5. Run the same command with `--verify`, which exits `1` while any row is
   still under an older generation.
6. Only then remove the old key, into offline escrow until the backup
   retention horizon has passed.

`python -m ai_gateway.credentials generations` prints the rows per
generation. Each command prints generation labels and counts only, and each
change is audited.

For `vault_transit`, the rotation follows the same order on Vault's key
versions: rotate the transit key, run `rewrap` and then `rewrap --verify`,
and only then raise `min_decryption_version`. Never set the key's
`exportable` flag. The gateway's AppRole (or token) needs only this policy;
it never reads the key's metadata:

```hcl
path "transit/encrypt/<key>" { capabilities = ["update"] }
path "transit/decrypt/<key>" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
```

## Remote-artifact residual risk

A provider file the scheduler could not prove deleted stays
`manual_cleanup_required`, and the version it was uploaded under cannot be
destroyed. After deleting it by hand, or accepting that it outlives its
row, an operator closes the row as an accepted residual risk (never as
cleanup):

```bash
python -m ai_gateway.execution remote-artifact accept-residual \
    --id <artifact-id> --evidence "<ticket or note>"
```

The command writes an `ai_admin_audit` row with the remote id, the file
name, the provider's expiry and the evidence, and exits `1` when no parked
row has that id.

A spool whose lock file vanished while its reservation is held (the
`spool_lock_missing` warning) keeps its capacity charged until an operator,
having confirmed no process holds its data file, releases it:

```bash
python -m ai_gateway.execution spool repair \
    --id <execution-id> --evidence "<how it was confirmed>"
```

The release is audited (`spool.repair`), and the next orphan pass removes the
data file.

## Deployment

Compose stacks will live under `docker_compose/`; none ships yet. Images are
published by `.github/workflows/docker-publish.yaml` on a published GitHub
release only (multi-arch, Trivy-gated, SPDX SBOM, keyless cosign signature,
build provenance).

See [`SECURITY.md`](SECURITY.md) for the threat model and how to report a
vulnerability, and [`SCAFFOLD.md`](SCAFFOLD.md) for the template this service
was adapted from.
