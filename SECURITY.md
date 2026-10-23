# Security

`ai-gateway-m8` is the only service of the m8 stack that holds AI provider
credentials. Security is its governing priority: where a simpler and a safer
design compete, the safer one wins.

## Reporting a vulnerability

Report a suspected vulnerability privately through this repository's GitHub
**Security → Report a vulnerability** form (a private security advisory). Do
not open a public issue, and do not include live credentials or provider keys
in the report. Expect an acknowledgement within seven days.

## Supported versions

The gateway has not been released yet. Once it is, only the latest minor
release receives security fixes.

## Threat model

> Skeleton. Each section names the threat and the control that answers it; the
> controls are delivered by the tasks that implement them, and this file is
> completed alongside them.

### Assets

Provider credentials (user, tenant and platform scope), key-encryption keys
and fingerprint keys, signed job contexts, execution receipts, the OCR spool,
and the data each provider call discloses.

### Trust boundaries

- Users → management routes (issuer JWT, tier-gated).
- Fleet services → execution routes (service-client credentials plus a signed,
  single-use job context; never a user JWT).
- Gateway → providers (outbound destination policy; local and external
  boundaries).
- Gateway → issuer (JWKS and the private revocation API).
- Gateway → its own database and, when configured, Vault.

### Credential storage and decryption

Only the gateway decrypts provider credentials, and only through the
`CredentialStore` contract (`ai_gateway/credentials/store.py`, C-06). Nothing
outside `ai_gateway/credentials/` may import or name the credential-version
table (`ruff` `TID251` and a grep test).

- An execution resolves **exactly** the version its execution row recorded,
  and only while the credential is `active` and that version is current.
  Anything else, including a retired version or a disabled, invalid, deleted
  or re-confirmation-pending credential, is `credential_unavailable`, with no
  cause given. A binding is never read at that point.
- Provider-file cleanup has its own entry point. It accepts a retired version
  and a non-`active` credential while the version's material exists, and is
  never used to execute.
- The plaintext exists only inside a `with` block, as a `ResolvedSecret`. Its
  `repr` and `str` are redacted, and its buffer is overwritten when the block
  ends, however it ends. The wipe is best effort: a `str` copy handed to the
  HTTP client cannot be erased by Python.

**Envelope (database backend).** Each version is sealed with AES-256-GCM
under a fresh random 256-bit data key and a random 96-bit nonce. The data key
is wrapped under the KEK with AES-256-GCM. Both are bound to the same
additional data: the length-prefixed `credential_id`, `version`,
`provider_id`, `scope_type`, `tenant_id` and `owner_user_id`. Ciphertext
moved to another row, a truncated tag, a changed scope or a KEK generation
that is not configured therefore never decrypts, and each answers
`credential_unavailable`. AES-GCM authenticates before it releases anything,
so no partial plaintext is returned. A database dump holds ciphertext and
wrapped keys only.

**Keys.** The KEK and the fingerprint key are separate 32-byte files, read
once, mode-checked and never taken from an environment variable. A row
records the generation it needs as a purpose-tagged digest label, never the
key itself. A replica refuses to start while any stored row needs a
generation it does not hold. A rotation re-wraps data keys without touching
ciphertext (`rewrap`), and `--verify` proves no row remains under the old
generation before the key is removed.

**Vault (`vault_transit`).** `hvac` runs on its own `requests` session, which
ignores the environment (proxy variables and `.netrc` alike) and always
verifies TLS (`AI_VAULT_CA_FILE` or the system store). It refuses redirects,
because `requests` would forward `X-Vault-Token` to another host, and Vault
speaks only `https` under production/strict. An AppRole login is renewed
before its lease ends, and a `403` logs in again once. The token and the
`secret_id` are never logged. Data keys are wrapped and unwrapped with the
version's AAD as associated data. Health and execution use only
`lookup-self`, `encrypt` and `decrypt`, never a read of the key's metadata.
An unreachable Vault answers `credential_unavailable` for reads and writes,
never a fallback to another key.

**Fingerprints.** A fingerprint is HMAC-SHA256 under the fingerprint key over
the credential's scope and the secret. It can only detect the same key twice
within one tenant's or one user's scope. The same key in two scopes has two
unrelated fingerprints, so nothing can link them. Fingerprints are never
returned.

**Resolution failures** answer `credential_unavailable` and are logged by
exception type only. A slow database is cut off after
`AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS`.

### Credential access (D-05, A-1, A-2)

- Tenant credentials are managed by an `ADMIN` whose token carries the
  tenant's `tenant_id`, or by a superuser. A token without `tenant_id`
  matches no tenant.
- Personal (user-scope) credentials are managed by their owner at the
  `WRITER` tier and above. The owner is the JWT `sub` and the tenant is the
  token's `tenant_id`, both fixed at creation. A matching-tenant `ADMIN` has
  no access to them.
- The superuser can only **disable or delete** a user's credential, for
  incident response and offboarding. No route lets anyone create, rotate,
  validate, re-enable or bind a key on its owner's behalf, because whoever
  sets a binding's credential decides where that user's data goes.
- Every refusal on another scope's credential is the `404` a missing id
  gets, with the same body. Fingerprints are scope-bound, so storing a key
  that another scope already holds looks like storing any new key.
- Every transition writes `ai_credential_audit`, and each row is logged as an
  `ai_gateway.audit` event after the commit. Neither carries the secret or
  its fingerprint.

### Job-context forgery, replay and substitution

A context is accepted only when all of these hold, and every refusal is a
typed `401` (`context_missing`, `context_invalid`, `context_expired`,
`context_replayed`) that never echoes the token:

- the presenting service client authenticates (hashed secret, constant-time
  comparison) and holds `execute:<capability>` for the route;
- the header is at most 4 KiB, checked before decoding; the payload is strict
  canonical JSON in strict unpadded base64url, checked before any signature
  work; the signature verifies under the `m8.ai.job-context.v1` domain, so a
  receipt or attestation signed by the same key is refused;
- `iss` holds `job-context:issue` and owns `kid`: a context signed with
  another client's key is refused even when that key is registered;
- `azp` is the presenting client, `aud` is this installation as
  `ai_installation` records it, the capability is the route's and the profile
  is the request's;
- `iat`/`nbf` lead the clock by at most `AI_JOB_CONTEXT_CLOCK_SKEW_SECONDS`,
  `exp` gets no leeway, and the lifetime is within the context or dispatch TTL;
- `(iss, jti)` is redeemed once (`max_uses = 1`) by a single atomic statement
  that also asserts `exp > now()` on the database clock, so a replica whose
  clock lags cannot redeem an expired context. The redemption commits with the
  row transition it authorizes.

### Data-class policy and provider destinations

The gateway resolves the destination itself, inside the transaction that
records it on the execution row (`ai_gateway/controllers/resolution.py`). The
destination checked is therefore the destination dispatched, and a binding
repointed after that point changes nothing.

- **Precedence.** User binding, then tenant binding, then global binding.
  The user binding consulted is the one whose tenant and owner equal the
  signed context's `tenant_id` and `user_id`. A context without `user_id`
  never reaches one, and a user's binding never serves another tenant.
- **Unavailable credentials fail closed.** A bound credential that is
  disabled, invalid, deleted, awaiting re-confirmation or throttled answers
  `credential_unavailable` (or `rate_limited` with `Retry-After`) before any
  provider request. The same holds for a user binding while
  `AI_USER_BYOK_ENABLED` is false. Only `fall_through`, set by the binding's
  owner, moves on to the next scope, and every such move is audited.
  Switching user BYOK off never silently moves a user's data to the tenant's
  or the platform's key, and `/health` counts the user bindings it holds.
- **Destination policy, applied to the resolved candidate.** `rerank` goes to
  `local` providers only, whatever the policy says (`boundary_denied`). A
  signed `allowed_boundaries` claim must contain the provider's boundary.
  `internal` and `restricted` data reach `local` providers or the context's
  own BYOK credential, never an external platform key (`data_class_denied`).
  On the database backends, `restricted` OCR never goes to an `external`
  provider while the restore residual is not accepted. A denial is final: it
  never sends the request on to the next scope.

### Server-side request forgery and outbound egress

A provider's `base_url` is checked when it is written and again, with every
DNS answer, before each call (`ai_gateway/core/ssrf.py`):

- loopback, link-local (including `169.254.169.254`), multicast, reserved and
  unspecified addresses are refused for every provider, before any allowlist;
  IPv4-mapped IPv6 is normalised first;
- an `external` provider needs globally routable answers only (RFC 1918, ULA
  and CGNAT are refused), port 443 or a listed port, and HTTPS under
  production/strict;
- a `local` provider needs an allowlisted `name:port` pair
  (`AI_PROVIDER_ALLOWED_INTERNAL_HOSTS`); only that pair is exempt from the
  private-address rule;
- userinfo, query and fragment are refused; names are compared after IDNA
  normalisation.

**DNS-rebinding residual (R-11).** The check and the connection resolve the
name separately, so an answer that changes between them is not caught by the
guard. TLS hostname verification on `external` providers mitigates it;
closing it needs connect-time destination enforcement (an egress proxy), a
named follow-on. These rules bind the gateway's own code only: code running
inside a compromised gateway is not constrained by them.

**Frozen endpoints.** Only the superuser registers providers. A provider's
`boundary` never changes. Its `base_url`, `provider_type`, `auth_type` and
`auth_header_name` freeze at first use (the first credential that references
it, or its first outbound request), so a stored credential is never sent to
an endpoint other than the one it was stored against. The controller refuses
the change with `409`, and a database trigger refuses it again when the
controller is bypassed. A credential header name is a lower-case `x-…` name
or `api-key`, never `x-forwarded-`, `x-internal-` or `x-ai-`, so hop-by-hop,
routing and gateway headers cannot carry a key.

**The provider client** (`ai_gateway/providers/http.py`, D-20). Each provider
call gets its own client, closed when the call ends, so no connection, header
or credential is shared between providers:

- redirects are never followed: a `3xx` is `provider_rejected`, and a
  redirect to `169.254.169.254` sends nothing there;
- `trust_env=False` on the client **and** its transport: proxy variables,
  `.netrc`, `SSL_CERT_FILE` and `SSL_CERT_DIR` are ignored; TLS verification
  is always on, and a test greps the package for any switch that turns it
  off;
- an httpx request hook runs the destination guard above on **every**
  request, on a fresh resolution, and refuses a request to any origin other
  than the provider's own;
- paths come from fixed templates per `provider_type`, every segment
  URL-encoded; query parameters are fixed by the adapter, never taken from a
  caller;
- the credential is put only in its validated header, from the call's
  `ResolvedSecret`; a value that is not printable ASCII is refused rather
  than sent;
- request bodies are bounded by `AI_MAX_REQUEST_BYTES` before sending;
  answers are counted on the wire **and** after decoding against
  `AI_MAX_RESPONSE_BYTES` (`Accept-Encoding: identity` is requested, a
  `gzip`/`deflate` answer is inflated in steps that never exceed what is
  still allowed, any other coding is refused), and JSON is parsed with a
  depth cap and `NaN`/`Infinity` refused;
- the call runs under `asyncio.timeout_at` at its stored total deadline, and
  the remaining time is checked again before connecting and before writing:
  per-chunk read timeouts bound nothing on their own;
- a per-provider circuit breaker counts transport failures, timeouts and
  `5xx` only. A `401`/`403` is the credential's outcome and a `429` backs off
  that credential (`throttled_until` on the database clock, at most
  `AI_PROVIDER_MAX_BACKOFF_SECONDS`, 60 s when `Retry-After` is absent or
  unparsable, never shortened), so one tenant's invalid or throttled key opens
  no breaker for another. Breaker state is per process.

The **DNS-rebinding residual**, measured: with a test CA, a connection that
lands on a host other than the one the guard resolved fails its TLS
handshake before any byte is sent unless that host holds a valid certificate
for the provider's name, in which case it is reached. That last case is the
stated residual.

### Prompt injection and untrusted provider output

A provider answer is untrusted input. Adapters only extract values; whether
they are usable is decided by the shared validator
(`ai_gateway/providers/outputs.py`), which every result must pass before
settlement: exactly one vector per input, each of the model's declared
dimensions, every component finite; rerank indexes in range and unique with
finite scores; never more OCR pages than were reserved and requested. A
failed check is `provider_rejected`, and nothing partial is returned.

Failures are closed (D-41): a `ProviderFailure` carries a code, the provider's
status class, a bounded `Retry-After` and adapter-chosen metadata in the
closed `provider_metadata` shape. Provider bodies, headers and exception text
are discarded, never excerpted, so a hostile error body (plain, base64 or
split across lines) reaches no response, log line or traceback.

### Denial of wallet and resource exhaustion

The bounded quantity is **admission units**, fixed before dispatch from the
request and the recorded profile revision (D-24): input characters for
embeddings, query plus candidate characters for rerank, input characters
plus the output cap passed to the provider for structured output, and the
pages the gateway itself requests for OCR. Provider-reported tokens are
recorded separately and never settle a charge; no monetary bound is claimed.

- **One reservation transaction** (`ai_gateway/execution/reservation.py`)
  resolves the destination, redeems the job context, reserves the units of
  every scope the **signed** context names (`client` always, `tenant` and
  `user` when present) with `UPDATE … WHERE reserved + used + :units <=
  :budget`, charges one rate-window admission per principal, takes the
  client's occupancy slot and records it all on a `pending` row. A refusal
  rolls everything back. A user is bounded by its own budget, window and the
  client's slots whoever's credential resolved.
- **The marker** commits `dispatching` before any provider I/O and
  re-validates everything recorded: reservation and context unexpired on the
  database clock, provider enabled at its boundary, model enabled and
  unflagged, profile enabled at the recorded revision, the recorded version
  still the current version of an active, unthrottled credential. A change
  committed before it stops the call; one committed after it does not stop
  that one call (bounded by `AI_PROVIDER_TOTAL_DEADLINE_SECONDS`).
- **Settlement** is one compare-and-set on the stored status, from the
  recorded scope ids and budget day — midnight crossings settle on the day
  reserved. Only established pre-dispatch outcomes are refunded: anything
  before the marker, and after it only a transport failure the client
  guarantees sent no byte, while `first_byte_sent_at` is null (the schema
  refuses any other refund). A timeout, a transport loss, a cancellation or a
  crash after the marker is `charged_uncertain`. A late answer after a
  sweeper settled the row is discarded.
- **Sweepers** act by stored status: `pending` past
  `reservation_expires_at` → `abandoned`; `dispatching` past its deadline plus
  the grace → `charged_uncertain`. Every terminal transition returns the
  occupancy slot exactly once.
- Under `production`/strict the gateway refuses to start without every
  budget, the rate limit and the in-flight cap.

### Credential material on the execution path

The material fetch is the only credential-store I/O of a call, and it fetches
exactly the `(credential_id, version)` the reservation recorded — a binding
repointed meanwhile changes nothing. It happens before the marker: a store
that fails or stalls past `AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS` releases the
reservation (`credential_unavailable`) with no provider request. The
plaintext lives from that fetch to the end of the adapter call and is wiped
on every path, a zero-row marker and a cancelled request included.

### Logging, metrics and error disclosure

Every privileged change (providers, models, profiles, bindings) writes an
`ai_admin_audit` row in the same transaction. The row records the actor's id
and role, the target, and before/after values, never a secret, within the
table's 4 KiB bound: long values are replaced by their SHA-256. After the
commit, each row is also logged as one `ai_gateway.audit` event, so a restore
that rewinds `ai_db` does not erase the record of later changes. A change
that rolls back is not logged. The runtime role can insert and read audit
rows but never update or delete them.

Readers and `profiles:read` service clients see the published profiles only:
keys, capability, revision, dimensions, `embedding_space_id`,
`ocr_execution_identity` and `identity_assurance`. They never see a
credential, a provider or its `base_url`.

### Model identity (LLM03, D-11)

A model's identity is `execution_identity = h(provider_id, external_model_id,
model_revision)`, frozen from its first reservation. How much of it the
provider vouches for is `identity_assurance`, reported to every consumer:

- `provider_digest` — **Ollama**: the gateway reads the digest the provider
  lists at `/api/tags` when the superuser registers or renames the model and
  records it as `model_revision`; no one sets it by hand. The scheduler
  re-reads the listing, and a model whose digest changed or vanished is
  flagged and audited (`model.flagged`), after which every reservation and
  every marker refuses it — a silent same-dimension model swap never reaches
  an index. An unreachable provider or a malformed listing flags nothing.
- `pinned_snapshot` — a dated, immutable provider model id the superuser
  registered;
- `operator_declared` — the operator's statement only.

An embedding of a dimension other than the registered model's is refused as
`provider_rejected` and audited against the model (`model.incident`,
`dimension_mismatch`).

### Provider-side files (D-43)

An OCR upload leaves a file at the provider. It is tracked from before its
first byte: the intent row is committed with `first_byte_sent_at`, so a
crash at any later point leaves a row the scheduler owns, and that row's
foreign key keeps the credential version alive — no version a file was
uploaded under can be destroyed while its row exists. Only the gateway's
own name (`m8ai-<deployment>-<execution>`) and a fixed media type reach the
provider; the file is private to the key's user (`visibility=user`) and
expires.

Cleanup, listing and confirmation use the **recorded** credential version
only, never the current one, whatever happened to the credential since. A
row closes only on the provider's documented deletion proof (Mistral:
`200 {deleted: true}` for the recorded id). A `404`, a negative listing or a
passed expiry is evidence only: after its retries such a row is parked as
`manual_cleanup_required`, alerted, and closed only by a later proof or an
audited `accept-residual`. A listing keeps only names of this deployment's
prefix; another installation's or a tenant's files are never logged,
stored or deleted. Incident listings run under a platform key when
`AI_REMOTE_ARTIFACT_PLATFORM_INCIDENT_LISTING` allows it, and under a
tenant's or a user's key only with its `incident_listing_consent`.

### Execution request bodies (T31)

Every execution body is read once from the stream and counted as it
arrives, so neither an absent nor a false `Content-Length` lets more than
`AI_MAX_REQUEST_BYTES` in, and nothing is parsed before the cap holds. The
OCR form is read without FastAPI's spooling `UploadFile`: exactly two parts
(`options`, then `document`), part headers of at most 8 KiB, and the
client's file name ignored. A structured-output schema is admin- or
caller-authored input: it is accepted only in a closed dialect with no
`pattern`, no combinators and no remote or relative `$ref`, bounded in
size and depth, and the gateway's own validator resolves references inside
the schema only, so no reference can reach the network or a file.

### The OCR spool (D-44, D-45)

A document is spooled and verified before any provider sees it, and only
under the signed claims: no byte past the signed `input_bytes` is written,
and the digest, size and options hash must equal the spool context's. The
reservation is sized from those signed bytes, rounded up to the
filesystem's allocation unit, so a client header never sizes it. Only
`ai_gateway/execution/spool.py` opens spool files. Its lock lives on a
separate file whose identity outlives the data, and no data descriptor is
opened outside a held, re-validated lock. A cleaner therefore never frees
the reservation of blocks a paused reader or writer still holds, and the
release happens exactly once. A dispatch context must equal every claim the
spool recorded, the presenting client included, or nothing is sent.

### Sweepers and recovery (T32)

The sweepers settle by stored status through the same compare-and-set as
the handler, so a row is settled once and its occupancy slot returned
once, whichever side gets there first; a dispatched row past its deadline is
charged, never refunded. Spool cleanup goes through the lock discipline: a
held lock defers it, a crash between the data unlink and the release, or
between the release and the lock unlink, is finished on the next pass with
the reservation released exactly once. A lock that vanished while its
reservation is held is never released automatically; only the audited
`spool repair` command releases it.

### Credential validation (T25)

`:validate` sends one minimal authenticated request with the credential's
current version to the provider's frozen endpoint, through the same D-20
client as an execution (destination checks, no redirects, bounded bodies).
Only the provider's own `401`/`403` counts against the key, and it never
opens the provider's breaker; a gateway-side failure (a timeout, a store
outage, an open breaker) cannot invalidate a key. An outcome is recorded
only while the probed version is still current, so a rotation during the
probe is never charged with the old key's failures. No header, body or
secret is logged, returned or audited.

### OCR provenance receipt (C-01)

Every `ok` OCR result carries an Ed25519 receipt under the domain tag
`m8.ai.ocr-receipt.v1`, signed with the web service's receipt seed. It
binds the installation, the execution, the job context's `job_ref`,
`attempt`, `azp`, `profile_key`, `input_sha256` and `ocr_options_hash`, the
execution identity and `SHA-256(JCS(OcrResult))` of the exact body
returned. A different domain tag makes it fail as a job context or an
attestation; the seed signs nothing else.

### Supply chain and image provenance

### Database roles, migrations and restore

## Controls in place in this scaffold

- Execution routes require an authenticated service client with the route's
  `execute:` scope and a verified, single-use job context; the guard never
  reads `Authorization`, and a route whose capability the SDK route table does
  not declare is refused.
- No API-key principal is wired on any route.
- Service code cannot import `auth-sdk-m8` directly, and only
  `ai_gateway/credentials/` may import the credential version model
  (`ruff` `TID251`, enforced in CI).
- Settings refuse unknown keys and fail at startup on a missing required key.
- The web and scheduler never migrate; they exit unless the database revision
  equals the packaged head.
- Database health failures are reported by exception type only, never by
  message.
- The image installs a hash-locked set, carries no pip, runs as `appuser` and
  supports a read-only root filesystem.
