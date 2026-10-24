# Security

`ai-gateway-m8` is the only service of the m8 stack that holds AI provider
credentials. Security is its governing priority: where a simpler and a safer
design compete, the safer one wins.

This file is the gateway's threat model, its control register and its
security runbooks. Every control names the tests that prove it, as
`<file>::<test>` under `tests/`. A control that only another repository or
a deployed stack can prove says so ("Proven outside this repository") and
names where. `tests/test_security_doc.py` fails when a cited test does not
exist, and when a control section does neither.

## Reporting a vulnerability

Report a suspected vulnerability privately through this repository's GitHub
**Security → Report a vulnerability** form (a private security advisory). Do
not open a public issue, and do not include live credentials, provider keys,
key files or job contexts in the report. Expect an acknowledgement within
seven days.

A useful report names the gateway version or commit, the run-mode (web,
scheduler or `ai-migrate`), the credential backend, and the smallest request
or configuration that shows the problem. Reports are handled as coordinated
disclosure: the fix and an advisory are published together, and the reporter
is credited unless they ask not to be.

In scope: anything that lets a caller reach a provider, a credential, a
document or a budget it was not authorized for; anything that makes the
gateway disclose a secret, a token or content; and any way past a control
this file states. A residual this file already states is not a
vulnerability by itself, but a way to widen one is.

## Supported versions

The gateway has not been released yet. Once it is, only the latest minor
release receives security fixes.

## Supported topology

One Docker host, or an isolated LAN segment under `auth-sdk-m8`'s
single-host trust. Services talk plain `http` on internal compose networks,
as the rest of the fleet does. A multi-host deployment needs mutual TLS
between services first, which is a named follow-on. The OCR spool is
single-host by design: its locks need one kernel and a local filesystem
(D-45), and every gateway and scheduler process refuses to start on any
other.

## Assets

| Asset | Where it lives | Who can read it |
| --- | --- | --- |
| Provider credentials (platform, tenant and user scope) | AES-256-GCM envelopes in `ai_db`; plaintext only in gateway or scheduler memory for one call | the gateway web and scheduler processes |
| The KEK (`local`) or the transit key (`vault_transit`) | a Docker secret file on the web and scheduler services; the transit key never leaves Vault | the same two processes |
| The fingerprint key | a Docker secret file on the web service only | the web process |
| The OCR receipt seed (Ed25519) | a Docker secret file on the web service only | the web process |
| Vault AppRole or token | Docker secret files on the web and scheduler services | the same two processes |
| Service-client secrets | held by each client; the gateway holds salted SHA-256 digests only | the client that owns it |
| Job-context signing seeds | media-service only; the gateway holds public keys | media-service |
| Database passwords (`ai_owner`, `ai_runtime`) | Docker secrets: `ai_owner` on `ai-migrate` only | the run-mode that needs it |
| The installation identity (`AI_DEPLOYMENT_ID`) | configuration and `ai_installation`; not secret, but never regenerated | operators |
| Documents in transit | the OCR spool (`/spool`), then the provider | the web process; the scheduler deletes |
| Provider-side files | the provider account of the credential version that uploaded them | that account's owner |
| Execution, usage and audit records | `ai_db` (metadata only, never content or secrets) | operators; tenants see their own aggregates |
| Budgets and capacity | `ai_db` counters | the gateway |

## Trust boundaries

- **Users → management routes.** Issuer JWTs only, through `fastapi-m8`'s
  fresh-revocation tiers. No API-key principal is wired.
- **Fleet services → execution routes.** A hashed service-client secret with
  the route's `execute:` scope, plus a signed, single-use job context. A user
  JWT is never read on these routes.
- **media-service → the gateway.** media-service owns classification: it
  derives `data_class` from the object's live state and signs it. The gateway
  owns provider and binding policy, enforced from that signed class.
- **Gateway → providers.** The hardened client on `ai_egress` (external) or
  `ai_net` (local runtimes). Providers are outside the trust boundary: they
  receive what is sent to them and return untrusted output.
- **Gateway → issuer.** JWKS and the private revocation API, over the
  internal network.
- **Gateway → its database and Vault.** `ai_db` under two roles; Vault over
  `https` under production/strict.
- **Web ↔ scheduler.** One image and one credential trust boundary. The
  scheduler holds neither the fingerprint key nor the receipt seed.
- **Gateway → the log sink.** Audit events are mirrored there as evidence,
  never as authority.
- **The media document chain.** The documents worker is transport. Derived
  content is accepted only through the sandbox attestation and the gateway's
  OCR receipt (D-47, below).

## Threat model

Each threat names what an attacker gains, the controls that answer it, and
what remains. The controls and their tests are in *Controls* below.

### A compromised media worker

**Gains:** the worker's service-client secret (`execute:ocr`) and its
ability to ask media-service's run-bound endpoint for contexts.

**Controls:** the worker holds no signing seed, so it cannot mint a context.
A context is minted only while a run is live, inside its claimed attempt,
from the object's live state (media C-08), and is single-use, short-lived
and bound to the presenting client (`azp`). The dispatch context must equal
every claim the spool row recorded, so one run's spooled bytes cannot be
disclosed under another run's authorization. The worker's spool writes are
bounded by the signed `input_bytes`. Its admissions are bounded by the
client's budget, rate window and in-flight slots.

**Residual:** the worker can still *request* OCR of the object its run was
authorized for, and spend that client's budget. It cannot reach any other
object.

### A stolen Redis job

**Gains:** a queued job payload.

**Controls:** nothing on the queue carries a context or a secret (media
C-18). A context is minted after dequeue, inside the claimed attempt, so a
replayed or forged job cannot produce one for an attempt it does not hold.
A context captured in flight is useless without the presenting client's
secret, and is redeemed once.

**Residual:** none at the gateway beyond the compromised-worker row.

### A dump of `ai_db`

**Gains:** every table.

**Controls:** credentials are envelopes; the KEK is not in the database,
and with `vault_transit` no KEK exists outside Vault. Fingerprints are HMACs
under a key that is not in the database. Service-client secrets are not in
the database. Job-context rows hold `(iss, jti)` and expiry only.

**Residual:** metadata is disclosed: provider endpoints, tenant and user
ids, usage and audit rows. A dump stored next to a backup of the KEK is a
full credential loss, so the KEK backup is kept apart (*KEK backup and loss*
below).

### Leaked gateway configuration

**Gains:** the environment file.

**Controls:** keys are never environment values: the settings take key
*paths* and read mode-checked files. `AI_SERVICE_CLIENTS` holds salted
digests and public keys only, and a plaintext secret refuses boot. The
digest is a fast hash, which is why every service-client secret is 256 bits
from a CSPRNG and never chosen by a person.

**Residual:** the configuration together with the mounted secret files is a
gateway compromise (below).

### A Vault outage

**Controls:** every read and write answers `credential_unavailable`, never
a fallback to another key. A validation probe during an outage is
inconclusive and never marks a key invalid. The scheduler's cleanup retries
with backoff.

**Residual:** an availability loss for every credential that needs Vault.

### A malicious or compromised provider

**Controls:** answers are bounded on the wire and after decoding, parsed
with a depth cap, and validated before use. Redirects are refused and the
credential travels only to the provider's own origin. Diagnostics are
closed: no provider body, header or exception text reaches a response, a log
line or the audit trail. Provider output is data, never instructions. A
changed Ollama digest flags the model.

**Residual:** a provider sees everything sent to it, and can return wrong
but well-formed results. The OCR receipt proves which input the gateway sent
and which output it received, not that the output is correct. Where the
provider reports no model digest, model identity is the operator's word
(`identity_assurance`).

### A malicious document

**Controls:** the gateway never parses a document. It reads one two-part
multipart form with bounded part headers, writes the bytes to the spool
under the signed size, and verifies the signed digest before any provider
sees them. Inline submission is chosen from the verified signature of the
first bytes, never from a client header. Parsing happens in the media
sandbox (D-25, below).

**Residual:** the provider parses the document.

### Malicious superuser input

**Controls:** a provider's `base_url` passes the destination guard when it
is written and again before every call. Header names come from a closed
pattern. Model ids are URL-encoded into fixed path templates. A
structured-output schema is accepted only in a closed dialect. Endpoints and
model identities freeze at first use, and a database trigger enforces it
when the controller is bypassed. `restricted` can never be widened past the
context's own BYOK. Every change is audited.

**Residual:** the superuser is trusted to decide which providers exist and
where global bindings point. A malicious superuser can register an
attacker's external provider and bind it globally; data that policy lets
reach a global platform key (`public`, and `internal` only if an operator
widened it) then goes there. The change is audited and mirrored to the log
sink.

### A second replica

**Controls:** all shared state is in the database: atomic reservations,
rate windows, occupancy counters, `jti` redemption on the database clock,
credential cooldowns, scheduler leases with fencing tokens. The spool is
one shared volume on one host. `/health` refuses execution when the
application clock drifts from the database's.

**Residual:** circuit-breaker state is per process.

### Code execution in the gateway or scheduler

**Gains:** every provider credential the process can decrypt. User BYOK is
live (Q6), so that is every user's personal key as well as every tenant's
key and every platform key. It also gains unrestricted outbound reach over
`ai_egress`, an ordinary bridge network that masquerades to any
destination.

**Controls:** none inside the process. The SSRF and redirect rules bind
only the gateway's own code; they cannot constrain arbitrary code running
in it. The process runs as `appuser` on a read-only root with no pip, and
the scheduler holds neither the fingerprint key nor the receipt seed.

**Residual:** stated in full. Destination filtering would narrow the
exfiltration channel, not the loss. The destination-allowlist egress proxy
is a named follow-on (Q13, declined for V1 at `T1`). Until it lands, a
host-level egress filter in front of `ai_egress`, allowing only the
registered providers' addresses, is the available deployment hardening.

### A stolen management session (binding repoint)

**Gains:** whoever sets a binding's credential decides where that scope's
data goes. A stolen `WRITER` session can repoint its user's binding to an
attacker's provider account and receive that user's later documents. A
stolen tenant `ADMIN` session can do the same for the tenant.

**Controls:** user-scope and tenant-scope writes use the fresh-revocation
tiers (`CurrentWriter`, `CurrentAdmin`), never the positively cached one, so
a revoked session stops at once. Management accepts JWTs only. Every binding
change is audited and mirrored to the log sink. A repoint never changes a
call already resolved.

**Residual:** stated. A live stolen session can repoint until it is
revoked.

## Stated guarantees and residuals

### User precedence

A user's own binding overrides the tenant's binding for that user's own
objects, `TENANT`-visible and `SENSITIVE` ones included. V1 has no tenant
opt-out; a tenant policy that forbids or gates personal bindings is a named
follow-on. Personal BYOK does not enable `restricted` external OCR.

### The exact egress guarantee (media D-21)

Only the gateway image, in its web and scheduler run-modes, holds AI
credentials and can reach local AI runtimes (`ai_net`); no media service or
worker joins `ai_net`. Docker bridge egress does not filter destinations,
so another egress-capable service could open a connection to a provider
host; without a credential that yields nothing. Traefik blocks
`/ai/v1/execute/*` and `/ai/v1/internal/*` at the public router and strips
`X-Internal-Client`, `X-Internal-Token` and `X-AI-Job-Context`.
Destination-restricted egress is a named follow-on, not a V1 claim.

### DNS rebinding (R-11)

`external` providers need HTTPS with certificate hostname verification;
`local` providers are allowlisted compose names on `ai_net`. No
connection-level IP pinning is claimed: the guard and the connection resolve
the name separately, and an answer that changes between them reaches a host
other than the one checked. TLS verification then fails the handshake before
any byte is sent, unless that host holds a valid certificate for the
provider's name. That last case is the residual.

### The two OCR residuals (D-44)

The *decision-time* residual: a state change between the dispatch context's
signing and the gateway's dispatch decision is honoured only if it happened
more than `AI_DISPATCH_CONTEXT_TTL_SECONDS` (30 s) before the decision. A
stale context inside that window discloses, by design. The *transmission*
residual: once the decision is taken, bytes keep flowing for at most
`AI_PROVIDER_TOTAL_DEADLINE_SECONDS`, with no further authorization check.
Synchronous calls (embedding, rerank, structured output) carry one request's
latency.

### Whole-document OCR disclosure (Q12)

`pages=[…]` limits the pages the provider processes and the admission units
charged. The **whole original document** is still sent to the provider.
External OCR ships disabled (`ocr` absent from `AI_CAPABILITIES_ENABLED`)
until the OCR enablement gate is met.

### Model identity as an operator trust boundary (D-11)

`identity_assurance` says how far a model's identity is the provider's word:
`provider_digest` (Ollama's listed digest, re-checked), `pinned_snapshot`
(a dated, immutable model id the superuser registered) or
`operator_declared` (the operator's statement only). Where the provider
reports no digest, the superuser-set model revision is an operator trust
boundary. Changing such a model is a new model row, hence a new
`execution_identity` and `embedding_space_id`; media-service then answers
search FTS-only until a re-index into the new space completes (media
`T69`).

### `restricted` OCR and the restore residual

On the `database` backends a restored `ai_db` cannot reach provider files
created under a credential version newer than the backup. The gateway
therefore refuses `restricted` external OCR on those backends unless
`AI_RESTRICTED_OCR_RESTORE_RESIDUAL_ACCEPTED=true`. `T1` (2026-10-10)
declined that acceptance: the flag stays unset in every shipped stack, and
only a separate, dated human decision can set it.

### Provider capability evidence

A remote file counts as deleted, or absent, only on what the provider's
recorded reference documents. Each adapter declares `deletion_proof`,
`absence_proof`, `list_consistency`, `safe_server_side_prefix_listing` and
`sweep_absence_proof`, re-read from the provider's reference when the
adapter was built:

| Provider | Deletion proof | Absence proof | Listing | Reference read |
| --- | --- | --- | --- | --- |
| Mistral | `DELETE /v1/files/{id}` → `200 {deleted: true}` for the recorded id | none (a `404` or a negative listing is evidence only) | no server-side prefix filter; consistency undocumented | 2026-10-03, re-read 2026-10-22/23 |
| Ollama, OpenAI-compatible | no provider files are created | — | — | — |

A passed provider-side expiry is defense in depth, never proof.

## Controls

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
never a fallback to another key. The `vault` KV backend is not served by
this build, and a deployment configured for it refuses to start.

**Fingerprints.** A fingerprint is HMAC-SHA256 under the fingerprint key over
the credential's scope and the secret. It can only detect the same key twice
within one tenant's or one user's scope. The same key in two scopes has two
unrelated fingerprints, so nothing can link them. Fingerprints are never
returned.

**Resolution failures** answer `credential_unavailable` and are logged by
exception type only. A slow database is cut off after
`AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS`.

Tests:
`test_credential_boundary.py::test_no_other_module_names_the_version_table`,
`test_credential_store.py::test_a_retired_version_resolves_for_cleanup_only`,
`test_credential_store.py::test_a_credential_that_is_not_active_resolves_for_cleanup_only`,
`test_credential_store.py::test_a_resolved_secret_is_wiped_even_when_the_block_raises`,
`test_credential_store.py::test_fingerprints_are_scope_bound`,
`test_database_store.py::test_the_aad_is_length_prefixed_and_unambiguous`,
`test_database_store.py::test_every_version_has_its_own_dek_and_nonce`,
`test_database_store.py::test_a_tampered_row_is_unavailable_never_partial`,
`test_database_store.py::test_a_database_dump_holds_ciphertext_only`,
`test_database_store.py::test_neither_the_kek_nor_the_secret_reaches_a_log_or_an_exception`,
`test_database_store.py::test_a_slow_database_is_unavailable_within_the_resolve_timeout`,
`test_database_store.py::test_start_up_refuses_a_missing_generation`,
`test_database_store.py::test_the_vault_kv_backend_is_not_served_yet`,
`test_vault_transit.py::test_a_wrapped_key_never_unwraps_for_another_row`,
`test_vault_transit.py::test_a_redirect_to_another_host_is_never_followed`,
`test_vault_transit.py::test_proxy_variables_are_ignored_and_tls_is_always_verified`,
`test_vault_transit.py::test_an_unreachable_vault_is_unavailable_never_a_fallback`,
`test_vault_transit.py::test_neither_the_token_nor_the_secret_id_is_ever_shown`,
`test_vault_transit.py::test_health_needs_lookup_self_encrypt_and_decrypt_only`,
`test_settings_refusals.py::test_local_kek_file_must_be_safe_and_32_bytes`,
`test_settings_refusals.py::test_plain_http_vault_is_refused_under_production`,
`test_settings_refusals.py::test_a_key_reused_across_purposes_is_refused`,
`test_credentials.py::test_the_canary_never_leaves_the_store`.

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
- Each scope holds at most `AI_MAX_CREDENTIALS_PER_SCOPE` live credentials,
  and creations, rotations and validations are rate-limited per subject.
- Every transition writes `ai_credential_audit`, and each row is logged as an
  `ai_gateway.audit` event after the commit. Neither carries the secret or
  its fingerprint.

Tests:
`test_credentials.py::test_another_tenants_admin_sees_nothing`,
`test_credentials.py::test_an_admin_without_a_tenant_matches_no_tenant`,
`test_credentials.py::test_the_same_key_in_another_tenant_looks_like_any_new_key`,
`test_credentials.py::test_a_scope_field_in_a_body_is_refused`,
`test_credentials.py::test_ownership_is_immutable_when_the_controller_is_bypassed`,
`test_credentials.py::test_another_user_cannot_reach_my_key`,
`test_credentials.py::test_a_tenant_admin_has_no_access_to_its_users_keys`,
`test_credentials.py::test_cross_scope_ids_answer_the_same_404`,
`test_credentials.py::test_user_and_reader_tokens_cannot_write_user_keys`,
`test_credentials.py::test_the_superuser_can_only_stop_a_users_key`,
`test_credentials.py::test_the_per_scope_cap_holds_under_concurrency`,
`test_credentials.py::test_creates_and_rotations_are_rate_limited_per_subject`,
`test_management_routes.py::test_user_scope_writes_use_the_fresh_writer_tier`,
`test_revocation.py::test_a_revocation_inside_the_positive_cache_window_reaches_the_writer_tier`.

### Management authentication and authorization (D-05)

Management routes accept issuer JWTs only (RS256, `iss`/`aud`, revocation,
through `fastapi-m8`); `API_KEY_INTROSPECTION_ENABLED=true` refuses boot.
Every route has exactly one tier. Provider, model, profile, global-binding
and policy management are superuser-only, which needs both the `SUPERADMIN`
role and `is_superuser`. An issuer that cannot be reached fails closed.

Tests:
`test_management_routes.py::test_every_management_route_has_exactly_one_tier`,
`test_management_routes.py::test_every_admin_route_is_superuser_only`,
`test_management_routes.py::test_an_api_key_alone_is_401`,
`test_auth.py::test_an_admin_claiming_is_superuser_is_not_a_superuser`,
`test_auth.py::test_superuser_only_denies_every_lower_role`,
`test_revocation.py::test_an_unreachable_issuer_fails_closed`,
`test_app.py::test_no_api_key_principal_is_wired`,
`test_settings_refusals.py::test_api_key_introspection_is_refused`.

### Service clients (D-06)

`AI_SERVICE_CLIENTS` is a deny-by-default registry of salted SHA-256
digests with capability-precise scopes. A wrong secret and an unknown client
answer alike, after the same constant-time comparison. A user JWT alone
never authenticates an execution route, and a JWT sent beside a service
client is never read. A plaintext secret, an unknown scope, an issuing
client without public keys, a `kid` its key does not derive, and one public
key under two clients each refuse boot.

Tests:
`test_service_client_guard.py::test_unknown_client_and_wrong_secret_are_indistinguishable`,
`test_service_client_guard.py::test_an_authenticated_client_without_the_scope_is_forbidden`,
`test_execution_guard.py::test_a_jwt_beside_a_service_client_is_never_read`,
`test_execution_guard.py::test_an_undeclared_route_is_refused_whatever_it_carries`,
`test_execution_guard.py::test_every_gateway_execution_route_depends_on_the_guard`,
`test_settings_refusals.py::test_service_client_refusals`.

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

Tests:
`test_job_context.py::test_a_header_over_4_kib_is_refused_before_decoding`,
`test_job_context.py::test_a_malformed_encoding_is_refused_before_the_signature`,
`test_job_context.py::test_a_tampered_payload_or_signature_is_refused`,
`test_job_context.py::test_an_object_signed_for_another_purpose_is_refused`,
`test_job_context.py::test_a_context_signed_with_another_clients_key_is_refused`,
`test_job_context.py::test_a_registered_client_without_the_issue_scope_cannot_issue`,
`test_job_context.py::test_a_presenter_other_than_azp_is_refused`,
`test_job_context.py::test_another_installations_audience_is_refused`,
`test_job_context.py::test_an_nbf_beyond_the_skew_is_refused`,
`test_job_context.py::test_a_ttl_over_the_cap_is_refused`,
`test_job_context.py::test_concurrent_redemptions_admit_exactly_one`,
`test_job_context.py::test_a_lagging_replica_cannot_redeem_past_the_database_clock`,
`test_job_context.py::test_max_uses_other_than_one_is_refused`,
`test_job_context.py::test_no_token_reaches_a_log_line`,
`test_job_context.py::test_a_jwt_on_an_execution_route_is_refused`.

### The signed-object rule (C-03) and its three domains

One implementation, `ai_sdk_m8.signed`, signs and verifies three kinds of
object, each with its own Ed25519 key and its own domain tag:

| Domain tag | Signed by | Verified by |
| --- | --- | --- |
| `m8.ai.job-context.v1` | media-service (its context seed) | the gateway |
| `m8.ai.ocr-receipt.v1` | the gateway (`AI_EXECUTION_RECEIPT_KEY_FILE`) | media-service |
| `m8.doctools.sandbox-attestation.v1` | the media sandbox supervisor | media-service |

The signed bytes are `UTF-8(domain_tag) ‖ 0x00 ‖ JCS(payload)`. The verifier
supplies the tag it expects and never reads it from the object, so an object
signed for one purpose fails as any other. No seed serves two purposes: boot
refuses an issuer key equal to the receipt key, and a receipt seed reused as
a KEK.

Tests:
`test_job_context.py::test_an_object_signed_for_another_purpose_is_refused`,
`test_mistral_adapter.py::test_the_receipt_fails_when_altered_or_presented_for_another_purpose`,
`test_settings_refusals.py::test_an_issuer_key_equal_to_the_receipt_key_is_refused`,
`test_settings_refusals.py::test_receipt_seed_reused_as_a_kek_is_refused`,
`test_settings_refusals.py::test_receipt_kid_must_match_the_seed`.

### Data-class policy and provider destinations

The gateway resolves the destination itself, inside the transaction that
records it on the execution row (`ai_gateway/controllers/resolution.py`). The
destination checked is therefore the destination dispatched, and a binding
repointed after that point changes nothing.

- **Precedence.** User binding, then tenant binding, then global binding.
  The user binding consulted is the one whose tenant and owner equal the
  signed context's `tenant_id` and `user_id`. A context without `user_id`
  never reaches one, and a user's binding never serves another tenant.
- **Unavailable credentials fail closed (`on_unavailable`).** A bound
  credential that is disabled, invalid, deleted, awaiting re-confirmation or
  throttled answers `credential_unavailable` (or `rate_limited` with
  `Retry-After`) before any provider request. The same holds for a user
  binding while `AI_USER_BYOK_ENABLED` is false. Only `fall_through`, set by
  the binding's owner, moves on to the next scope, and every such move is
  audited. A global binding cannot fall through. Switching user BYOK off
  never silently moves a user's data to the tenant's or the platform's key,
  and `/health` counts the user bindings it holds.
- **Destination policy, applied to the resolved candidate.** `rerank` goes to
  `local` providers only, whatever the policy says (`boundary_denied`). A
  signed `allowed_boundaries` claim must contain the provider's boundary.
  `internal` and `restricted` data reach `local` providers or the context's
  own BYOK credential, never an external platform key (`data_class_denied`).
  On the database backends, `restricted` OCR never goes to an `external`
  provider while the restore residual is not accepted. A denial is final: it
  never sends the request on to the next scope.

Tests:
`test_resolution.py::test_the_user_binding_wins_then_the_tenant_then_the_global`,
`test_resolution.py::test_a_users_binding_serves_only_its_own_tenant_and_user`,
`test_resolution.py::test_an_unavailable_bound_key_fails_closed_by_default`,
`test_resolution.py::test_fall_through_follows_user_tenant_global_with_an_audit_row`,
`test_resolution.py::test_each_candidate_is_judged_by_d08_and_a_denial_is_terminal`,
`test_resolution.py::test_byok_off_holds_user_bindings_unavailable_and_health_reports_them`,
`test_resolution.py::test_internal_data_reaches_local_or_its_own_byok`,
`test_resolution.py::test_rerank_is_local_only_whatever_the_policy`,
`test_resolution.py::test_restricted_ocr_never_leaves_on_the_database_backends`,
`test_registry.py::test_a_global_binding_cannot_fall_through`,
`test_execution_core.py::test_the_data_class_matrix_on_external_destinations`,
`test_execution_core.py::test_a_binding_repointed_after_resolution_dispatches_the_recorded_provider`,
`test_settings_refusals.py::test_data_class_policy_refusals`.

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

These rules bind the gateway's own code only: code running inside a
compromised gateway is not constrained by them (*Code execution in the
gateway or scheduler*, above). The DNS-rebinding residual is stated above
(R-11).

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

Tests:
`test_ssrf.py::test_dangerous_literals_are_blocked_everywhere`,
`test_ssrf.py::test_loopback_through_an_allowlisted_name_is_refused`,
`test_ssrf.py::test_external_providers_need_global_addresses`,
`test_ssrf.py::test_cgnat_and_ipv4_mapped_private_are_refused_under_production`,
`test_ssrf.py::test_every_answer_must_pass`,
`test_ssrf.py::test_local_providers_need_an_allowlisted_name_and_port`,
`test_ssrf.py::test_external_port_allowlist`,
`test_ssrf.py::test_malformed_urls_are_refused`,
`test_ssrf.py::test_rebinding_between_check_and_connect_is_the_recorded_residual`,
`test_registry.py::test_a_reserved_or_routing_header_name_is_refused`,
`test_registry.py::test_a_referenced_provider_keeps_its_endpoint`,
`test_registry.py::test_the_boundary_is_fixed_even_before_first_use`,
`test_schema.py::test_a_used_providers_endpoint_is_frozen`,
`test_schema.py::test_a_boundary_change_is_always_refused`,
`test_provider_client.py::test_a_redirect_to_a_metadata_address_is_not_followed`,
`test_provider_client.py::test_the_default_transport_verifies_tls_and_ignores_the_environment`,
`test_provider_client.py::test_no_code_turns_tls_verification_off`,
`test_provider_client.py::test_the_guard_runs_on_every_request`,
`test_provider_client.py::test_a_request_for_another_origin_never_passes_the_guard`,
`test_provider_client.py::test_a_path_outside_the_fixed_templates_is_refused_before_sending`,
`test_provider_client.py::test_a_credential_that_cannot_travel_safely_is_refused_before_sending`,
`test_provider_client.py::test_a_gzip_bomb_under_the_raw_cap_is_aborted_at_the_decoded_cap`,
`test_provider_client.py::test_an_over_deep_or_malformed_json_answer_is_rejected`,
`test_provider_client.py::test_a_slow_drip_answer_is_cancelled_at_the_total_deadline`,
`test_provider_client.py::test_a_tenants_invalid_key_opens_no_breaker_for_another_tenant`,
`test_provider_client.py::test_a_later_shorter_cooldown_never_shortens_an_earlier_one`,
`test_provider_client.py::test_dns_rebinding_residual_is_mitigated_only_by_certificate_verification`.

### Prompt injection and untrusted provider output

A provider answer is untrusted input. Adapters only extract values; whether
they are usable is decided by the shared validator
(`ai_gateway/providers/outputs.py`), which every result must pass before
settlement: exactly one vector per input, each of the model's declared
dimensions, every component finite; rerank indexes in range and unique with
finite scores; never more OCR pages than were reserved and requested. A
structured-output answer is validated against the request's schema. A failed
check is `provider_rejected`, and nothing partial is returned. Nothing the
gateway sends concatenates a document into instructions, and V1 has no tool
use, chat or agent loop for an injected instruction to steer.

Failures are closed (D-41): a `ProviderFailure` carries a code, the provider's
status class, a bounded `Retry-After` and adapter-chosen metadata in the
closed `provider_metadata` shape. Provider bodies, headers and exception text
are discarded, never excerpted, so a hostile error body (plain, base64 or
split across lines) reaches no response, log line or traceback.

Tests:
`test_provider_outputs.py::test_bad_embeddings_are_rejected`,
`test_provider_outputs.py::test_bad_rerank_hits_are_rejected`,
`test_provider_outputs.py::test_ocr_pages_beyond_the_reservation_are_rejected`,
`test_execution_routes.py::test_an_output_outside_the_schema_is_rejected_and_charged`,
`test_provider_client.py::test_a_malicious_error_body_never_reaches_the_failure_or_the_logs`,
`test_provider_client.py::test_the_public_error_carries_the_typed_fields_only`.

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

Tests:
`test_execution_core.py::test_n_parallel_calls_against_budget_m_admit_exactly_the_units_that_fit`,
`test_execution_core.py::test_two_gateway_processes_share_one_budget_exactly`,
`test_execution_core.py::test_the_in_flight_cap_holds_across_replicas_and_slots_return_exactly_once`,
`test_execution_core.py::test_a_rate_window_refusal_carries_retry_after_and_charges_nothing`,
`test_execution_core.py::test_a_user_whose_own_key_resolved_is_still_bounded_by_its_signed_identity`,
`test_execution_core.py::test_a_change_committed_before_the_marker_stops_the_call`,
`test_execution_core.py::test_a_connect_failure_before_any_byte_releases_the_reservation`,
`test_execution_core.py::test_a_timeout_after_dispatch_stays_charged`,
`test_execution_core.py::test_a_kill_after_sending_then_two_sweeps_settle_exactly_once`,
`test_execution_core.py::test_a_late_answer_after_the_sweeper_cannot_double_settle`,
`test_execution_core.py::test_settlement_uses_the_reserved_day_across_midnight`,
`test_execution_core.py::test_a_sweep_racing_the_marker_leaves_the_handler_no_provider_call`,
`test_schema.py::test_a_refund_after_the_first_byte_is_refused`,
`test_schema.py::test_a_settled_row_settles_exactly_once`,
`test_settings_refusals.py::test_admission_bounds_must_be_set_under_production`.

### Credential material on the execution path

The material fetch is the only credential-store I/O of a call, and it fetches
exactly the `(credential_id, version)` the reservation recorded — a binding
repointed meanwhile changes nothing. It happens before the marker: a store
that fails or stalls past `AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS` releases the
reservation (`credential_unavailable`) with no provider request. The
plaintext lives from that fetch to the end of the adapter call and is wiped
on every path, a zero-row marker and a cancelled request included.

Tests:
`test_execution_core.py::test_a_keyed_call_gets_exactly_its_recorded_secret`,
`test_execution_core.py::test_a_binding_repointed_before_the_material_fetch_fetches_the_recorded_version`,
`test_execution_core.py::test_a_stalled_credential_store_releases_with_no_provider_request`,
`test_execution_core.py::test_a_store_failure_of_any_kind_releases_as_credential_unavailable`,
`test_settings_refusals.py::test_resolve_timeout_must_be_below_both_ttls`.

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

Metrics are declared in one module (`ai_gateway/core/metrics.py`) and every
label is a member of a closed vocabulary: a capability, a provider type, a
stored status, an error code, a backend, a scope type or a table name. No
collector is labelled with a user, tenant, client, filename, query, model
input or key material; `tests/test_metrics.py` fails on any metric family or
label not named in the allowlist and asserts a canary absent from the
exposition. Every execution settlement also logs one structured line (ids,
units, status, error class) on `ai_gateway.audit`. `ai_breaker_state` is the
last state a request observed in the process, not a cross-replica value.

Errors are typed: an unrecognised exception is answered without its
message, a database health failure is reported by exception type only,
request ids are opaque, and `/docs` and the OpenAPI document are absent
under production. `/metrics` is absent unless enabled and then needs its
scrape credential.

Tests:
`test_registry.py::test_provider_crud_is_audited_with_its_actor`,
`test_registry.py::test_audit_events_are_logged_only_after_the_commit`,
`test_registry.py::test_audit_metadata_is_bounded`,
`test_registry.py::test_readers_see_identities_never_a_credential_or_base_url`,
`test_schema.py::test_the_runtime_role_cannot_rewrite_the_audit_trail`,
`test_schema.py::test_audit_metadata_is_capped_at_4_kib`,
`test_metrics.py::test_the_exposition_carries_only_allowlisted_families_and_labels`,
`test_metrics.py::test_every_settlement_is_one_structured_audit_line`,
`test_exceptions.py::test_an_unrecognised_exception_is_redacted`,
`test_app.py::test_check_db_reports_the_failure_without_its_message`,
`test_app.py::test_the_metrics_endpoint_requires_its_credential`,
`test_meta_health.py::test_request_ids_are_opaque_and_unique`,
`test_meta_health.py::test_docs_and_openapi_are_absent_under_production`,
`test_meta_health.py::test_meta_never_carries_key_material`,
`test_settings_refusals.py::test_boot_errors_never_carry_the_environment`.

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
`dimension_mismatch`). An OCR call pinned to an `expected_execution_identity`
is refused with `execution_identity_changed` when the resolved identity
differs.

Tests:
`test_registry.py::test_the_execution_identity_is_the_c07_hash`,
`test_registry.py::test_an_executed_model_keeps_its_identity`,
`test_registry.py::test_identity_assurance_provider_digest_is_never_declared`,
`test_schema.py::test_a_used_models_identity_is_frozen`,
`test_ollama_adapter.py::test_registering_an_ollama_model_pins_its_listed_digest`,
`test_ollama_adapter.py::test_the_recheck_flags_a_changed_or_vanished_digest_and_audits_it`,
`test_ollama_adapter.py::test_a_digest_change_after_first_use_refuses_every_execution`,
`test_ollama_adapter.py::test_a_dimension_mismatch_is_rejected_and_audited_against_the_model`,
`test_execution_core.py::test_a_flagged_model_is_never_reserved`,
`test_execution_core.py::test_an_identity_pin_mismatch_is_refused_before_any_provider_call`.

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
row closes only on the provider's documented deletion proof (*Provider
capability evidence*, above). A `404`, a negative listing or a passed expiry
is evidence only: after its retries such a row is parked as
`manual_cleanup_required`, alerted, and closed only by a later proof or an
audited `accept-residual`. A listing keeps only names of this deployment's
prefix; another installation's or a tenant's files are never logged,
stored or deleted. Incident listings run under a platform key when
`AI_REMOTE_ARTIFACT_PLATFORM_INCIDENT_LISTING` allows it, and under a
tenant's or a user's key only with its `incident_listing_consent`. The
periodic sweep never lists a tenant's or a user's account.

Tests:
`test_mistral_adapter.py::test_the_intent_row_exists_before_the_provider_reads_the_upload`,
`test_mistral_adapter.py::test_an_upload_is_private_expiring_and_named_by_the_gateway_only`,
`test_mistral_adapter.py::test_only_a_deletion_of_the_recorded_id_is_proof`,
`test_mistral_adapter.py::test_listings_keep_only_this_deployments_prefix_across_pages`,
`test_remote_artifacts.py::test_a_401_on_cleanup_is_retried_with_the_recorded_version_only`,
`test_remote_artifacts.py::test_a_404_or_an_unproven_delete_never_closes_and_parks_after_the_attempts`,
`test_remote_artifacts.py::test_rotation_and_deletion_during_pending_keep_the_old_version_alive`,
`test_remote_artifacts.py::test_negative_listings_never_close_a_row_and_a_late_listing_recovers_it`,
`test_remote_artifacts.py::test_a_passed_expiry_is_never_proof_and_a_later_proof_closes_the_row`,
`test_remote_artifacts.py::test_a_tenant_key_is_listed_only_with_its_consent`,
`test_remote_artifacts.py::test_the_sweep_is_off_by_default_and_never_lists_a_tenants_account`,
`test_remote_artifacts.py::test_the_sweep_deletes_only_this_deployments_old_untracked_files`,
`test_remote_artifacts.py::test_a_crash_right_after_the_intent_commit_ends_outside_uploading`,
`test_schema.py::test_material_survives_while_an_artifact_or_sweep_obligation_needs_it`.

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

Tests:
`test_execution_routes.py::test_a_body_over_the_cap_is_aborted_before_parsing`,
`test_execution_routes.py::test_a_malformed_body_is_422_with_no_value_echoed`,
`test_execution_routes.py::test_a_schema_outside_the_dialect_is_422_with_no_provider_call`,
`test_execution_routes.py::test_an_oversize_or_over_deep_schema_is_422`,
`test_spool.py::test_a_part_name_is_read_and_a_file_name_ignored`,
`test_spool.py::test_a_part_header_outside_the_form_is_refused`,
`test_spool.py::test_the_body_cap_is_counted_while_reading`,
`test_ocr_routes.py::test_a_body_that_is_not_the_two_part_form_is_400`.

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
spool recorded, the presenting client included, or nothing is sent. Every
gateway and scheduler process refuses a spool that is not on `ext4`, `xfs`
or `btrfs`, or whose locks do not exclude another process.

Tests:
`test_ocr_routes.py::test_one_workflow_spools_dispatches_and_charges_once`,
`test_ocr_routes.py::test_a_chunked_body_with_any_content_length_is_sized_by_the_signed_bytes`,
`test_ocr_routes.py::test_one_byte_past_the_signed_size_aborts_with_nothing_retained`,
`test_ocr_routes.py::test_a_digest_that_differs_from_the_signed_one_sends_nothing`,
`test_ocr_routes.py::test_a_dispatch_context_not_bound_to_the_spool_sends_nothing`,
`test_ocr_routes.py::test_an_expired_dispatch_context_is_refused`,
`test_ocr_routes.py::test_a_full_capacity_is_503_before_any_byte`,
`test_ocr_routes.py::test_a_reader_holding_the_spool_defers_the_cleaner`,
`test_ocr_routes.py::test_a_receiver_paused_before_its_file_creates_nothing_once_cleaned`,
`test_ocr_routes.py::test_only_the_spool_module_opens_spool_files`,
`test_ocr_routes.py::test_the_family_is_404_without_ocr`,
`test_spool.py::test_reservations_round_up_to_the_allocation_unit`,
`test_spool.py::test_a_lock_whose_path_was_replaced_is_retired`,
`test_spool.py::test_a_cleaner_meets_a_held_lock_and_the_release_happens_once`,
`test_meta_health.py::test_remote_or_memory_spool_is_refused`,
`test_meta_health.py::test_locks_that_do_not_exclude_are_refused`.

### Sweepers and recovery (T32)

The sweepers settle by stored status through the same compare-and-set as
the handler, so a row is settled once and its occupancy slot returned
once, whichever side gets there first; a dispatched row past its deadline is
charged, never refunded. Spool cleanup goes through the lock discipline: a
held lock defers it, a crash between the data unlink and the release, or
between the release and the lock unlink, is finished on the next pass with
the reservation released exactly once. A lock that vanished while its
reservation is held is never released automatically: it is logged as
`spool_lock_missing` and only the audited `spool repair` command releases it
(*Spool repair* below).

Tests:
`test_sweepers.py::test_uploads_past_their_lease_and_spools_past_their_ttl_are_abandoned`,
`test_sweepers.py::test_a_held_lock_defers_and_a_crash_between_unlink_and_release_recovers`,
`test_sweepers.py::test_a_crash_between_release_and_lock_unlink_leaves_only_the_lock_to_collect`,
`test_sweepers.py::test_orphans_never_touch_a_live_spool_or_a_held_lock`,
`test_sweepers.py::test_a_missing_lock_is_repaired_only_by_the_audited_command`,
`test_ocr_routes.py::test_a_missing_lock_with_a_created_file_keeps_the_capacity_charged`.

### Retention and audit pruning (T33)

Retention is a positive predicate, not an age cut-off: a row that still owns
a ledger entry, a spool reservation, an occupancy slot or a remote artifact
is never collected, whatever its age, and an unreconciled `charged_uncertain`
row is never collected. `reconcile` records the operator's evidence in
`ai_admin_audit`. `GET /v1/usage` returns aggregates only; a tenant admin
cannot learn that another tenant exists. The runtime role cannot delete audit
rows; `audit-prune` runs as the schema owner, writes its own summary row
first and refuses a future cut-off.

Tests:
`test_retention.py::test_only_a_row_nothing_else_needs_is_collected`,
`test_retention.py::test_a_charged_uncertain_row_is_collected_only_after_reconciliation`,
`test_retention.py::test_another_tenant_and_a_missing_tenant_see_nothing`,
`test_retention.py::test_audit_prune_as_the_owner_removes_exactly_the_rows_before_the_date`,
`test_retention.py::test_audit_prune_as_the_runtime_fails_on_permissions_and_changes_nothing`,
`test_retention.py::test_audit_prune_command_succeeds_as_the_owner_and_refuses_the_future`.

### Scheduler lease and fencing (T33a, D-42)

Scheduled work runs under one database lease per job. A lease is taken only
once expired, with a fresh random 128-bit token, and every job statement
asserts the epoch, the token and an unexpired lease on the lease row, read
`FOR SHARE` so a successor's acquisition and a stale statement cannot both
commit. A leader paused past its lease and resumed, or one that survived an
`ai_db` restore that rewound the epoch, therefore commits nothing. Remote
artifacts are claimed per row before any provider call, and every later
change asserts the claim and the lease. What this proves is stated exactly:
database transitions happen at most once; external effects (a provider
deletion, a spool unlink) may repeat, and none counts as complete by its own
repetition: a deletion counts only on the adapter's documented proof (a
`404` is not one for Mistral), an unlink only under the D-45 lock.

The scheduler sits inside the credential trust boundary (it resolves the
recorded version to delete provider files and re-checks Ollama digests), but
runs without the fingerprint key and the OCR receipt seed, which it never
uses. The occupancy repair recounts under the counter row's lock with a
fresh statement, so a concurrent admission or settlement is never lost.
Material destruction clears a retired version only once no artifact row of
any status references it, its sweep obligation is discharged, it is no live
credential's current version and no execution in flight resolved it; the
schema trigger re-checks the first conditions.

Tests:
`test_scheduler.py::test_a_paused_leader_commits_nothing_after_a_successor_took_epoch_n_plus_1`,
`test_scheduler.py::test_a_leader_whose_database_was_restored_commits_nothing`,
`test_scheduler.py::test_two_replicas_run_a_job_exactly_once_per_tick`,
`test_scheduler.py::test_a_stale_claim_commits_nothing_and_a_404_never_closes_the_row`,
`test_scheduler.py::test_the_repair_loses_no_concurrent_admission_or_settlement`,
`test_scheduler.py::test_a_retired_version_is_destroyed_only_after_its_last_artifact_row`,
`test_scheduler.py::test_the_scheduler_neither_needs_nor_reads_the_fingerprint_key_or_seed`,
`test_scheduler.py::test_health_degrades_on_a_job_that_never_ran_or_is_stuck`,
`test_remote_artifacts.py::test_every_scheduler_transition_honours_its_fence`.

### Restore (T33a)

A snapshot restore rewinds `ai_db_epoch` but not the spool volume, so a
database behind the spool's high-water refuses execution until ratified.
`restore reconcile` fails closed: every provider disabled, every active
credential held for re-confirmation by its owner, every `fall_through`
binding back to `fail`, execution held for the job-context TTL plus skew (a
context minted before the restore cannot be replayed against the rewound
redemption table), and the budget held until the next UTC day (the restored
usage rows undercount; V1 offers no reconstruction). Ratification reads only
the database; the log-sink audit stream and `/spool/.state/restore-events`
are evidence, not authority. On the database backends, provider files
created under a version the restored database never saw are beyond reach;
the residual is recorded and bounded only by provider-side expiry. The
operator procedure is *Restore* under *Runbooks*.

Tests:
`test_restore.py::test_the_high_water_rises_and_a_database_behind_it_is_a_restore`,
`test_restore.py::test_entry_resets_every_relaxing_control_and_records_the_event`,
`test_restore.py::test_execution_refuses_restore_detected_until_ratified`,
`test_restore.py::test_the_steps_run_in_order_and_ratification_waits_for_all_three`,
`test_restore.py::test_the_budget_stays_held_until_the_next_utc_day_after_ratification`,
`test_restore.py::test_a_stale_scheduler_takes_no_restore_step`,
`test_restore.py::test_the_operator_commands`.

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

Tests:
`test_credential_validation.py::test_three_consecutive_auth_failures_make_a_key_invalid`,
`test_credential_validation.py::test_ten_timeouts_leave_a_key_active`,
`test_credential_validation.py::test_a_store_outage_is_inconclusive`,
`test_credential_validation.py::test_a_rotation_during_the_probe_is_not_charged_to_the_new_key`,
`test_credential_validation.py::test_the_probe_never_logs_a_header_or_the_secret`.

### OCR provenance receipt (C-01)

Every `ok` OCR result carries an Ed25519 receipt under the domain tag
`m8.ai.ocr-receipt.v1`, signed with the web service's receipt seed. It
binds the installation, the execution, the job context's `job_ref`,
`attempt`, `azp`, `profile_key`, `input_sha256` and `ocr_options_hash`, the
execution identity and `SHA-256(JCS(OcrResult))` of the exact body
returned. A different domain tag makes it fail as a job context or an
attestation; the seed signs nothing else. OCR without a receipt seed is
refused before any request.

Tests:
`test_mistral_adapter.py::test_the_receipt_verifies_and_binds_the_exact_result_returned`,
`test_mistral_adapter.py::test_the_receipt_fails_when_altered_or_presented_for_another_purpose`,
`test_mistral_adapter.py::test_ocr_without_a_receipt_seed_is_refused_before_any_request`,
`test_mistral_adapter.py::test_jcs_matches_the_sdk_rule_and_sorts_keys_by_utf16_units`,
`test_settings_refusals.py::test_ocr_needs_a_receipt_key_and_a_spool`.

### The D-47 provenance chain and its trust boundary

The gateway's receipt is one link of media-service's provenance chain. The
documents worker is transport only: it can read every visibility bucket, so
a hash it computes proves nothing. Derived document content is accepted
only through signatures made inside trusted, isolated components:

1. the media sandbox supervisor attests each invocation (`parse`, then
   `merge` when OCR is needed): the digests of its private input copies, of
   its outputs, and its runtime;
2. the gateway's receipt binds the verified `input_sha256` it sent to the
   provider and the exact `OcrResult` it returned;
3. the worker writes exactly the receipt's `JCS(OcrResult)` bytes as the
   `merge` invocation's input, so the attested digest equals the receipt's
   `result_sha256` byte for byte;
4. media-service verifies the whole chain against the object's own digest,
   the run's attempt and the configured gateway installation before any
   activation, and stores the verified digest.

Confidentiality of foreign content therefore rests on the sandbox
supervisor and the gateway. A hostile broker can withhold delivery or
deliver bytes that differ from the attestation, which is refused: an
availability loss, not a confidentiality one. The sandbox's `runtime`
block is application-level provenance (what the supervisor reports about
itself), not remote attestation of the image or host.

Tests:
`test_mistral_adapter.py::test_the_receipt_verifies_and_binds_the_exact_result_returned`.
Proven outside this repository: the chain verifier is `doctools-m8`'s
`T42a`, its use media-service's `T59`–`T61`, and the deployed chain the
media plan's `T88b`.

### The media sandbox the chain relies on (D-25)

The gateway does not run the sandbox, but the D-47 chain is only as strong
as it. Stated here because the gateway's disclosure guarantees depend on it:

- **Supervisor capabilities.** The supervisor runs as container uid `0` with
  every capability dropped except `CHOWN`, `DAC_READ_SEARCH`, `SETUID`,
  `SETGID` and `KILL` — never `DAC_OVERRIDE`, `FOWNER`, `SYS_ADMIN` or
  `SYS_PTRACE`. `DAC_READ_SEARCH` lets it read the brokers' `0700` inboxes;
  without `DAC_OVERRIDE` and `FOWNER` it can write only where it owns the
  directory, so it never writes inside a broker's tree. It holds exactly one
  secret, its attestation seed.
- **The child boundary is discretionary access control.** Each child runs as
  an attempt-unique uid and gid, with no supplementary groups, `umask 077`,
  `NO_NEW_PRIVS` and a seccomp filter; it cannot read another invocation's
  private tree or any broker tree. This is DAC with a per-attempt identity,
  not a mandatory access-control or VM boundary.
- **Persistent IPC.** `ipc: none` removes `/dev/shm` but leaves a
  container-lifetime System V namespace. The child's seccomp filter
  therefore denies every System V and POSIX message-queue call, so no kernel
  object outlives an invocation, and the supervisor's containment audit
  fails an invocation that leaves one.
- **Bounded child streams.** stdin is `/dev/null`; stdout and stderr are
  supervisor-owned pipes drained to `WORKER_SANDBOX_MAX_STREAM_BYTES` each,
  discarded beyond that and never written to a container log. Diagnostics
  come only from the structured result's closed error codes.

Proven outside this repository: `doctools-m8`'s `T42` (the supervisor and its
seccomp filter) and the media plan's deployed sandbox rows.

### Database roles and migrations (D-04)

`ai_db` is the gateway's own database on the stack's PostgreSQL instance,
with its own version table (`alembic_version_ai`). Two roles:

- `ai_owner` owns the schema and is used only by the `ai-migrate` one-shot.
  **Only `ai-migrate` ever runs Alembic.**
- `ai_runtime` (web and scheduler) has DML on the operational tables,
  `INSERT`/`SELECT` only on `ai_admin_audit` and `ai_credential_audit`, read
  only on `ai_installation`, and no DDL. A compromised runtime cannot
  rewrite or erase the audit trail.

The web and scheduler never run `upgrade`, autogenerate or any DDL. At start
each reads `alembic_version_ai` as `ai_runtime` and exits unless it equals
the head packaged in its own image, and unless the database records this
`AI_DEPLOYMENT_ID`. A half-migrated, newer or foreign database fails closed.
No role can update an audit row, the owner included; only the owner can
delete one, which is what `audit-prune` does.

Tests:
`test_schema.py::test_the_runtime_role_cannot_run_ddl`,
`test_schema.py::test_the_runtime_role_cannot_rewrite_the_audit_trail`,
`test_schema.py::test_audit_rows_are_immutable_even_for_the_owner`,
`test_schema.py::test_the_runtime_role_cannot_run_alembic`,
`test_schema.py::test_the_runtime_role_only_reads_the_installation`,
`test_repository.py::test_run_mode_scripts_never_run_alembic`,
`test_repository.py::test_only_ai_migrate_upgrades_and_it_never_autogenerates`,
`test_prestart.py::test_the_revision_must_equal_the_packaged_head`,
`test_prestart.py::test_main_exits_on_another_installation`,
`test_prestart.py::test_the_revision_check_writes_nothing`.

### Configuration and secrets handling

Settings refuse unknown keys, placeholders and missing required keys at
startup, and every contradiction they can see (README *Configuration*).
Keys are always files, mode-checked, never environment values; a secret
reused across two purposes refuses boot under production/strict. Service
code cannot import `auth-sdk-m8` directly; it uses `fastapi-m8`'s
re-exports.

Tests:
`test_settings.py::test_an_unknown_key_in_the_env_file_is_refused`,
`test_settings.py::test_import_fails_fast_on_an_incomplete_environment`,
`test_settings_refusals.py::test_a_placeholder_gateway_value_is_refused`,
`test_settings_refusals.py::test_a_reused_secret_is_refused_under_production`,
`test_settings_refusals.py::test_user_byok_must_be_explicit_under_production`,
`test_repository.py::test_no_service_module_imports_auth_sdk_m8`,
`test_repository.py::test_every_gateway_placeholder_is_changethis`.

### Supply chain and image provenance (S-12)

The image installs a hash-locked dependency set on the ratified Debian base
digest with the fleet's patch layer, carries no pip, runs as `appuser` and
supports a read-only root filesystem. CI runs `pip-audit`, `bandit`, Trivy
and hadolint, with every action pinned by commit SHA. Images are published
only from a published GitHub release, Trivy-gated, with an SPDX SBOM,
a keyless cosign signature and build-provenance attestations. Stacks pin the
image by digest.

Tests:
`test_repository.py::test_the_dockerfile_never_migrates_and_drops_root`,
`test_repository.py::test_the_dockerfile_carries_the_debian_patch_layer`,
`test_service_client_guard.py::test_the_lock_satisfies_the_platform_floor`.
Proven per release outside the test suite: `cosign verify` and
`gh attestation verify` on the pushed digest, recorded at the release
(`T35`).

## Best-practice maps

### OWASP ASVS 5.0

| ASVS 5.0 chapter | Gateway controls (sections above) |
| --- | --- |
| V1 Encoding and Sanitization | closed diagnostics; URL-encoded path segments; no provider text echoed (*Prompt injection and untrusted provider output*, *Server-side request forgery and outbound egress*) |
| V2 Validation and Business Logic | typed request models; the closed schema dialect; provider outputs validated; atomic budgets, rate windows and occupancy reserved before dispatch (*Execution request bodies*, *Denial of wallet and resource exhaustion*) |
| V4 API and Web Service | no generic proxying (fixed route templates); execution routes service-client only; docs and OpenAPI absent under production; typed errors (*Service clients*, *Logging, metrics and error disclosure*) |
| V5 File Handling | the bounded, lock-owned OCR spool; streaming byte counters; caps at three layers (*The OCR spool*, *Execution request bodies*) |
| V6 Authentication | salted, constant-time service-client digests over 256-bit secrets; JWT verification for management only (*Service clients*, *Management authentication and authorization*) |
| V7 Session Management, V9 Self-contained Tokens | short-lived, single-audience, single-use, domain-separated job contexts redeemed on the database clock; `kid` rotation (*Job-context forgery, replay and substitution*, *Runbooks*) |
| V8 Authorization | deny by default; D-05 tiers; owner-only user scope with a superuser stop; `404` on foreign ids; fail-closed data-class policy; dispatch bound to the spool row (*Credential access*, *Data-class policy and provider destinations*) |
| V11 Cryptography | AES-256-GCM envelopes with AAD and single-use data keys; one Ed25519 key per purpose; rotation by `rewrap`, `refingerprint` and `kid` (*Credential storage and decryption*, *The signed-object rule*) |
| V12 Secure Communication | TLS always verified; HTTPS for external providers and Vault under production; redirects off; `trust_env=False` (*Server-side request forgery and outbound egress*) |
| V13 Configuration | fail-fast settings; keys as mode-checked files mounted per service on need (*Configuration and secrets handling*) |
| V14 Data Protection | data classes and boundaries; no content kept except the spool; private, expiring provider files; redacted `repr` (*Provider-side files*, *Credential storage and decryption*) |
| V15 Secure Coding and Architecture | hash-locked image, SHA-pinned CI, SBOM, cosign, provenance (*Supply chain and image provenance*) |
| V16 Security Logging and Error Handling | insert-only audit for the runtime role, mirrored to the log sink; canary tests; closed metric labels (*Logging, metrics and error disclosure*) |

### OWASP Top 10 for LLM Applications (2025)

| Risk | Gateway controls |
| --- | --- |
| LLM01 Prompt Injection | document text sent as data only; provider output untrusted and validated; no tool use or agent loop (R-12) |
| LLM02 Sensitive Information Disclosure | signed data classes and boundaries, fail-closed; `rerank` local-only; whole-document OCR stated and shipped disabled; closed diagnostics |
| LLM03 Supply Chain | hash-locked image, SBOM, cosign; Ollama digests pinned and re-checked; `identity_assurance` reported |
| LLM05 Improper Output Handling | embeddings, rerank indexes, OCR pages and structured output validated; OCR results bound by the signed receipt |
| LLM06 Excessive Agency | no chat or vision route, no tool calling, no user-callable execution (R-12, R-14) |
| LLM08 Vector and Embedding Weaknesses | `embedding_space_id` identity per profile revision, reported with every result; retrieval ACLs are media-service's |
| LLM10 Unbounded Consumption | admission-unit budgets reserved before dispatch, rate windows, occupancy slots, total deadlines, request, response and schema caps |

LLM04, LLM07 and LLM09 (training data, system-prompt secrecy, answer
quality) concern answer generation, which the gateway does not do.

## Runbooks

### Key generation

Generate every key on a trusted host, write it straight into the secret
store or a `0600` file, and never paste it into a chat, a ticket or an
environment variable.

| Key | Generate | Notes |
| --- | --- | --- |
| KEK (`local`) | `python3 -c "import secrets,sys; sys.stdout.buffer.write(secrets.token_bytes(32))" > kek.bin` | 32 raw bytes (or their base64 text); mode `0600`/`0400` |
| Fingerprint key | the same command, to a different file | never the KEK's bytes: boot refuses a key reused across purposes |
| Transit key (`vault_transit`) | `vault write -f transit/keys/<key>` | never set `exportable` |
| Service-client secret | `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` | 256 bits from a CSPRNG, never chosen by a person; one per client |
| Its registry digest | `python3 -c "from fastapi_m8 import ConsumerCredential; print(ConsumerCredential.create('<client>', '<secret>').encoded_secret)"` | only the `sha256$…` digest goes into `AI_SERVICE_CLIENTS` |
| Job-context signing seed (media-service) | `python -m ai_sdk_m8.jobcontext keygen --out <seed-file>` | prints `kid` and the public key, never the seed |
| OCR receipt seed (gateway) | `python -m ai_sdk_m8.jobcontext keygen --out <seed-file>` | a separate run; set `AI_EXECUTION_RECEIPT_KID` to the printed `kid` |
| Sandbox attestation seed (media) | the same command, for each sandbox service | never reused for any other purpose |

A digest of a secret is a fast hash, so the secret's entropy is the only
defence of a leaked registry: never shorten it. A slow hash or a peppered
HMAC in `auth-sdk-m8` is a named follow-on.

### Key rotation: KEK, fingerprint key and transit key (D-23)

Rotation is a deployment protocol, not one command. The start-up coverage
check is the safety net: a replica refuses to start while any stored row
needs a generation it does not hold, so an early removal fails loudly
instead of losing credentials.

1. Deploy the new key to **every** web and scheduler replica as
   decrypt-capable (`AI_CREDENTIAL_KEK_PREVIOUS_FILES`, or
   `AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE`), the old key still active.
2. Switch the active key on every replica.
3. Check `/meta` on every replica reports the new generation.
4. Run `python -m ai_gateway.credentials rewrap` (or `refingerprint`).
5. Run the same command with `--verify`; it exits `1` while any row is
   still under an older generation.
6. Only then remove the old key, into **offline escrow**, not destruction,
   until the backup-retention horizon has passed: every older backup still
   holds rows under it. The escrow is encrypted at rest, readable only by
   the operators who run restores, and restore-tested at each rotation.

For `vault_transit`: rotate the transit key, run `rewrap` and
`rewrap --verify`, and only then raise `min_decryption_version`, and only
once no restorable backup still holds an older ciphertext. Transit versions
stay inside Vault (and its own disaster-recovery backups); the key's
`exportable` flag, irreversible once set, is never set.

### Key rotation: service-client secrets

Measured from `auth-sdk-m8` (`ConsumerCredentialRegistry`): the registry
holds **one** digest per client id and refuses a duplicate id, so there is
no overlap mechanism. A secret cannot be valid in its old and new form at
once. Rotation is therefore a short, coordinated cutover:

1. Generate the new secret and its digest (*Key generation*).
2. Replace the client's digest in `AI_SERVICE_CLIENTS` and its secret in the
   client's own configuration, then restart both, gateway first.
3. Between the two restarts the client's calls answer `401`. An
   asynchronous run fails its attempt and is retried by media-service's
   attempt policy; a synchronous search degrades to FTS-only.

Registering a second client id instead does not give an overlap: job
contexts bind `azp`, and media-service mints for a fixed client id. Rotate
at once, outside a scheduled rotation, when a secret may have leaked.

### Key rotation: job-context signing keys (`kid`)

1. Generate a new seed in media-service (*Key generation*).
2. Add its public key to the issuing client's `job_context_public_keys` in
   `AI_SERVICE_CLIENTS`, next to the old one, and restart every gateway
   replica.
3. Switch media-service's signer to the new seed.
4. Wait at least `AI_JOB_CONTEXT_MAX_TTL_SECONDS` (900 s) plus
   `AI_JOB_CONTEXT_CLOCK_SKEW_SECONDS` after the switch, then remove the old
   public key. Removing it earlier refuses contexts that are still valid.

A key that may have leaked is removed at once instead; contexts it signed
then fail, which is the point.

### Key rotation: the OCR receipt key (D-23)

1. Generate a new receipt seed (*Key generation*).
2. Add its public key to media-service's `AI_GATEWAY_RECEIPT_PUBLIC_KEYS`.
3. Switch the gateway's `AI_EXECUTION_RECEIPT_KEY_FILE` and
   `AI_EXECUTION_RECEIPT_KID` on every web replica.
4. Remove the old public key from media-service after the longest document
   attempt (`MEDIA_DOCUMENT_ATTEMPT_MAX_SECONDS`) plus a grace.

Receipts are verified once, at activation, which persists the verified
digest; later reads compare bytes and never re-verify a signature, so no
historical receipt key is ever needed.

### Key rotation: the sandbox attestation key (media D-47)

The same order on the media side: add the new public key to
`MEDIA_SANDBOX_ATTESTATION_PUBLIC_KEYS`, switch the sandbox service's seed,
and remove the old key once no un-activated chain signed by it can still
arrive (the activation window).

### KEK backup and loss

**KEK loss is credential loss.** Every envelope wrapped under a lost KEK
generation is unrecoverable, and so are the provider keys in it; the
gateway has no recovery path by design.

- Back up the KEK (and every escrowed previous generation) separately from
  `ai_db` backups, under different access. A database backup stored next to
  its KEK is a full credential disclosure.
- Restore-test the KEK backup at each rotation, together with a database
  backup it must open.
- If a KEK is lost anyway, restore it from that backup. This build has
  **no supported recovery without it**: every web and scheduler replica
  refuses to start while a row still holds material under the lost
  generation, and deleting a credential does not clear its material (the
  delete is logical, D-43), so nothing can run to remove those rows. A
  recovery command that destroys unreadable material, after which owners
  re-enter their keys, is not shipped.
- With `vault_transit` the same holds for the transit key inside Vault: its
  loss, or a Vault restore that lost versions, loses the credentials it
  wrapped.

**Fingerprint-key loss is not credential loss.** Fingerprints are
recomputed from the decrypted secret: configure a new fingerprint key and
run `python -m ai_gateway.credentials refingerprint` (the command does not
run the start-up coverage check), then start the web replicas.

### Installation identity and copies (`clone-init`)

`AI_DEPLOYMENT_ID` is the installation identity: a UUID generated once,
backed up with the deployment's secrets and configuration (independently of
`ai_db`), and **never regenerated**. It namespaces the installation's Vault
paths, the audience of every job context, the issuer of every receipt and
the names of its provider files. Web and scheduler refuse to start against a
database that records a different id.

Two deployments must never share one id on a provider account: each would
take the other's in-flight files for its own.

A copy of a deployment (staging from production, a migrated host kept
alongside the old one) needs `clone-init`: copied credential material
destroyed, a new KEK or transit key and AppRole, a new receipt seed,
a new installation id, and media-service re-pointed to it. **`clone-init`
is not shipped by this build**, so a copy that keeps running beside its
source is not supported. Moving a deployment (the source stopped for good)
keeps its id.

### Restore

After any `ai_db` restore, in this order:

1. **Stop every gateway and scheduler process first.**
2. `python -m ai_gateway.restore reconcile`: the fail-closed reset — every
   provider disabled, every active credential `reconfirm_required`, every
   `fall_through` binding back to `fail`, execution held for the
   job-context TTL plus skew, the budget held until the next UTC day.
3. Start the scheduler. It records replay safety once the hold passed,
   runs the external reconciliation (spools cleaned after the snapshot point
   are released and audited as restore artifacts; the residual for provider
   files the restored database never knew is recorded), and writes the
   security report — in that order. `python -m ai_gateway.restore status`
   shows the steps taken.
4. `python -m ai_gateway.restore ratify --evidence "<ticket>"`, which
   refuses until all three steps are done. It resumes execution and
   re-baselines the high-water mark.
5. Re-enable providers and have owners re-confirm their credentials one by
   one, using the log-sink audit stream as evidence of what changed after
   the snapshot. The stream is never replayed as authority.

Consequences to plan for:

- the budget day stays held: budgeted admissions answer `quota_exceeded`
  until the next UTC midnight after ratification; V1 has no reconstruction;
- a tenant's or user's key rotated after the backup point must be
  re-entered: the restored database holds only the older version;
- on the database backends, provider files created under a version newer
  than the backup are beyond reach, bounded only by provider-side expiry.
  Continuous WAL archiving (point-in-time recovery) shrinks that window;
- `restricted` external OCR stays refused on those backends (*`restricted`
  OCR and the restore residual*, above);
- after a Vault-side restore, `restore reconcile --vault` belongs to the
  `vault` KV backend, which this build does not serve (it exits `2`), and so
  do the `credential_material_lost` alert and material-loss handling.

### Remote artifacts

A provider file the scheduler could not prove deleted is parked as
`manual_cleanup_required`, which raises an alert (`ai_remote_artifacts`
by status). Its credential version cannot be destroyed while it is parked.

1. Inspect the row as the scope's owner or the superuser
   (`GET …/credentials/{credential_id}/remote-artifacts`).
2. Delete the file in the provider's console, signed in as the account of
   the **original** credential version. A BYOK row is resolved by its owner,
   in their own provider account.
3. Wait for the scheduler's next proof (it retries after the provider's
   expiry, then daily), or close the row as an accepted residual:
   `python -m ai_gateway.execution remote-artifact accept-residual --id
   <artifact-id> --evidence "<ticket>"`. That writes an audited
   residual-risk acceptance with the remote id, file name and expiry. It is
   reported as accepted risk, never as cleanup.

Provider-side expiry is defense in depth, never proof.

### Spool repair (`spool_lock_missing`)

A spool whose lock file vanished while its reservation is held is impossible
under the lock protocol outside a restore, so it is treated as tampering:
`spool_lock_missing` is logged and the capacity stays charged.

1. Investigate how the lock file disappeared.
2. Confirm no gateway process holds the data file (`/spool/<execution-id>`),
   for example with `fuser` or `lsof` on every gateway and scheduler
   container.
3. `python -m ai_gateway.execution spool repair --id <execution-id>
   --evidence "<how it was confirmed>"`. The release is audited
   (`spool.repair`), and the next orphan pass removes the data file.

After an `ai_db` restore the same state is normal, and the restore's
recovery releases it without an alert.

### Offboarding a user

A departed user's personal key keeps serving that user's still-owned
objects until a superuser disables or deletes it (A-2). Offboarding
therefore includes: as the superuser, disable or delete each of the user's
credentials. Their bindings then follow `on_unavailable` (`fail` by
default, or the next scope only where the user set `fall_through`). The
superuser cannot read, rotate, re-enable or rebind the key.

### Binding semantics (`on_unavailable`)

A scope with no binding falls through to the next scope. A scope with an
explicit binding does not, by default: `on_unavailable = fail` answers
`credential_unavailable` (or `rate_limited`) with no provider request when
its credential is disabled, invalid, deleted, awaiting re-confirmation or
throttled. Set `fall_through` only when the owner accepts that the next
scope's key (and its provider account) receives the data instead; the
change is audited, and a data-class or boundary denial never falls through.

### Changing an `operator_declared` model

A used model's identity is frozen. To move a profile to another model or
revision: register a new model, then create a new profile revision bound to
it. The new revision has a new `execution_identity` and, for embeddings, a
new `embedding_space_id`; media-service answers search FTS-only until its
space migration re-indexes into the new space (media `T69`). Never relabel a
model's revision in place to avoid the re-index.

### Migrations

Run `ai-migrate` (the `ai_owner` one-shot) before starting the web and
scheduler after every upgrade; nothing else runs Alembic. A web or scheduler
process that finds another revision exits.

### Audit pruning

The runtime never prunes the audit tables, and the default retention is
unlimited. To prune by operator policy:
`python -m ai_gateway.audit_prune --before <date> --operator <name>`,
through the `ai-migrate` service as `ai_owner`. It writes an `audit.prune`
row first, refuses a future date, and changes nothing as `ai_runtime`. Alert
on `ai_audit_table_bytes{table}` past the threshold the deployment sets.
