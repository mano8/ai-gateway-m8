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

### Prompt injection and untrusted provider output

### Denial of wallet and resource exhaustion

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
