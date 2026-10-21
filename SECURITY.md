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

### Prompt injection and untrusted provider output

### Denial of wallet and resource exhaustion

### Logging, metrics and error disclosure

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
