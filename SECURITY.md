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

### Data-class policy and provider destinations

### Server-side request forgery and outbound egress

### Prompt injection and untrusted provider output

### Denial of wallet and resource exhaustion

### Logging, metrics and error disclosure

### Supply chain and image provenance

### Database roles, migrations and restore

## Controls in place in this scaffold

- Execution routes refuse every request (`401 context_invalid`) until the
  job-context verifier lands; the guard never reads `Authorization`.
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
