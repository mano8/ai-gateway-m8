# ai-gateway-m8

## Layer

Service (AI provider gateway).

## Purpose

Run the control plane that alone holds AI provider credentials. The gateway
enforces data-class policy, meters admission units, verifies signed job
contexts, and executes provider calls on behalf of the fleet's services.

The service package is `ai_gateway`; the image is `tepochtli/ai-gateway-m8`.

## Repository boundaries

- Only the gateway decrypts provider credentials. No other repository stores,
  receives, or logs them.
- Every execution route requires a verified signed job context. A user JWT is
  never sufficient on an execution route; user authentication applies to
  management routes only.
- `fa-auth-m8` is the issuer through JWT/JWKS and its private revocation API.
  The gateway shares no issuer database or Redis and copies no issuer or
  signing code.
- `auth-sdk-m8` is never imported directly in service code — only `fastapi-m8`
  and its re-exports are.
- The signed-object rule comes from `ai-sdk-m8`; the gateway carries no second
  implementation.
- Schema migrations run only through the dedicated migration command, never on
  web or scheduler start.

These are repository architecture constraints. If a requested change appears to
break one, record the decision in the workspace context when that optional
enhancement is available and confirm the exception before proceeding.

## Standalone authority

This file, repository documentation, and existing CI are the authoritative local
context. A verified nearest workspace may optionally add launcher-selected
policies and tasks; its absence is a successful standalone condition and does
not make a parent workspace necessary.
