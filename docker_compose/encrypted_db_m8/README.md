# encrypted_db_m8

The gateway alone in the **production posture**: provider secrets are
envelope-encrypted in `ai_db` (the `database` backend) under a local KEK file
mounted as a Docker secret. This is the *Simple LAN* deployment profile, and a
target for the gateway's live security suite.

- **Strict production.** Both the gateway and the issuer run with
  `ENVIRONMENT=production` and `STRICT_PRODUCTION_MODE=true`:
  - no docs or OpenAPI;
  - admission bounds required;
  - per-consumer private auth at the issuer: `INTERNAL_CLIENT_ID=ai-gateway`,
    with its digest in the issuer's `PRIVATE_API_CONSUMERS`.
- **Hostname.** The stack answers on `DOMAIN=ai-gateway.lan`. Resolve the
  name to this host and trust `secrets/stack_ca.pem`. Traefik's certificate
  names it, `localhost` and `127.0.0.1`.
- **Optional Ollama.** `docker compose --profile ollama up -d` adds a local
  runtime on `ai_net` only. Load models with the `ollama-pull` one-shot (see
  the [stack index](../README.md#optional-local-models-encrypted_db_m8)).

```bash
bash init.sh
docker compose up -d
```

Back up `./secrets`: the KEK and `AI_DEPLOYMENT_ID` live there.
