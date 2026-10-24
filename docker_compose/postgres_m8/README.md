# postgres_m8

The gateway alone in the **development posture**: the `database` credential
backend with a local KEK file (`secrets/ai_kek`), `ENVIRONMENT=local`, docs
and OpenAPI served on the loopback `api` entrypoint. Use it to explore the
API. [`encrypted_db_m8`](../encrypted_db_m8/) is the same layout in
production mode.

```bash
bash init.sh
docker compose up -d
```

- Public router: `https://localhost:4431/ai/…`. Trust `secrets/stack_ca.pem`.
- Unfiltered loopback entrypoint: `http://127.0.0.1:18080/ai/…`, including
  `/ai/docs`.
- The issuer's superuser: `admin@example.com`, with the password in
  `secrets/issuer_superuser_password`.

The rules every stack keeps are in the [stack index](../README.md).
