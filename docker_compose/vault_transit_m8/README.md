# vault_transit_m8

The gateway alone in the **production posture**, with the recommended
*Hardened Vault* backend: `database` storage whose data keys are wrapped by a
Vault transit key (`AI_CREDENTIAL_KEK_PROVIDER=vault_transit`). No KEK file
exists on the host. The gateway logs in to Vault with an AppRole over TLS.
This stack is a target for the gateway's live security suite.

```bash
bash init.sh
docker compose up -d
```

**The bundled Vault is learning-only.** It runs in server mode, with
persistent storage and TLS from the stack CA, but it is initialised with one
unseal share, and that share and the root token are kept in the
`vault_bootstrap` volume. `vault-init` unseals it on every `up`. Production
uses [`vault_prod_template`](../vault_prod_template/).

The AppRole policy grants `transit/encrypt` and `transit/decrypt` on
`ai-gateway-kek`, nothing else.

The live check `tests/live/test_vault_transit_stack.py` runs against this
stack; its module docstring has the command.
