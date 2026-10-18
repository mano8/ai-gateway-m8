# Compose stacks

Placeholder. The gateway's deployment examples (gateway-only stacks with the
web, scheduler and `ai-migrate` services, the gateway's own `ai_db`, and the
hardened profile) land here. None ships yet.

Every stack will run `ai-migrate` as a one-shot before the web and scheduler
services, mount secrets as files, and keep the OCR spool on a dedicated volume.
