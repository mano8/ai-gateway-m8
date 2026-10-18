# Changelog

All notable changes to `ai-gateway-m8` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First version: `0.1.0`, dated when the human publishes the release.

### Added

- Service scaffold adapted from `fa-auth-m8`'s `examples/fastapi_full`
  (`SCAFFOLD.md` maps every file): the `fastapi-m8` application factory,
  `ConsumerServiceSettings` subclass declaring every gateway key, build-once
  auth and database dependencies, the auth event-stream lifespan, the database
  health check and the optional metrics endpoint.
- Execution-route guard: every execution router is built with a mandatory
  job-context dependency that never reads the `Authorization` header and,
  until the verifier lands, refuses every request with `401 context_invalid`.
- Run-modes: web and scheduler start scripts that wait for the database and
  exit unless `alembic_version_ai` equals the packaged head, and the
  `ai-migrate` one-shot as the only command that runs Alembic.
- Two-stage `Dockerfile` on the fleet's pinned `python:3.14-slim` digest with
  the Debian patch layer, a hash-locked install, pip/setuptools/wheel removed
  and a non-root `appuser`.
- `ruff` `TID251` bans: `auth_sdk_m8` in service code, and the credential
  version model outside `ai_gateway/credentials/`.
- CI (lint, type check, bandit, pip-audit, Trivy, tests on Python 3.12–3.14
  at 100% branch coverage, tests against the shipped lock, hadolint, image
  scan, gitleaks) and the release-only Docker publish workflow.
- Repository baseline: `.codacy.yml`, `.dockerignore`, `.gitleaks.toml`,
  `.markdownlint.yaml`, `.github/dependabot.yml`, `.github/FUNDING.yml`,
  `SECURITY.md`.
