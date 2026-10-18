# Build context: the repository root.
#   docker build -f ai_gateway/Dockerfile .

# ---------- BUILD STAGE ----------
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS builder

WORKDIR /install

ARG ENVIRONMENT=production
ENV PIP_ROOT_USER_ACTION=ignore

COPY ./ai_gateway/requirements_base.txt .
COPY ./ai_gateway/requirements_dev.txt .
COPY ./ai_gateway/requirements_prod.txt .
COPY ./ai_gateway/requirements_prod.lock .

# Release builds install from a hash-locked, fully pinned set, so a rebuild of
# the same source cannot silently resolve a different dependency graph.
# Development builds keep the unpinned floors. Regenerate the lock with:
#   pip-compile --generate-hashes --no-emit-index-url --no-strip-extras \
#     --output-file=requirements_prod.lock requirements_prod.txt
RUN pip install --no-cache-dir --upgrade "pip==26.1.1" && \
    if [ "$ENVIRONMENT" = "development" ]; then \
        pip install --prefix=/install --no-cache-dir -r requirements_base.txt && \
        pip install --prefix=/install --no-cache-dir -r requirements_dev.txt ; \
    else \
        pip install --prefix=/install --no-cache-dir \
            --require-hashes -r requirements_prod.lock ; \
    fi


# ---------- RUNTIME STAGE ----------
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH="/home/appuser/.local/bin:$PATH"
ENV PYTHONPATH=/opt

# Debian patch layer — the one fleet form; owner: the workspace's
# `.workspace/context/debian-patch-layer.md`. Every Debian package self-heals
# on each build through `apt-get upgrade -y`; nothing is exact-pinned and
# nothing is installed that the base does not already ship. The base digest
# above moves in lock-step with the other service images, never alone. If a
# package must ever lead the pinned base, the recorded form is an unpinned
# install plus a `dpkg --compare-versions … ge <floor>` assertion in this same
# RUN — never an exact `=` pin, which freezes the image on the next advisory.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --create-home appuser

WORKDIR /opt

COPY --from=builder /install /usr/local

# Strip the installer tooling from the runtime image. Nothing here installs
# anything at run time: the release set is installed hash-locked in the
# builder, so pip, setuptools and wheel are pure attack surface (and pip's
# vendored SBOM would surface its vendored dependencies as installed packages).
# At the pinned digest the base ships pip alone, so the setuptools/wheel
# uninstall stands as a guard against a later base reintroducing them. The
# import and console-script checks fail the build if the removal broke the
# runtime graph or the entrypoint's binaries.
RUN python -m pip uninstall -y setuptools wheel && \
    python -m pip uninstall -y pip && \
    python -c "import alembic, fastapi, fastapi_m8, httpx, prometheus_client, psycopg2, pydantic, pydantic_settings, sqlalchemy, sqlmodel, starlette, tenacity, uvicorn" && \
    alembic --version && uvicorn --version && gunicorn --version

COPY --chown=appuser:appuser ./ai_gateway ./ai_gateway

# Normalise line endings and the executable bit of the run-mode scripts. The
# image writes nothing at run time, so it runs under a read-only root
# filesystem (the OCR spool is a dedicated mounted volume).
RUN find /opt/ai_gateway/scripts -name "*.sh" -exec sed -i 's/\r$//' {} + && \
    chmod +x /opt/ai_gateway/scripts/*.sh

# Numeric UID:GID of appuser (created above), so the host and any runtime can
# resolve it without the image's /etc/passwd (hadolint DL3066).
USER 1000:1000

EXPOSE 8000

# Web run-mode by default. The scheduler runs scripts/scheduler_start.sh and
# the ai-migrate one-shot runs scripts/ai_migrate.sh, from this same image.
CMD ["./ai_gateway/scripts/docker_start.sh"]
