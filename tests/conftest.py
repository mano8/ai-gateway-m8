"""Test bootstrap for ai_gateway.

``ai_gateway.core.config`` validates its settings at import time and fails fast
when the configuration is incomplete, so a deterministic environment has to
exist before the first ``ai_gateway`` import. Environment variables outrank any
developer ``.env``, which keeps this suite identical locally and in CI (where no
``.env`` is checked in).

Every value here is a throwaway placeholder. The key files are random and
written to a private temporary directory, mode 0600, before the import. The
service clients in ``AI_SERVICE_CLIENTS`` are real: random secrets stored as
their salted digests, and fresh Ed25519 issuer keys, so the execution guard
runs against the registry the gateway parses.
"""

from __future__ import annotations

import atexit
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
import os
import secrets
import shutil
import tempfile
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any

from ai_sdk_m8.signed import (
    derive_kid,
    encode_public_key,
    generate_seed,
    public_key_from_seed,
)

# Not through fastapi_m8: importing it here would bind the real ``find_dotenv``
# before the stub below replaces it.
from auth_sdk_m8.security.consumer_auth import (
    INTERNAL_CLIENT_HEADER,
    INTERNAL_TOKEN_HEADER,
    ConsumerCredential,
)

#: Private directory for the test key files (removed at interpreter exit).
KEY_DIR = Path(tempfile.mkdtemp(prefix="ai-gateway-test-keys-"))
atexit.register(shutil.rmtree, KEY_DIR, ignore_errors=True)


def write_key_file(name: str, content: bytes | None = None, mode: int = 0o600) -> Path:
    """Write a key file under :data:`KEY_DIR` with ``mode``."""
    path = KEY_DIR / name
    path.write_bytes(secrets.token_bytes(32) if content is None else content)
    path.chmod(mode)
    return path


import pg_harness as pg  # noqa: E402

KEK_FILE = write_key_file("kek")
FINGERPRINT_KEY_FILE = write_key_file("fingerprint")


@dataclass(frozen=True)
class ServiceIdentity:
    """A registered test service client; ``seed`` signs its job contexts."""

    client_id: str
    scopes: tuple[str, ...]
    seed: bytes | None = None
    secret: str = field(default_factory=lambda: secrets.token_urlsafe(48))

    @property
    def kid(self) -> str:
        """The ``kid`` its seed derives."""
        assert self.seed is not None
        return derive_kid(public_key_from_seed(self.seed))

    def headers(self, secret: str | None = None) -> dict[str, str]:
        """The ``X-Internal-Client`` / ``X-Internal-Token`` pair."""
        return {
            INTERNAL_CLIENT_HEADER: self.client_id,
            INTERNAL_TOKEN_HEADER: self.secret if secret is None else secret,
        }

    def entry(self) -> dict[str, object]:
        """The ``AI_SERVICE_CLIENTS`` entry: hashed secret, scopes, keys."""
        encoded = ConsumerCredential.create(self.client_id, self.secret).encoded_secret
        value: dict[str, object] = {"secret": encoded, "scopes": list(self.scopes)}
        if self.seed is not None:
            public = encode_public_key(public_key_from_seed(self.seed))
            value["job_context_public_keys"] = {self.kid: public}
        return value


#: Signs contexts for its own synchronous calls and for the documents worker.
MEDIA_SERVICE = ServiceIdentity(
    "media-service",
    (
        "execute:embedding",
        "execute:rerank",
        "execute:structured_output",
        "job-context:issue",
        "profiles:read",
    ),
    seed=generate_seed(),
)
#: Presents contexts media-service signed for it (``azp = media-worker``).
MEDIA_WORKER = ServiceIdentity("media-worker", ("execute:ocr",))
#: A second issuer: its key must never stand in for media-service's.
DOC_ISSUER = ServiceIdentity(
    "doc-issuer", ("execute:embedding", "job-context:issue"), seed=generate_seed()
)
#: Reads profiles only; executes nothing.
PROFILE_READER = ServiceIdentity("profile-reader", ("profiles:read",))
SERVICE_CLIENTS = (MEDIA_SERVICE, MEDIA_WORKER, DOC_ISSUER, PROFILE_READER)

TEST_ISSUER = "https://auth.test.invalid"
HEALTH_DETAIL = {"X-Internal-Token": "GatewayTests-Health-Detail-Credential-1"}
TEST_AUDIENCE = "ai-gateway-tests"
ACCESS_SECRET = "GatewayTests-AccessKey-ai8gw-Ab12Cd34"

TEST_ENV = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "PROJECT_NAME": "ai-gateway-tests",
    "STACK_NAME": "ai-gateway-tests",
    "API_PREFIX": "/ai",
    "BACKEND_HOST": "http://127.0.0.1:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost:5173",
    "AUTH_SERVICE_ROLE": "consumer",
    "AUTH_PREFIX": "/user",
    "SELECTED_DB": "Postgres",
    "DB_HOST": pg.ADMIN_URL.host or "127.0.0.1",
    "DB_PORT": str(pg.ADMIN_URL.port or 5432),
    "DB_DATABASE": pg.DB_NAME,
    "DB_USER": pg.RUNTIME,
    "DB_PASSWORD": pg.RUNTIME_PASSWORD,
    "SECRET_KEY": "GatewayTests-SessionSecret-ai8gw-Ab1",
    "ACCESS_SECRET_KEY": ACCESS_SECRET,
    "REFRESH_SECRET_KEY": "GatewayTests-RefreshKey-ai8gw-Ab12Cd34",
    "ACCESS_TOKEN_ALGORITHM": "HS256",
    "REFRESH_TOKEN_ALGORITHM": "HS256",
    "TOKEN_MODE": "stateless",
    # Strict validation on, so issuer and audience binding is exercised.
    "TOKEN_STRICT_VALIDATION": "true",
    "TOKEN_ISSUER": TEST_ISSUER,
    "TOKEN_AUDIENCE": TEST_AUDIENCE,
    "EVENT_SIGNING_ENABLED": "false",
    "METRICS_ENABLED": "false",
    "HEALTH_DETAIL_CREDENTIAL": "GatewayTests-Health-Detail-Credential-1",
    # Gateway keys without a default.
    "AI_DEPLOYMENT_ID": "6f1c1a52-2b8e-4a0e-9a37-3f4b5c6d7e80",
    "AI_CREDENTIAL_STORAGE_BACKEND": "database",
    "AI_CREDENTIAL_KEK_PROVIDER": "local",
    "AI_CREDENTIAL_KEK_FILE": str(KEK_FILE),
    "AI_CREDENTIAL_FINGERPRINT_KEY_FILE": str(FINGERPRINT_KEY_FILE),
    "AI_SERVICE_CLIENTS": json.dumps({c.client_id: c.entry() for c in SERVICE_CLIENTS}),
    "AI_MAX_CREDENTIALS_PER_SCOPE": "10",
}

for _key, _value in TEST_ENV.items():
    os.environ[_key] = _value

#: Admission bounds a production configuration must set (D-24, ``T27``).
ADMISSION_LIMITS = {
    "AI_CLIENT_DAILY_BUDGET_UNITS": "1000000",
    "AI_TENANT_DAILY_BUDGET_UNITS": "1000000",
    "AI_USER_DAILY_BUDGET_UNITS": "1000000",
    "AI_RATE_LIMIT_PER_MINUTE": "600",
    "AI_MAX_INFLIGHT_PER_CLIENT": "32",
}


# The environment must be complete before ``ai_gateway`` is imported.
import auth_sdk_m8.utils.paths as _paths_mod  # noqa: E402

# ``find_dotenv`` raises when no ``.env`` exists anywhere up the tree, which is
# always true on a CI runner; the variables above are a complete environment.
_real_find_dotenv = _paths_mod.find_dotenv
_paths_mod.find_dotenv = lambda *_a, **_kw: ""

import jwt  # noqa: E402

import ai_gateway.main  # noqa: E402,F401  (builds the app once)

_paths_mod.find_dotenv = _real_find_dotenv

#: Roles whose canonical ``is_superuser`` claim is true.
SUPERUSER_ROLES = frozenset({"superadmin"})


def access_token(
    role: str,
    *,
    issuer: str = TEST_ISSUER,
    audience: str = TEST_AUDIENCE,
    secret: str = ACCESS_SECRET,
    expires_in: timedelta = timedelta(minutes=5),
    subject: uuid.UUID | None = None,
    **extra: Any,
) -> str:
    """Mint an HS256 access token as the issuer would, for *role*."""
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(subject or uuid.uuid4()),
        "jti": uuid.uuid4().hex,
        "type": "access",
        "iss": issuer,
        "aud": audience,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + expires_in).timestamp()),
        "email": f"{role}@example.com",
        "role": role,
        "is_superuser": role in SUPERUSER_ROLES,
        "is_active": True,
        **extra,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def bearer(role: str, **kwargs: Any) -> dict[str, str]:
    """Return an ``Authorization`` header carrying a token for *role*."""
    return {"Authorization": f"Bearer {access_token(role, **kwargs)}"}


import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _postgres() -> None:
    """Create the roles, a fresh test database, the schema and the installation."""
    from ai_gateway.core.config import settings

    pg.bootstrap_database()
    pg.migrate_and_install(settings.AI_DEPLOYMENT_ID, settings.AI_OCR_SPOOL_MAX_BYTES)


@pytest.fixture
def clean_db() -> Iterator[None]:
    """Empty every data table before and after the test."""
    pg.truncate_all()
    yield
    pg.truncate_all()
