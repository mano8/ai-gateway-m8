"""Test bootstrap for ai_gateway.

``ai_gateway.core.config`` validates its settings at import time and fails fast
when the configuration is incomplete, so a deterministic environment has to
exist before the first ``ai_gateway`` import. Environment variables outrank any
developer ``.env``, which keeps this suite identical locally and in CI (where no
``.env`` is checked in).

Every value here is a throwaway placeholder. No test opens a socket to a real
service; the only databases are in-memory SQLite surrogates.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

TEST_ISSUER = "https://auth.test.invalid"
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
    "DB_HOST": "127.0.0.1",
    "DB_PORT": "5432",
    "DB_DATABASE": "ai_db",
    "DB_USER": "ai_runtime_tests",
    "DB_PASSWORD": "GatewayTests_Passw0rd",
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
    # Gateway keys without a default.
    "AI_DEPLOYMENT_ID": "6f1c1a52-2b8e-4a0e-9a37-3f4b5c6d7e80",
    "AI_CREDENTIAL_STORAGE_BACKEND": "database",
    "AI_SERVICE_CLIENTS": "[]",
    "AI_MAX_CREDENTIALS_PER_SCOPE": "10",
}

for _key, _value in TEST_ENV.items():
    os.environ[_key] = _value


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
