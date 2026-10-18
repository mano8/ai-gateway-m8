"""Service settings for ai_gateway.

Extends ``ConsumerServiceSettings`` with the gateway's own fields only.
``ConsumerAuthMixin``, ``ObservabilitySettingsMixin`` and ``CommonSettings``
are inherited through the base class, and so are the ``<FIELD>_FILE`` secret
sources.

Scaffold scope: every gateway key is declared here with its type, so the
``.env.example`` beside this package and the settings model stay in step and an
unknown key is refused (``extra="forbid"``). The keys without a safe default are
required, so an incomplete environment fails fast at import. The cross-field
boot refusals (backend/KEK contradictions, placeholder secrets under
production/strict, key-file mode checks, TTL ordering, the data-class policy
shape) are not implemented yet; they belong to the settings task that follows
this scaffold and land as validators on this same class.
"""

from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi_m8 import ConsumerServiceSettings, find_dotenv
from pydantic import NonNegativeInt, PositiveInt
from pydantic_settings import SettingsConfigDict

from .. import __version__


class Settings(ConsumerServiceSettings):
    """ai_gateway settings — inherits every consumer field from fastapi-m8.

    ``SERVICE_VERSION`` re-surfaces the package ``__version__``; the contract
    axis is versioned separately (``CONTRACT_VERSION``) and served at
    ``{API_PREFIX}/meta``.
    """

    ENV_FILE_DIR: Path = Path(__file__).resolve().parent.parent

    SERVICE_VERSION: str = __version__
    CONTRACT_VERSION: str = "1.0"
    CONTRACT_RANGE: str = ">=1.0.0 <2.0.0"

    # ── Installation identity ────────────────────────────────────────────────
    # Generated once per installation and never rotated; boot will refuse a
    # value that differs from the database's recorded installation.
    AI_DEPLOYMENT_ID: UUID

    # ── Credential storage and key encryption ────────────────────────────────
    AI_CREDENTIAL_STORAGE_BACKEND: Literal["database", "vault"]
    AI_CREDENTIAL_KEK_PROVIDER: Literal["local", "vault_transit"] | None = None
    AI_CREDENTIAL_KEK_FILE: Path | None = None
    AI_CREDENTIAL_KEK_PREVIOUS_FILES: str | None = None
    AI_CREDENTIAL_FINGERPRINT_KEY_FILE: Path | None = None
    AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE: Path | None = None
    AI_CREDENTIAL_PREPARE_GRACE_SECONDS: PositiveInt | None = None
    AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS: PositiveInt | None = None
    AI_MAX_CREDENTIALS_PER_SCOPE: PositiveInt

    # ── Vault ────────────────────────────────────────────────────────────────
    AI_VAULT_ADDR: str | None = None
    AI_VAULT_AUTH_METHOD: Literal["token_file", "approle"] | None = None
    AI_VAULT_TOKEN_FILE: Path | None = None
    AI_VAULT_ROLE_ID_FILE: Path | None = None
    AI_VAULT_SECRET_ID_FILE: Path | None = None
    AI_VAULT_CA_FILE: Path | None = None
    AI_VAULT_TRANSIT_MOUNT: str | None = None
    AI_VAULT_TRANSIT_KEY: str | None = None
    AI_VAULT_KV_MOUNT: str | None = None
    AI_VAULT_KV_PATH_PREFIX: str | None = None
    AI_VAULT_QUIESCENCE_SECONDS: PositiveInt | None = None

    # ── Callers, users and policy ────────────────────────────────────────────
    # Registered service clients and their job-context public keys (JSON).
    AI_SERVICE_CLIENTS: str
    # No implicit default under production/strict; reported in /meta.
    AI_USER_BYOK_ENABLED: bool | None = None
    AI_DATA_CLASS_POLICY: str | None = None
    # Closed capability set; unset enables nothing, and ``ocr`` is never on by
    # default.
    AI_CAPABILITIES_ENABLED: str | None = None

    # ── Provider destinations and client ─────────────────────────────────────
    AI_PROVIDER_ALLOWED_INTERNAL_HOSTS: str | None = None
    AI_PROVIDER_ALLOWED_EXTERNAL_PORTS: str = "443"
    AI_PROVIDER_TIMEOUT_SECONDS: PositiveInt | None = None
    AI_PROVIDER_TOTAL_DEADLINE_SECONDS: PositiveInt | None = None
    AI_PROVIDER_MAX_BACKOFF_SECONDS: PositiveInt | None = None
    AI_PROVIDER_FILE_EXPIRY_SECONDS: PositiveInt | None = None

    # ── Request and payload bounds ───────────────────────────────────────────
    AI_MAX_REQUEST_BYTES: PositiveInt | None = None
    AI_MAX_RESPONSE_BYTES: PositiveInt | None = None
    AI_MAX_OCR_PAGES: PositiveInt | None = None
    AI_MAX_EMBED_INPUTS: PositiveInt | None = None
    AI_MAX_INPUT_CHARS: PositiveInt | None = None
    AI_MAX_RERANK_CANDIDATES: PositiveInt | None = None
    AI_MAX_SCHEMA_BYTES: PositiveInt | None = None
    AI_MAX_SCHEMA_DEPTH: PositiveInt | None = None
    AI_OCR_UPLOAD_INLINE_THRESHOLD_BYTES: PositiveInt | None = None

    # ── Job contexts and clocks ──────────────────────────────────────────────
    AI_JOB_CONTEXT_MAX_TTL_SECONDS: PositiveInt = 900
    AI_JOB_CONTEXT_CLOCK_SKEW_SECONDS: NonNegativeInt = 5
    AI_DISPATCH_CONTEXT_TTL_SECONDS: PositiveInt = 30
    AI_MAX_CLOCK_SKEW_SECONDS: PositiveInt | None = None

    # ── Admission, budgets and reservations ──────────────────────────────────
    AI_TENANT_DAILY_BUDGET_UNITS: PositiveInt | None = None
    AI_USER_DAILY_BUDGET_UNITS: PositiveInt | None = None
    AI_CLIENT_DAILY_BUDGET_UNITS: PositiveInt | None = None
    AI_RATE_LIMIT_PER_MINUTE: PositiveInt | None = None
    AI_MAX_INFLIGHT_PER_CLIENT: PositiveInt | None = None
    AI_RESERVATION_TTL_SECONDS: PositiveInt | None = None

    # ── Provider-side artifacts ──────────────────────────────────────────────
    AI_REMOTE_ARTIFACT_MAX_DELETE_ATTEMPTS: PositiveInt | None = None
    AI_REMOTE_ARTIFACT_MAX_PENDING_HOURS: PositiveInt | None = None
    AI_REMOTE_ARTIFACT_VISIBILITY_GRACE_SECONDS: PositiveInt | None = None
    AI_REMOTE_ARTIFACT_NEGATIVE_LISTINGS: PositiveInt | None = None
    AI_REMOTE_ARTIFACT_PLATFORM_INCIDENT_LISTING: bool = True
    AI_REMOTE_ARTIFACT_PLATFORM_SWEEP_ENABLED: bool = False
    # Declined at ratification: stays unset in every shipped stack.
    AI_RESTRICTED_OCR_RESTORE_RESIDUAL_ACCEPTED: bool = False

    # ── OCR spool ────────────────────────────────────────────────────────────
    AI_OCR_SPOOL_DIR: Path | None = None
    AI_OCR_SPOOL_MAX_BYTES: PositiveInt | None = None
    AI_OCR_SPOOL_TTL_SECONDS: PositiveInt | None = None
    AI_MAX_CONCURRENT_SPOOLS: PositiveInt | None = None
    AI_UPLOAD_TOTAL_TIMEOUT_SECONDS: PositiveInt | None = None

    # ── Execution receipts and retention ─────────────────────────────────────
    AI_EXECUTION_RECEIPT_KEY_FILE: Path | None = None
    AI_EXECUTION_RECEIPT_KID: str | None = None
    AI_EXECUTION_RETENTION_DAYS: PositiveInt | None = None

    # Vault/`_FILE` source ordering is handled by the inherited
    # CommonSettings.settings_customise_sources classmethod — no override needed.
    model_config = SettingsConfigDict(
        env_file=find_dotenv(Path(__file__).resolve().parent.parent),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="forbid",
    )


try:
    settings = Settings()  # type: ignore[call-arg]
except Exception as exc:
    raise RuntimeError(f"Configuration validation error:\n {exc}") from exc
