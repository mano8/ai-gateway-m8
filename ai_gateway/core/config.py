"""
Service settings for ai_gateway (C-14, T15).

Extends ``ConsumerServiceSettings`` with the gateway's own fields.
``ConsumerAuthMixin``, ``ObservabilitySettingsMixin`` and ``CommonSettings``
are inherited through the base class, and so are the ``<FIELD>_FILE`` secret
sources.

Every contradiction the gateway can detect without a database is refused
here, at construction, so an inconsistent environment never boots. The checks
that need the database — the schema revision, the installation identity, the
key generations stored rows need — run in :mod:`ai_gateway.prestart` and at
application start.

Secret keys are read from files once, here, and kept as
:class:`~ai_gateway.core.keyfiles.KeyMaterial` (redacted ``repr``) for the
components that use them; no key is ever an environment value.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Final, Literal
from urllib.parse import urlsplit
from uuid import UUID

from ai_sdk_m8.schemas import V1_CAPABILITIES, Capability
from ai_sdk_m8.signed import derive_kid, public_key_from_seed
from pydantic import (
    NonNegativeInt,
    PositiveInt,
    PrivateAttr,
    ValidationError,
    model_validator,
)
from pydantic_settings import SettingsConfigDict

from fastapi_m8 import ConsumerServiceSettings, find_dotenv

from .. import __version__
from .keyfiles import KeyFileError, KeyMaterial, load_key_file, load_secret_text
from .policy import DataClassPolicy, PolicyConfigError, parse_data_class_policy
from .service_clients import (
    ServiceClientConfigError,
    ServiceClients,
    parse_service_clients,
)

#: The fleet's placeholder; refused in every gateway field and every secret.
PLACEHOLDER: Final = "changethis"

#: Grace the scheduler adds before settling a context row, a ``dispatching``
#: row or a spool lease (D-24). Every clock-skew bound must stay within it.
SWEEPER_GRACE_SECONDS: Final = 30

#: Valid Vault auth methods and the file settings each needs.
_VAULT_AUTH_FILES: Final = {
    "token_file": ("AI_VAULT_TOKEN_FILE",),
    "approle": ("AI_VAULT_ROLE_ID_FILE", "AI_VAULT_SECRET_ID_FILE"),
}

_KEK_SETTINGS: Final = (
    "AI_CREDENTIAL_KEK_PROVIDER",
    "AI_CREDENTIAL_KEK_FILE",
    "AI_CREDENTIAL_KEK_PREVIOUS_FILES",
)

#: The admission bounds (D-24); required under production/strict (``T27``).
ADMISSION_SETTINGS: Final = (
    "AI_CLIENT_DAILY_BUDGET_UNITS",
    "AI_TENANT_DAILY_BUDGET_UNITS",
    "AI_USER_DAILY_BUDGET_UNITS",
    "AI_RATE_LIMIT_PER_MINUTE",
    "AI_MAX_INFLIGHT_PER_CLIENT",
)


def _split_list(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_capabilities(raw: str | None) -> frozenset[Capability]:
    if raw is None:
        return frozenset()
    names = _split_list(raw)
    try:
        capabilities = [Capability(name) for name in names]
    except ValueError:
        raise ValueError(
            "AI_CAPABILITIES_ENABLED names an unknown capability"
        ) from None
    if len(set(capabilities)) != len(capabilities):
        raise ValueError("AI_CAPABILITIES_ENABLED repeats a capability")
    if not set(capabilities) <= V1_CAPABILITIES:
        raise ValueError("AI_CAPABILITIES_ENABLED names a capability with no V1 route")
    return frozenset(capabilities)


def _valid_port(text: str) -> int:
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise ValueError(f"{text!r} is not a TCP port")
    return int(text)


def _label_ok(label: str) -> bool:
    return (
        0 < len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(c.isalnum() or c == "-" for c in label)
        and label.isascii()
        and label == label.lower()
    )


def _hostname_ok(name: str) -> bool:
    labels = name.split(".")
    return all(_label_ok(label) for label in labels) and not all(
        label.isdigit() for label in labels
    )


def _parse_internal_hosts(raw: str | None) -> frozenset[tuple[str, int]]:
    if raw is None:
        return frozenset()
    hosts: set[tuple[str, int]] = set()
    for entry in _split_list(raw):
        name, sep, port = entry.rpartition(":")
        if not sep or not _hostname_ok(name):
            raise ValueError(
                f"AI_PROVIDER_ALLOWED_INTERNAL_HOSTS entry {entry!r} is not a "
                "lower-case name:port pair"
            )
        hosts.add((name, _valid_port(port)))
    return frozenset(hosts)


class Settings(ConsumerServiceSettings):
    """
    ai_gateway settings — inherits every consumer field from fastapi-m8.

    ``SERVICE_VERSION`` re-surfaces the package ``__version__``; the contract
    axis is versioned separately (``CONTRACT_VERSION``) and served at
    ``{API_PREFIX}/meta``.
    """

    ENV_FILE_DIR: Path = Path(__file__).resolve().parent.parent

    #: Fleet secrets plus the gateway's: none may hold the placeholder.
    secret_fields: ClassVar[list[str]] = [
        *ConsumerServiceSettings.secret_fields,
        "SECRET_KEY",
        "PRIVATE_API_SECRET",
        "EVENT_SIGNING_KEY",
        "HEALTH_DETAIL_CREDENTIAL",
        "METRICS_SCRAPE_CREDENTIAL",
        "AI_SERVICE_CLIENTS",
    ]

    SERVICE_VERSION: str = __version__
    CONTRACT_NAME: str | None = "ai-gateway-m8"
    CONTRACT_VERSION: str = "1.0"
    CONTRACT_RANGE: str = ">=1.0.0 <2.0.0"

    # ── Installation identity ────────────────────────────────────────────────
    # Generated once per installation and never rotated; boot refuses a value
    # that differs from the database's recorded installation.
    AI_DEPLOYMENT_ID: UUID

    # ── Run-mode ─────────────────────────────────────────────────────────────
    # ``scheduler`` is set by ``python -m ai_gateway.scheduler`` and its start
    # script, never in the shared env file: that process neither needs nor
    # reads the fingerprint key or the OCR receipt seed (D-42).
    AI_RUN_MODE: Literal["web", "scheduler"] = "web"

    # ── Credential storage and key encryption ────────────────────────────────
    AI_CREDENTIAL_STORAGE_BACKEND: Literal["database", "vault"]
    AI_CREDENTIAL_KEK_PROVIDER: Literal["local", "vault_transit"] | None = None
    AI_CREDENTIAL_KEK_FILE: Path | None = None
    # Comma-separated decrypt-only previous KEK files (rotation, D-23).
    AI_CREDENTIAL_KEK_PREVIOUS_FILES: str | None = None
    AI_CREDENTIAL_FINGERPRINT_KEY_FILE: Path | None = None
    AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE: Path | None = None
    AI_CREDENTIAL_PREPARE_GRACE_SECONDS: PositiveInt = 300
    AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS: PositiveInt = 5
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
    AI_VAULT_QUIESCENCE_SECONDS: PositiveInt = 3600

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
    AI_PROVIDER_TIMEOUT_SECONDS: PositiveInt = 30
    AI_PROVIDER_TOTAL_DEADLINE_SECONDS: PositiveInt = 120
    AI_PROVIDER_MAX_BACKOFF_SECONDS: PositiveInt = 300
    AI_PROVIDER_FILE_EXPIRY_SECONDS: PositiveInt = 3600

    # ── Request and payload bounds ───────────────────────────────────────────
    AI_MAX_REQUEST_BYTES: PositiveInt = 50 * 1024 * 1024
    AI_MAX_RESPONSE_BYTES: PositiveInt = 16 * 1024 * 1024
    AI_MAX_OCR_PAGES: PositiveInt = 100
    AI_MAX_EMBED_INPUTS: PositiveInt = 64
    AI_MAX_INPUT_CHARS: PositiveInt = 32768
    AI_MAX_RERANK_CANDIDATES: PositiveInt = 100
    AI_MAX_SCHEMA_BYTES: PositiveInt = 16384
    AI_MAX_SCHEMA_DEPTH: PositiveInt = 8
    AI_OCR_UPLOAD_INLINE_THRESHOLD_BYTES: PositiveInt = 1024 * 1024

    # ── Job contexts and clocks ──────────────────────────────────────────────
    AI_JOB_CONTEXT_MAX_TTL_SECONDS: PositiveInt = 900
    AI_JOB_CONTEXT_CLOCK_SKEW_SECONDS: NonNegativeInt = 5
    AI_DISPATCH_CONTEXT_TTL_SECONDS: PositiveInt = 30
    AI_MAX_CLOCK_SKEW_SECONDS: PositiveInt = 5

    # ── Admission, budgets and reservations ──────────────────────────────────
    # Owned by the execution core; unset budgets are resolved there.
    AI_TENANT_DAILY_BUDGET_UNITS: PositiveInt | None = None
    AI_USER_DAILY_BUDGET_UNITS: PositiveInt | None = None
    AI_CLIENT_DAILY_BUDGET_UNITS: PositiveInt | None = None
    AI_RATE_LIMIT_PER_MINUTE: PositiveInt | None = None
    AI_MAX_INFLIGHT_PER_CLIENT: PositiveInt | None = None
    AI_RESERVATION_TTL_SECONDS: PositiveInt = 60

    # ── Provider-side artifacts ──────────────────────────────────────────────
    AI_REMOTE_ARTIFACT_MAX_DELETE_ATTEMPTS: PositiveInt = 10
    AI_REMOTE_ARTIFACT_MAX_PENDING_HOURS: PositiveInt = 72
    AI_REMOTE_ARTIFACT_VISIBILITY_GRACE_SECONDS: PositiveInt = 300
    AI_REMOTE_ARTIFACT_NEGATIVE_LISTINGS: PositiveInt = 3
    AI_REMOTE_ARTIFACT_PLATFORM_INCIDENT_LISTING: bool = True
    AI_REMOTE_ARTIFACT_PLATFORM_SWEEP_ENABLED: bool = False
    # Declined at ratification: stays unset in every shipped stack.
    AI_RESTRICTED_OCR_RESTORE_RESIDUAL_ACCEPTED: bool = False

    # ── OCR spool ────────────────────────────────────────────────────────────
    AI_OCR_SPOOL_DIR: Path | None = None
    AI_OCR_SPOOL_MAX_BYTES: PositiveInt = 1024 * 1024 * 1024
    AI_OCR_SPOOL_TTL_SECONDS: PositiveInt = 300
    AI_MAX_CONCURRENT_SPOOLS: PositiveInt = 4
    AI_UPLOAD_TOTAL_TIMEOUT_SECONDS: PositiveInt = 120

    # ── Execution receipts and retention ─────────────────────────────────────
    AI_EXECUTION_RECEIPT_KEY_FILE: Path | None = None
    AI_EXECUTION_RECEIPT_KID: str | None = None
    AI_EXECUTION_RETENTION_DAYS: PositiveInt = 90

    # Vault/`_FILE` source ordering is handled by the inherited
    # CommonSettings.settings_customise_sources classmethod — no override needed.
    model_config = SettingsConfigDict(
        env_file=find_dotenv(Path(__file__).resolve().parent.parent),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="forbid",
    )

    _service_clients: ServiceClients = PrivateAttr()
    _policy: DataClassPolicy = PrivateAttr()
    _capabilities: frozenset[Capability] = PrivateAttr()
    _internal_hosts: frozenset[tuple[str, int]] = PrivateAttr()
    _external_ports: frozenset[int] = PrivateAttr()
    _kek: KeyMaterial | None = PrivateAttr(default=None)
    _previous_keks: tuple[KeyMaterial, ...] = PrivateAttr(default=())
    _fingerprint_key: KeyMaterial | None = PrivateAttr(default=None)
    _previous_fingerprint_key: KeyMaterial | None = PrivateAttr(default=None)
    _receipt_seed: KeyMaterial | None = PrivateAttr(default=None)
    _receipt_kid: str | None = PrivateAttr(default=None)

    # ── derived views ────────────────────────────────────────────────────────

    @property
    def is_production(self) -> bool:
        """``production`` or strict mode: every relaxed fallback is refused."""
        return self.ENVIRONMENT == "production" or self.STRICT_PRODUCTION_MODE

    @property
    def user_byok_enabled(self) -> bool:
        """The effective Q6 flag; ``false`` only as the non-production fallback."""
        return bool(self.AI_USER_BYOK_ENABLED)

    @property
    def service_clients(self) -> ServiceClients:
        """The parsed ``AI_SERVICE_CLIENTS`` registry."""
        return self._service_clients

    @property
    def data_class_policy(self) -> DataClassPolicy:
        """The effective D-08 table."""
        return self._policy

    @property
    def capabilities_enabled(self) -> frozenset[Capability]:
        """The capabilities this deployment serves."""
        return self._capabilities

    @property
    def internal_hosts(self) -> frozenset[tuple[str, int]]:
        """The ``(name, port)`` pairs a ``local`` provider may use."""
        return self._internal_hosts

    @property
    def external_ports(self) -> frozenset[int]:
        """The ports an ``external`` provider may use."""
        return self._external_ports

    @property
    def deployment_id(self) -> str:
        """The installation identity as the lower-case text used on the wire."""
        return str(self.AI_DEPLOYMENT_ID)

    @property
    def job_context_audience(self) -> str:
        """The ``aud`` every job context for this installation carries."""
        return f"ai-gateway/{self.deployment_id}"

    @property
    def is_scheduler(self) -> bool:
        """The scheduler run-mode: no fingerprint key, no receipt seed (D-42)."""
        return self.AI_RUN_MODE == "scheduler"

    @property
    def kek(self) -> KeyMaterial | None:
        """The active local KEK (``database`` backend, ``local`` provider)."""
        return self._kek

    @property
    def previous_keks(self) -> tuple[KeyMaterial, ...]:
        """Decrypt-only KEK generations kept during a rotation."""
        return self._previous_keks

    @property
    def fingerprint_key(self) -> KeyMaterial | None:
        """The active fingerprint HMAC key (``database`` backend)."""
        return self._fingerprint_key

    @property
    def previous_fingerprint_key(self) -> KeyMaterial | None:
        """The previous fingerprint key, accepted during its rotation."""
        return self._previous_fingerprint_key

    @property
    def receipt_seed(self) -> KeyMaterial | None:
        """The OCR receipt signing seed (web run-mode, ``ocr`` enabled)."""
        return self._receipt_seed

    @property
    def receipt_kid(self) -> str | None:
        """The ``kid`` the receipt seed derives."""
        return self._receipt_kid

    @property
    def receipt_public_key(self) -> bytes | None:
        """The receipt verification key, when a seed is configured."""
        if self._receipt_seed is None:
            return None
        return public_key_from_seed(self._receipt_seed.reveal())

    # ── boot refusals ────────────────────────────────────────────────────────

    @model_validator(mode="after")
    def _refuse_gateway_placeholders(self) -> Settings:
        """No gateway key may keep the ``changethis`` placeholder."""
        for name in type(self).model_fields:
            if not name.startswith("AI_"):
                continue
            value = getattr(self, name)
            if (
                isinstance(value, str | Path)
                and str(value).strip().lower() == PLACEHOLDER
            ):
                raise ValueError(f"{name} still holds the {PLACEHOLDER!r} placeholder")
        return self

    @model_validator(mode="after")
    def _refuse_api_key_principals(self) -> Settings:
        """No gateway route accepts an API-key principal (D-05, D-08)."""
        if self.API_KEY_INTROSPECTION_ENABLED:
            raise ValueError(
                "API_KEY_INTROSPECTION_ENABLED must stay false: no gateway route "
                "accepts an API-key principal"
            )
        return self

    @model_validator(mode="after")
    def _parse_structured_values(self) -> Settings:
        """Parse the JSON and list-shaped keys, refusing malformed values."""
        try:
            self._service_clients = parse_service_clients(self.AI_SERVICE_CLIENTS)
            self._policy = parse_data_class_policy(self.AI_DATA_CLASS_POLICY)
        except (ServiceClientConfigError, PolicyConfigError) as exc:
            raise ValueError(str(exc)) from None
        self._capabilities = _parse_capabilities(self.AI_CAPABILITIES_ENABLED)
        self._internal_hosts = _parse_internal_hosts(
            self.AI_PROVIDER_ALLOWED_INTERNAL_HOSTS
        )
        ports = _split_list(self.AI_PROVIDER_ALLOWED_EXTERNAL_PORTS)
        if not ports:
            raise ValueError("AI_PROVIDER_ALLOWED_EXTERNAL_PORTS lists no port")
        self._external_ports = frozenset(_valid_port(p) for p in ports)
        return self

    @model_validator(mode="after")
    def _require_explicit_user_byok(self) -> Settings:
        """Q6: production and strict mode never take the flag implicitly."""
        if self.is_production and self.AI_USER_BYOK_ENABLED is None:
            raise ValueError(
                "AI_USER_BYOK_ENABLED must be set explicitly under production or "
                "strict mode"
            )
        return self

    @model_validator(mode="after")
    def _check_timing_order(self) -> Settings:
        """TTL, timeout and skew bounds must be mutually consistent (D-24)."""
        if self.AI_DISPATCH_CONTEXT_TTL_SECONDS > self.AI_JOB_CONTEXT_MAX_TTL_SECONDS:
            raise ValueError(
                "AI_DISPATCH_CONTEXT_TTL_SECONDS exceeds AI_JOB_CONTEXT_MAX_TTL_SECONDS"
            )
        timeout = self.AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS
        if (
            timeout >= self.AI_RESERVATION_TTL_SECONDS
            or timeout >= self.AI_DISPATCH_CONTEXT_TTL_SECONDS
        ):
            raise ValueError(
                "AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS must be below both "
                "AI_RESERVATION_TTL_SECONDS and AI_DISPATCH_CONTEXT_TTL_SECONDS"
            )
        for name in ("AI_JOB_CONTEXT_CLOCK_SKEW_SECONDS", "AI_MAX_CLOCK_SKEW_SECONDS"):
            if getattr(self, name) > SWEEPER_GRACE_SECONDS:
                raise ValueError(
                    f"{name} exceeds the sweeper grace of {SWEEPER_GRACE_SECONDS} s"
                )
        return self

    @model_validator(mode="after")
    def _check_storage_backend(self) -> Settings:
        """Backend and KEK provider settings must not contradict each other."""
        if self.AI_CREDENTIAL_STORAGE_BACKEND == "vault":
            given = [name for name in _KEK_SETTINGS if getattr(self, name) is not None]
            if given:
                raise ValueError(
                    "the vault backend stores no envelope, so it takes no KEK "
                    f"setting; remove {', '.join(given)}"
                )
            self._require("AI_VAULT_KV_MOUNT", "AI_VAULT_KV_PATH_PREFIX")
            self._check_vault_access()
            return self
        self._check_database_backend()
        return self

    def _check_database_backend(self) -> None:
        if self.AI_CREDENTIAL_KEK_PROVIDER is None:
            raise ValueError(
                "the database backend needs AI_CREDENTIAL_KEK_PROVIDER "
                "(local or vault_transit)"
            )
        if not self.is_scheduler:  # the scheduler never fingerprints (D-42)
            self._require("AI_CREDENTIAL_FINGERPRINT_KEY_FILE")
        if self.AI_CREDENTIAL_KEK_PROVIDER == "local":
            self._require("AI_CREDENTIAL_KEK_FILE")
        else:
            if self.AI_CREDENTIAL_KEK_FILE or self.AI_CREDENTIAL_KEK_PREVIOUS_FILES:
                raise ValueError(
                    "the vault_transit KEK lives in Vault; remove the local KEK files"
                )
            self._require("AI_VAULT_TRANSIT_MOUNT", "AI_VAULT_TRANSIT_KEY")
            self._check_vault_access()

    def _require(self, *names: str) -> None:
        missing = [name for name in names if not getattr(self, name)]
        if missing:
            raise ValueError(
                f"{', '.join(missing)} must be set for "
                f"AI_CREDENTIAL_STORAGE_BACKEND={self.AI_CREDENTIAL_STORAGE_BACKEND}"
            )

    def _check_vault_access(self) -> None:
        self._require("AI_VAULT_ADDR", "AI_VAULT_AUTH_METHOD")
        assert self.AI_VAULT_ADDR is not None  # nosec B101 - narrowed by _require
        assert self.AI_VAULT_AUTH_METHOD is not None  # nosec B101
        self._require(*_VAULT_AUTH_FILES[self.AI_VAULT_AUTH_METHOD])
        parts = urlsplit(self.AI_VAULT_ADDR)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("AI_VAULT_ADDR must be an absolute http or https URL")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError(
                "AI_VAULT_ADDR must carry no credentials, query or fragment"
            )
        if self.is_production and parts.scheme != "https":
            raise ValueError(
                "AI_VAULT_ADDR must be https under production or strict mode"
            )

    @model_validator(mode="after")
    def _load_key_files(self) -> Settings:
        """Read every key file once; mode, length and reuse are checked."""
        try:
            self._load_kek_files()
            self._load_fingerprint_and_receipt_keys()
            self._check_vault_files()
        except KeyFileError as exc:
            raise ValueError(str(exc)) from None
        self._refuse_reused_keys()
        return self

    def _load_kek_files(self) -> None:
        if self.AI_CREDENTIAL_KEK_PROVIDER == "local" and self.AI_CREDENTIAL_KEK_FILE:
            self._kek = load_key_file(self.AI_CREDENTIAL_KEK_FILE, what="the KEK file")
            self._previous_keks = tuple(
                load_key_file(Path(p), what="a previous KEK file")
                for p in _split_list(self.AI_CREDENTIAL_KEK_PREVIOUS_FILES or "")
            )

    def _load_fingerprint_and_receipt_keys(self) -> None:
        if self.is_scheduler:
            return  # mounted on the web service only (D-42)
        if self.AI_CREDENTIAL_FINGERPRINT_KEY_FILE:
            self._fingerprint_key = load_key_file(
                self.AI_CREDENTIAL_FINGERPRINT_KEY_FILE,
                what="the fingerprint key file",
            )
        if self.AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE:
            self._previous_fingerprint_key = load_key_file(
                self.AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE,
                what="the previous fingerprint key file",
            )
        if self.AI_EXECUTION_RECEIPT_KEY_FILE:
            self._receipt_seed = load_key_file(
                self.AI_EXECUTION_RECEIPT_KEY_FILE, what="the receipt key file"
            )

    def _check_vault_files(self) -> None:
        for name in (
            "AI_VAULT_TOKEN_FILE",
            "AI_VAULT_ROLE_ID_FILE",
            "AI_VAULT_SECRET_ID_FILE",
        ):
            path = getattr(self, name)
            if path is not None and self._uses_vault():
                load_secret_text(path, what=name)

    def _uses_vault(self) -> bool:
        return (
            self.AI_CREDENTIAL_STORAGE_BACKEND == "vault"
            or self.AI_CREDENTIAL_KEK_PROVIDER == "vault_transit"
        )

    def _refuse_reused_keys(self) -> None:
        keys = [
            key
            for key in (
                self._kek,
                *self._previous_keks,
                self._fingerprint_key,
                self._previous_fingerprint_key,
                self._receipt_seed,
            )
            if key is not None
        ]
        for index, key in enumerate(keys):
            for other in keys[index + 1 :]:
                if key.same_as(other) or key.path.resolve() == other.path.resolve():
                    raise ValueError(
                        f"{key.path} and {other.path} hold the same key: every key "
                        "generation and purpose needs its own"
                    )

    @model_validator(mode="after")
    def _refuse_reused_secrets(self) -> Settings:
        """Under production/strict, no secret value serves two purposes."""
        if not self.is_production:
            return self
        seen: dict[str, str] = {}
        for name in self.secret_fields:
            value = getattr(self, name, None)
            if value is None or name == "AI_SERVICE_CLIENTS":
                continue
            raw = (
                value.get_secret_value()
                if hasattr(value, "get_secret_value")
                else value
            )
            if raw in seen:
                raise ValueError(f"{name} reuses the value of {seen[raw]}")
            seen[raw] = name
        return self

    def _receipt_seed_missing(self) -> bool:
        """OCR on the web service without a seed (the scheduler signs nothing)."""
        return (
            Capability.OCR in self._capabilities
            and self._receipt_seed is None
            and not self.is_scheduler
        )

    @model_validator(mode="after")
    def _check_receipts_and_issuer_keys(self) -> Settings:
        """Receipts need a seed when OCR is on; no key serves two purposes."""
        if self._receipt_seed_missing():
            raise ValueError(
                "ocr in AI_CAPABILITIES_ENABLED needs a readable, mode-safe "
                "AI_EXECUTION_RECEIPT_KEY_FILE"
            )
        if self._receipt_seed is None:
            if self.AI_EXECUTION_RECEIPT_KID is not None and not self.is_scheduler:
                raise ValueError(
                    "AI_EXECUTION_RECEIPT_KID is set without AI_EXECUTION_RECEIPT_KEY_FILE"
                )
            return self
        public = public_key_from_seed(self._receipt_seed.reveal())
        self._receipt_kid = derive_kid(public)
        if (
            self.AI_EXECUTION_RECEIPT_KID is not None
            and self.AI_EXECUTION_RECEIPT_KID != self._receipt_kid
        ):
            raise ValueError(
                "AI_EXECUTION_RECEIPT_KID differs from the kid the receipt seed derives"
            )
        if public in self._service_clients.all_public_keys():
            raise ValueError(
                "a job-context issuer key equals the gateway's receipt key; each "
                "signature purpose needs its own key"
            )
        return self

    @model_validator(mode="after")
    def _check_spool(self) -> Settings:
        """OCR needs a spool directory; the filesystem itself is checked at start."""
        if Capability.OCR in self._capabilities and self.AI_OCR_SPOOL_DIR is None:
            raise ValueError("ocr in AI_CAPABILITIES_ENABLED needs AI_OCR_SPOOL_DIR")
        if (
            self.AI_MAX_CONCURRENT_SPOOLS * self.AI_MAX_REQUEST_BYTES
            > (self.AI_OCR_SPOOL_MAX_BYTES)
            and Capability.OCR in self._capabilities
        ):
            raise ValueError(
                "AI_MAX_CONCURRENT_SPOOLS x AI_MAX_REQUEST_BYTES exceeds "
                "AI_OCR_SPOOL_MAX_BYTES"
            )
        return self

    @model_validator(mode="after")
    def _require_admission_bounds(self) -> Settings:
        """D-24: production and strict mode never run without admission bounds."""
        if not self.is_production:
            return self
        missing = [name for name in ADMISSION_SETTINGS if getattr(self, name) is None]
        if missing:
            raise ValueError(
                f"{', '.join(missing)} must be set under production or strict mode"
            )
        return self


def describe_validation_error(exc: ValidationError) -> str:
    """
    The field locations and messages of ``exc``, never its input.

    Pydantic's own text embeds a truncated dump of the input — the whole
    environment, secrets included — which must never reach a log.
    """
    return "\n".join(
        f" {'.'.join(str(part) for part in error['loc']) or 'settings'}: {error['msg']}"
        for error in exc.errors(include_input=False, include_url=False)
    )


def load_settings() -> Settings:
    """Build the process settings, failing fast on an incomplete environment."""
    try:
        return Settings()  # type: ignore[call-arg]
    except ValidationError as exc:
        raise RuntimeError(
            f"Configuration validation error:\n{describe_validation_error(exc)}"
        ) from None


settings = load_settings()
